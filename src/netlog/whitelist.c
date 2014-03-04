#include <net/ip.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/inet.h>
#include <linux/err.h>
#include <linux/spinlock.h>
#include "whitelist.h"
#include "proc_config.h"
#include "netlog.h"
#include "internal.h"
#include "retro-compat.h"
#include "sparse_compat.h"

#define BUFFER_STEP 4096
#define BUFFER_MAX  4096000

#define IP_RAW_SIZE 16

/* Whitelist */
struct white_process {
	struct white_process *next;
	int port;
	unsigned short family;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
		u8 raw[IP_RAW_SIZE];
	} ip;
	size_t path_len;
	char path[];
};

/* Max size of a row without the path */
/* |i<${ip}>|p<${port}>\n */
#define ROW_MAX_SIZE (9 + INET6_ADDRSTRLEN + 6)

static struct white_process *whitelist = NULL;

/* Lock on the whitelist */
static DEFINE_RWLOCK(whitelist_rwlock);

static struct white_process*
whiterow_from_string(char *str)
{
	struct white_process *new_row = NULL;
	char *pos;
	size_t len;
	ssize_t slen;
	char temp;
	int ret;

	if (unlikely(str == NULL))
		return NULL;

	/* Extract the path, in order to know its length */
	for (pos = str; *pos != FIELD_SEPARATOR && *pos != '\0'; ++pos);
	len = pos - str;
	if (unlikely(len == 0))
		return NULL;

	/* Allocate new memory */
	new_row = kmalloc(sizeof(struct white_process) + len + 1, GFP_ATOMIC);
	if (unlikely(new_row == NULL))
		return NULL;

	/* Initialize */
	new_row->next = NULL;
	new_row->port = NO_PORT;
	memset(new_row->ip.raw, 0, IP_RAW_SIZE);
	new_row->family = AF_UNSPEC;

	/* Fill it with the path */
	memcpy(new_row->path, str, len);
	new_row->path_len = len;
	new_row->path[len] = '\0';

	/* Try to extact the next field */
	while (*pos == FIELD_SEPARATOR) {
		temp = *(pos + 1);
		str = pos + 2;
		if (*str == '<')
			++str;
		for (pos = str; *pos != FIELD_SEPARATOR && *pos != '\0'; ++pos);
		slen = pos - str;
		if (*(pos - 1) == '>')
			--slen;
		if (unlikely(slen <= 0))
			goto fail;
		switch (temp) {
		case 'i':
			if (in4_pton(str, slen, new_row->ip.raw, -1, NULL) == 1)
				new_row->family = AF_INET;
			else if (in6_pton(str, slen, new_row->ip.raw, -1, NULL) == 1)
				new_row->family = AF_INET6;
			else
				goto fail;
			break;
		case 'p':
			temp = *(str + slen);
			*(str + slen) = '\0';
			ret = kstrtoint(str, 0, &new_row->port);
			*(str + slen) = temp;
			if (unlikely(ret))
				goto fail;
			if (unlikely(new_row->port < 1 || new_row->port > 65535))
				goto fail;
			break;
		default:
			goto fail;
		}
	}

	/* Everything is good, return */
	return new_row;
fail:
	kfree(new_row);
	return NULL;
}

static int
is_already_whitelisted(struct white_process *new_row) __must_hold(whitelist_rwlock)
{
	struct white_process *row = whitelist;

	while (row != NULL) {
		if (new_row->port == row->port &&
		    new_row->family == row->family &&
		    new_row->path_len == row->path_len &&
		    (memcmp(new_row->ip.raw, row->ip.raw, IP_RAW_SIZE) == 0) &&
		    (memcmp(new_row->path, row->path, new_row->path_len) == 0))
			return 1;
		row = row->next;
	}
	return 0;
}

static void
purge_whitelist(void) __must_hold(whitelist_rwlock)
{
	struct white_process *current_row;
	struct white_process *next_row;

	pr_info("\t[+] Cleared whitelist\n");

	current_row = whitelist;
	while (current_row != NULL) {
		next_row = current_row->next;
		kfree(current_row);
		current_row = next_row;
	}
	whitelist = NULL;
}

void
destroy_whitelist(void)
{
	unsigned long flags;

	write_lock_irqsave(&whitelist_rwlock, flags);

	purge_whitelist();

	write_unlock_irqrestore(&whitelist_rwlock, flags);
}

static struct white_process *
add_whiterow(struct white_process *last, char *raw) __must_hold(whitelist_rwlock)
{
	struct white_process *new_row;
	if (raw == NULL)
		return last;

	new_row = whiterow_from_string(raw);
	if (new_row == NULL) {
		pr_err("\t[-] Failed to whitelist %s\n", raw);
		kfree(new_row);
	} else if (is_already_whitelisted(new_row)) {
		pr_err("\t[-] Duplicate whitelist %s\n", raw);
		kfree(new_row);
	} else {
		pr_info("\t[+] Whitelisted %s\n", raw);
		if (last == NULL)
			whitelist = new_row;
		else
			last->next = new_row;
		new_row->next = NULL;
		last = new_row;
	}
	return last;
}

void
set_whitelist_from_array(char **raw_array, int raw_len)
{
	int i;
	unsigned long flags;
	struct white_process *last = NULL;

	write_lock_irqsave(&whitelist_rwlock, flags);

	purge_whitelist();

	for (i = 0; i < raw_len; ++i)
		last = add_whiterow(last, raw_array[i]);

	write_unlock_irqrestore(&whitelist_rwlock, flags);
}


int
is_whitelisted(const char *path, unsigned short family, const void *ip, int port)
{
	size_t path_len;
	unsigned long flags;
	struct white_process *row;

	path_len = strnlen(path, MAX_EXEC_PATH);

	/*Empty or paths greater than our limit are not whitelisted*/
	if (unlikely(path_len == 0) ||
	    unlikely(path_len == MAX_EXEC_PATH))
		return NOT_WHITELISTED;

	/*Check if the execution path and the ip and port are whitelisted*/

	read_lock_irqsave(&whitelist_rwlock, flags);

	row = whitelist;
	while (row != NULL) {
		if ((row->port == NO_PORT || row->port == port) &&
		    row->path_len == path_len && (memcmp(row->path, path, path_len) == 0)) {
			if (row->family == AF_UNSPEC)
				goto whitelisted;
			if (row->family == family) {
				switch (row->family) {
				case AF_INET:
					if (memcmp(&row->ip.ip4, ip, sizeof(struct in_addr)) == 0)
						goto whitelisted;
					break;
				case AF_INET6:
					if (memcmp(&row->ip.ip6, ip, sizeof(struct in6_addr)) == 0)
						goto whitelisted;
					break;
				default:
					break;
				}
			}
		}
		row = row->next;
	}

	read_unlock_irqrestore(&whitelist_rwlock, flags);

	return NOT_WHITELISTED;

whitelisted:
	read_unlock_irqrestore(&whitelist_rwlock, flags);

	return WHITELISTED;
}

static const char *list_delims = ",\n";

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
int
whitelist_param_set(const char *buf, struct kernel_param *kp)
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
static int
whitelist_param_set(const char *buf, const struct kernel_param *kp)
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(2, 6, 36) */
{
	char *raw_orig;
	char *raw;
	unsigned long flags;
	struct white_process *last = NULL;

	raw_orig = kstrdup(buf, GFP_KERNEL);

	write_lock_irqsave(&whitelist_rwlock, flags);

	purge_whitelist();

	if (unlikely(buf == NULL))
		goto unlock;

	while ((raw = strsep(&raw_orig, list_delims)) != NULL)
		if (likely(*raw != '\0' && *raw != '\n'))
			last = add_whiterow(last, raw);

unlock:
	write_unlock_irqrestore(&whitelist_rwlock, flags);
	kfree(raw_orig);
	return 0;
}

#define VERIFY_SNPRINTF(buf, remaining, change)	\
do {						\
	if (change == 0) {			\
		/* Nothing written ! */		\
		return NULL;			\
	}					\
	buf += change;				\
	remaining -= change;			\
} while (0)

static char *
whitelist_print(struct white_process *row, char * buf, size_t *avail)
__must_hold(whitelist_rwlock)
{
	int ret;
	int rem = *avail;

	ret = scnprintf(buf, rem, "%.*s", (int) row->path_len, row->path);
	VERIFY_SNPRINTF(buf, rem, ret);
	switch (row->family) {
	case AF_INET:
		ret = scnprintf(buf, rem, "|i<%pI4>", &row->ip.ip4);
		VERIFY_SNPRINTF(buf, rem, ret);
		break;
	case AF_INET6:
		ret = scnprintf(buf, rem, "|i<%pI6c>", &row->ip.ip6);
		VERIFY_SNPRINTF(buf, rem, ret);
		break;
	default:
		ret = 0;
		break;
	}
	if (row->port != NO_PORT) {
		ret = scnprintf(buf, rem, "|p<%d>", row->port);
		VERIFY_SNPRINTF(buf, rem, ret);
	}
	ret = scnprintf(buf, rem, ",");
	VERIFY_SNPRINTF(buf, rem, ret);
	*avail = rem;
	return buf;
}

static const char whitelist_overflow[] = "!!OVERFLOW!!";

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
int
whitelist_param_get(char *buffer, struct kernel_param *kp)
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
static int
whitelist_param_get(char *buffer, const struct kernel_param *kp)
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(2, 6, 36) */
{
	struct white_process *row;
	char *last;
	char *tmp;
	/* fs/sysfs/file.c indicate that max size is PAGE_SIZE (minus trailing space) */
	size_t available = PAGE_SIZE - 1;

	read_lock(&whitelist_rwlock);

	last = buffer;
	row = whitelist;
	while (row != NULL) {
		tmp = whitelist_print(row, last, &available);
		if (tmp == NULL) {
			if (available < sizeof(whitelist_overflow) - 1)
				last = buffer + (PAGE_SIZE - sizeof(whitelist_overflow));
			last += scnprintf(buffer, sizeof(whitelist_overflow) - 1, "%s", whitelist_overflow);
			goto done;
		}
		last = tmp;
		row = row->next;
	}

	if (last > buffer) {
		--last;
		*last = '\0';
	}
done:
	read_unlock(&whitelist_rwlock);

	return (last - buffer);
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36)
const struct kernel_param_ops whitelist_param = {
	.set = whitelist_param_set,
	.get = whitelist_param_get,
};
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
