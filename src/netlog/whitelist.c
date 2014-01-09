#include <net/ip.h>
#include <linux/mm.h>
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
		switch(temp) {
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

	printk(KERN_INFO MODULE_NAME ":\t[+] Cleared whitelist\n");

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

static void
add_whiterow(char *raw) __must_hold(whitelist_rwlock)
{
	struct white_process *new_row;
	if (raw == NULL)
		return;

	new_row = whiterow_from_string(raw);
	if (new_row == NULL) {
		printk(KERN_ERR MODULE_NAME ":\t[-] Failed to whitelist %s\n", raw);
		kfree(new_row);
	} else if (is_already_whitelisted(new_row)) {
		printk(KERN_ERR MODULE_NAME ":\t[-] Duplicate whitelist %s\n", raw);
		kfree(new_row);
	} else {
		printk(KERN_INFO MODULE_NAME ":\t[+] Whitelisted %s\n", raw);
		new_row->next = whitelist;
		whitelist = new_row;
	}
}

void
set_whitelist_from_array(char **raw_array, int raw_len)
{
	int i;
	unsigned long flags;

	write_lock_irqsave(&whitelist_rwlock, flags);

	purge_whitelist();

	for (i = 0; i < raw_len; ++i)
		add_whiterow(raw_array[i]);

	write_unlock_irqrestore(&whitelist_rwlock, flags);
}

static const char *list_delims = ",\n";

void
set_whitelist_from_string(char *raw_list)
{
	char *raw;
	unsigned long flags;

	write_lock_irqsave(&whitelist_rwlock, flags);

	purge_whitelist();

	while ((raw = strsep(&raw_list, list_delims)) != NULL)
		if (likely(*raw != '\0' && *raw != '\n'))
			add_whiterow(raw);

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
	if(unlikely(path_len == 0) ||
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

static void *
whitelist_file_start(struct seq_file *m, loff_t *pos)
__acquires(whitelist_rwlock)
{
	struct white_process *row;
	loff_t curr_pos;

	read_lock(&whitelist_rwlock);
	row = whitelist;
	curr_pos = 0;
	while ((curr_pos < *pos) && row != NULL) {
		row = row->next;
		++curr_pos;
	}
	return row;
}

static void
whitelist_file_stop(struct seq_file *m, void *v)
__releases(whitelist_rwlock)
{
	read_unlock(&whitelist_rwlock);
}

static void *
whitelist_file_next (struct seq_file *m, void* v, loff_t *pos)
__must_hold(whitelist_rwlock)
{
	struct white_process *row;

	row = (struct white_process*) v;
	if (unlikely(v == NULL))
		return NULL;
	++(*pos);
	return row->next;
}

static int
whitelist_file_show(struct seq_file *m, void *v)
__must_hold(whitelist_rwlock)
{
	int ret;
	struct white_process *row;

	row = (struct white_process*) v;
	if (unlikely(v == NULL))
		return -1;
	ret = seq_printf(m, "%.*s", (int) row->path_len, row->path);
	if (ret != 0)
		return ret;
	switch(row->family) {
		case AF_INET:
			ret = seq_printf(m, "|i<%pI4>", &row->ip.ip4);
			break;
		case AF_INET6:
			ret = seq_printf(m, "|i<%pI6c>", &row->ip.ip6);
			break;
		default:
			ret = 0;
			break;
	}
	if (ret != 0)
		return ret;
	if (row->port != NO_PORT) {
		ret = seq_printf(m, "|p<%d>", row->port);
		if (ret != 0)
			return ret;
	}
	return seq_putc(m, '\n');
}

struct seq_operations whitelist_file = {
	.start = &whitelist_file_start,
	.next = &whitelist_file_next,
	.stop = &whitelist_file_stop,
	.show = &whitelist_file_show
};
