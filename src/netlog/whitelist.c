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

#define BUFFER_STEP 4096
#define BUFFER_MAX  4096000

/* Whitelist */
struct white_process {
	struct white_process *next;
	int port;
	unsigned short family;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
		u8 raw[16];
	} ip;
	size_t path_len;
	char path[];
};

/* Max size of a row without the path */
/* |i<${ip}>|p<${port}>\n */
#define ROW_MAX_SIZE (9 + INET6_ADDRSTRLEN + 6)

static struct white_process *whitelist = NULL;

/* Lock on the whitelist */
static DEFINE_SPINLOCK(access_whitelist_spinlock);

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
	memset(new_row->ip.raw, 0, 16);
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
is_already_whitelisted(struct white_process *new_row) __must_hold(access_whitelist_spinlock)
{
	struct white_process *row = whitelist;

	while (row != NULL) {
		if (new_row->port == row->port &&
		    new_row->family == row->family &&
		    new_row->path_len == row->path_len &&
		    (memcmp(new_row->ip.raw, row->ip.raw, 16) == 0) &&
		    (memcmp(new_row->path, row->path, new_row->path_len) == 0))
			return 1;
		row = row->next;
	}
	return 0;
}

static void
purge_whitelist(void) __must_hold(access_whitelist_spinlock)
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

	spin_lock_irqsave(&access_whitelist_spinlock, flags);

	purge_whitelist();

	spin_unlock_irqrestore(&access_whitelist_spinlock, flags);
}

static void
add_whiterow(char *raw) __must_hold(access_whitelist_spinlock)
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

	spin_lock_irqsave(&access_whitelist_spinlock, flags);

	purge_whitelist();

	for (i = 0; i < raw_len; ++i)
		add_whiterow(raw_array[i]);

	spin_unlock_irqrestore(&access_whitelist_spinlock, flags);
}

const static char *list_delims = ",\n";

void
set_whitelist_from_string(char *raw_list)
{
	char *raw;
	unsigned long flags;

	spin_lock_irqsave(&access_whitelist_spinlock, flags);

	while ((raw = strsep(&raw_list, list_delims)) != NULL)
		if (likely(*raw != '\0' && *raw != '\n'))
			add_whiterow(raw);

	spin_unlock_irqrestore(&access_whitelist_spinlock, flags);
}

int
is_whitelisted(const char *path, unsigned short family, const void *ip, int port)
{
	size_t path_len;
	unsigned long flags;
	struct white_process *row;

	path_len = strnlen(path, MAX_ABSOLUTE_EXEC_PATH);

	/*Empty or paths greater than our limit are not whitelisted*/
	if(unlikely(path_len == 0) ||
	   unlikely(path_len == MAX_ABSOLUTE_EXEC_PATH))
		return NOT_WHITELISTED;

	/*Check if the execution path and the ip and port are whitelisted*/

	spin_lock_irqsave(&access_whitelist_spinlock, flags);

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

	spin_unlock_irqrestore(&access_whitelist_spinlock, flags);

	return NOT_WHITELISTED;

whitelisted:
	spin_unlock_irqrestore(&access_whitelist_spinlock, flags);

	return WHITELISTED;
}

size_t
dump_whitelist(char **buf, size_t len)
{
	struct white_process *row;
	unsigned long flags;
	size_t pos, curr_len;
	char *curr_buf;

	if (unlikely(buf == NULL))
		return 0;

	pos = 0;
	spin_lock_irqsave(&access_whitelist_spinlock, flags);
	row = whitelist;
	while (row != NULL) {
		curr_len = len;
		while(len - pos < ROW_MAX_SIZE + row->path_len) {
			len += BUFFER_STEP;
		}
		if (curr_len != len) {
			if (len > BUFFER_MAX) {
				len = curr_len;
				goto out;
			}
			curr_buf = *buf;
			*buf = krealloc(*buf, len, GFP_ATOMIC);
			if (*buf == NULL) {
				*buf = curr_buf;
				len = curr_len;
				goto out;
			}
		}
		memcpy((*buf) + pos, row->path, row->path_len);
		pos += row->path_len;
		switch(row->family) {
			case AF_INET:
				pos += sprintf(*buf + pos, "|i<%pI4>", &row->ip.ip4);
				break;
			case AF_INET6:
				pos += sprintf(*buf + pos, "|i<%pI6c>", &row->ip.ip6);
				break;
			default:
				break;
		}
		if (row->port != NO_PORT)
			pos += sprintf(*buf + pos, "|p<%d>", row->port);
		(*buf)[pos++] = '\n';
		row = row->next;
	}
out:
	spin_unlock_irqrestore(&access_whitelist_spinlock, flags);
	return pos;
}
