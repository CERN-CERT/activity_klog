#include <net/ip.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/inet.h>
#include <linux/err.h>
#include <linux/spinlock.h>
#include "whitelist.h"
#include "netlog.h"
#include "internal.h"
#include "retro-compat.h"
#include "sparse_compat.h"

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

static struct white_process *whitelist = NULL;

static struct white_process* whiterow_from_string(char *str);
static int is_already_whitelisted(struct white_process *head, struct white_process *new_row);
static char * whitelist_print(struct white_process *row, char * buf, size_t *avail);

#include "whitelist_helper.c"

static struct white_process*
whiterow_from_string(char *str) __must_hold(whitelist_sanitylock)
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
	/* By construction, pos >= str */
	len = (unsigned long)(pos - str);
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
		if (temp == '\0') {
			/* Un-expected end of string */
			goto fail;
		}
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
			/* Because on restrictions on the whole whitelist, slen can't overflow int */
			if (in4_pton(str, (int)slen, new_row->ip.raw, -1, NULL) == 1)
				new_row->family = AF_INET;
			else if (in6_pton(str, (int)slen, new_row->ip.raw, -1, NULL) == 1)
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
is_already_whitelisted(struct white_process *head, struct white_process *new_row) __must_hold(whitelist_sanitylock)
{
	struct white_process *row = head;

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

static char *
whitelist_print(struct white_process *row, char * buf, size_t *avail)
__must_hold(whitelist_rwlock)
{
	int ret;
	size_t rem = *avail;

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
