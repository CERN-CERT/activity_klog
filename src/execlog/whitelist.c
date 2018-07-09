#include <linux/version.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/spinlock.h>
#include "execlog.h"
#include "whitelist.h"
#include "sparse_compat.h"

/* Whitelist */
struct white_process {
	struct white_process *next;
	size_t filename_len;
	size_t argv_start_len;
	char data[];
};
#define ARGV_START(row) (row->data + row->filename_len + 1)

static struct white_process *whitelist = NULL;

static struct white_process* whiterow_from_string(char *str);
static int is_already_whitelisted(struct white_process *head, struct white_process *new_row);
static char * whitelist_print(struct white_process *row, char * buf, size_t *avail);

#include "whitelist_helper.c"

/* Also whitelist calls made by uid/euid 0 (default to false) */
static bool also_root;

/* Separator for the whitelisting */
#define FIELD_SEPARATOR '|'

static struct white_process*
whiterow_from_string(char *str) __must_hold(whitelist_sanitylock)
{
	struct white_process *new_row = NULL;
	char *separator_pos;
	size_t filename_len;
	size_t argv_start_len;

	if (unlikely(str == NULL))
		return NULL;

	/* Try to find the separator between the filename and the argv start */
	separator_pos = strchr(str, FIELD_SEPARATOR);
	if (separator_pos == NULL) {
		/* No separator, we only have a filename */
		filename_len = strlen(str);
		argv_start_len = 0;
	} else {
		/* We have both a filename and an argv start (may be empty)*/
		/* By construction, separator_pos > str */
		filename_len = (unsigned long)(separator_pos - str);
		argv_start_len = strlen(separator_pos + 1);
	}

	/* Ignore completely irrelevant rules */
	if (unlikely(filename_len == 0))
		return NULL;

	/* Allocate new memory */
	new_row = kmalloc(sizeof(struct white_process) + filename_len + argv_start_len + 2, GFP_ATOMIC);
	if (unlikely(new_row == NULL))
		return NULL;

	/* Copy filename */
	memcpy(new_row->data, str, filename_len);
	new_row->filename_len = filename_len;
	new_row->data[filename_len] = '\0';

	if (argv_start_len > 0) {
		/* Copy argv start after filename */
		memcpy(ARGV_START(new_row), separator_pos + 1, argv_start_len);
		new_row->argv_start_len = argv_start_len;
		*(ARGV_START(new_row) + argv_start_len) = '\0';
	} else {
		new_row->argv_start_len = 0;
	}

	/* Everything is good, return */
	return new_row;
}

static int
is_already_whitelisted(struct white_process *head, struct white_process *new_row) __must_hold(whitelist_sanitylock)
{
	struct white_process *row = head;

	while (row != NULL) {
		if (new_row->filename_len == row->filename_len &&
		    new_row->argv_start_len == row->argv_start_len &&
		    (memcmp(new_row->data, row->data, new_row->filename_len + 1 + new_row->argv_start_len) == 0))
			return 1;
		row = row->next;
	}
	return 0;
}

static bool current_is_root(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	return current_uid().val == 0 || current_euid().val == 0;
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0) */
	return current_uid() == 0 || current_euid() == 0;
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(3, 5, 0) */
}

int
is_whitelisted(const char *filename, const char *argv_start, size_t argv_size)
{
	size_t filename_len;
	unsigned long flags;
	struct white_process *row;

	filename_len = strnlen(filename, MAX_EXEC_PATH);

	/*Empty or filenames greater than our limit are not whitelisted*/
	if (unlikely(filename_len == 0) ||
	    unlikely(filename_len == MAX_EXEC_PATH))
		return NOT_WHITELISTED;

	/*Check if the entry is whitelisted*/

	read_lock_irqsave(&whitelist_rwlock, flags);

	if ((!also_root) && current_is_root())
		goto not_whitelisted;

	row = whitelist;
	while (row != NULL) {
		if (row->filename_len == filename_len && (memcmp(row->data, filename, filename_len) == 0)) {
			if (row->argv_start_len == 0)
				goto whitelisted;
			if (argv_size >= row->argv_start_len && (memcmp(ARGV_START(row), argv_start, row->argv_start_len) == 0))
				goto whitelisted;
		}
		row = row->next;
	}

not_whitelisted:
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

	ret = scnprintf(buf, rem, "%.*s", (int) row->filename_len, row->data);
	VERIFY_SNPRINTF(buf, rem, ret);
	if (row->argv_start_len > 0) {
		ret = scnprintf(buf, rem, "|%.*s", (int)row->argv_start_len, ARGV_START(row));
		VERIFY_SNPRINTF(buf, rem, ret);
	}
	ret = scnprintf(buf, rem, ",");
	VERIFY_SNPRINTF(buf, rem, ret);
	*avail = rem;
	return buf;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
int
whitelist_root_param_set(const char *buf, struct kernel_param *kp)
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
static int
whitelist_root_param_set(const char *buf, const struct kernel_param *kp)
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(2, 6, 36) */
{
	int ret;

	if (buf == NULL)
		return -EBADF;

	pr_info("[+] Modifying root whitelisting");

	write_lock(&whitelist_rwlock);
	ret = strtobool(buf, &also_root);
	write_unlock(&whitelist_rwlock);

	if (ret != 0)
		pr_info("[+] Invalid input");
	else if (also_root)
		pr_info("[+] Root actions are ignored like other");
	else
		pr_info("[+] Root actions are never ignored");

        return ret;
}


# if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
int
whitelist_root_param_get(char *buffer, struct kernel_param *kp)
# else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
static int
whitelist_root_param_get(char *buffer, const struct kernel_param *kp)
# endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(2, 6, 36) */
{
	int ret;

	read_lock(&whitelist_rwlock);
	ret = sprintf(buffer, "%c", also_root ? 'Y' : 'N');
	read_unlock(&whitelist_rwlock);

	return ret;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36)
const struct kernel_param_ops whitelist_root_param = {
	.set = whitelist_root_param_set,
	.get = whitelist_root_param_get,
};
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
