#include <net/ip.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/inet.h>
#include <linux/err.h>
#include <linux/spinlock.h>
#include "whitelist.h"
#include "sparse_compat.h"

/* Printing function */
#undef pr_fmt
#define pr_fmt(fmt) MODULE_NAME ": " fmt

/* Whitelist */
struct white_process {
	struct white_process *next;
	size_t filename_len;
	size_t argv_start_len;
	char data[];
};
#define ARGV_START(row) (row->data + row->filename_len + 1)

static struct white_process *whitelist = NULL;

/* Probes need to resolve those absolute path.
 * For memory reason, those path lentgh must be bounded.
 */
#define MAX_EXEC_PATH 950


/* Lock on the whitelist */
static DEFINE_RWLOCK(whitelist_rwlock);

/* Sanity lock on the whitelist: only one w modification at a time ! */
static DEFINE_SPINLOCK(whitelist_sanitylock);

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

static void
purge_whitelist(struct white_process *head) __must_hold(whitelist_sanitylock)
{
	struct white_process *next_row;
	struct white_process *current_row = head;

	while (current_row != NULL) {
		next_row = current_row->next;
		kfree(current_row);
		current_row = next_row;
	}
}

void
destroy_whitelist(void)
{
	unsigned long flags;
	struct white_process *old;

	spin_lock_irqsave(&whitelist_sanitylock, flags);

	write_lock(&whitelist_rwlock);
	old = whitelist;
	whitelist = NULL;
	write_unlock(&whitelist_rwlock);

	pr_info("[+] Whitelist cleared\n");

	purge_whitelist(old);

	spin_unlock_irqrestore(&whitelist_sanitylock, flags);
}

static struct white_process *
add_whiterow(struct white_process **head, struct white_process *last, char *raw) __must_hold(whitelist_sanitylock)
{
	struct white_process *new_row;
	if (raw == NULL)
		return last;

	new_row = whiterow_from_string(raw);
	if (new_row == NULL) {
		pr_err("[-] Failed to whitelist %s\n", raw);
		kfree(new_row);
	} else if (is_already_whitelisted(*head, new_row)) {
		pr_err("[-] Duplicate whitelist %s\n", raw);
		kfree(new_row);
	} else {
		pr_info("[+] Whitelisted %s\n", raw);
		if (last == NULL)
			*head = new_row;
		else
			last->next = new_row;
		new_row->next = NULL;
		last = new_row;
	}
	return last;
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
	struct white_process *old;
	struct white_process *last = NULL;
	struct white_process *head = NULL;

	raw_orig = kstrdup(buf, GFP_KERNEL);
	if (unlikely(raw_orig == NULL))
		return 0;

	spin_lock_irqsave(&whitelist_sanitylock, flags);

	pr_info("[+] Creating new whitelist ...\n");

	while ((raw = strsep(&raw_orig, list_delims)) != NULL)
		if (likely(*raw != '\0' && *raw != '\n'))
			last = add_whiterow(&head, last, raw);

	write_lock(&whitelist_rwlock);
	old = whitelist;
	whitelist = head;
	write_unlock(&whitelist_rwlock);

	pr_info("[+] New whitelist applied\n");
	purge_whitelist(old);
	spin_unlock_irqrestore(&whitelist_sanitylock, flags);

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
	/* scnprintf only returns > 0 values */	\
	remaining -= (unsigned long) change;	\
} while (0)

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

	/* last - buffer < PAGE_SIZE thus does not overflow int */
	return (int)(last - buffer);
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36)
const struct kernel_param_ops whitelist_param = {
	.set = whitelist_param_set,
	.get = whitelist_param_get,
};
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
