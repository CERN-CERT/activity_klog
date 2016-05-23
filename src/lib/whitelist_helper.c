#include <linux/version.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "sparse_compat.h"

/* Lock on the whitelist */
static DEFINE_RWLOCK(whitelist_rwlock);

/* Sanity lock on the whitelist: only one w modification at a time ! */
static DEFINE_SPINLOCK(whitelist_sanitylock);

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
