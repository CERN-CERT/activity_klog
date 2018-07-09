#include <linux/module.h>
#include <linux/binfmts.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/version.h>
#include "execlog.h"
#include "probes.h"
#include "probes_helper.h"
#include "whitelist.h"
#ifdef USE_PRINK
#include "current_details.h"
#else /* ! USE_PRINK */
#include "log.h"
#endif /* ? USE_PRINK */


/**********************************/
/*        32/64 compat            */
/**********************************/

#include <linux/compat.h>

struct user_arg_ptr {
	bool is_compat;
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
	#endif
	} ptr;
};

static const char __user*
get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return NULL;

		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return NULL;

	return native;
}

/**********************************/
/*     inter-probe nightmare      */
/**********************************/

struct execve_data {
	struct hlist_node hlist;
	pid_t pid;
	struct user_arg_ptr argv;
};

static HLIST_HEAD(active_kretprobes);
static DEFINE_SPINLOCK(active_kretprobes_lock);

static struct execve_data*
get_current_kretprobe_data(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	struct hlist_node * tmp;
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0) */
	struct execve_data *cur, *tgt = NULL;

	spin_lock(&active_kretprobes_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	hlist_for_each_entry(cur, tmp, &active_kretprobes, hlist) {
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0) */
	hlist_for_each_entry(cur, &active_kretprobes, hlist) {
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(3, 9, 0) */
		if (cur->pid == current->pid) {
			tgt = cur;
			break;
		}
	}
	spin_unlock(&active_kretprobes_lock);
	return tgt;
}


/**********************************/
/*          common core           */
/**********************************/

static const char * default_argv = "@Memory_error";

static void
execlog_common(const char *filename,
	       const struct user_arg_ptr __argv)
{
	const char __user *__argv_content;
	int argv_cur_pos;
	size_t argv_size;
	long argv_written;
	char *argv_buffer, *argv_current_end, *argv_loop;
	bool argv_truncated;
#ifdef USE_PRINK
	struct current_details details;
	size_t filename_len, printed, print_size;
#endif /* USE_PRINK */

	/* Find total argv_size */
	argv_size = 2;
	argv_cur_pos = 0;
	argv_truncated = 0;
	while ((__argv_content = get_user_arg_ptr(__argv, argv_cur_pos)) != NULL) {
		/* str(n)len_user includes the final \0 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
		/* strlen_user always return something > 0 */
		argv_size += (unsigned long) strlen_user(__argv_content);
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) */
		unsigned long user_len = strnlen_user(__argv_content, argv_max_len);
		if (user_len == 0) {
			if (!access_ok(VERIFY_READ, __argv_content, 1)) {
				/* This will be logged later */
				user_len += 1;
			} else {
				pr_err("Unable to read at most %lu from single argv", argv_max_len);
				user_len += argv_max_len;
				break;
			}
		} else {
			argv_size += user_len;
		}
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(4, 13, 0) */
		++argv_cur_pos;
	}

	/* strncpy can only take a long as it input, check for potential overflow */
	if (unlikely(argv_size > ARGV_MAX_SIZE)) {
		pr_err("argv truncated (%zu > %u)", argv_size, ARGV_MAX_SIZE);
		argv_size = ARGV_MAX_SIZE;
		argv_truncated = 1;
	}

	/* Allocate memory for copying the argv from userspace */
	argv_buffer = kmalloc(argv_size, GFP_ATOMIC);
	if (unlikely(argv_buffer == NULL)) {
		pr_err("Unable to allocate memory for user argv");
		argv_buffer = (char *)default_argv;
		argv_size = sizeof(default_argv);
		goto log;
	}

	/* Copy argv from userspace */
	argv_cur_pos = 0;
	argv_current_end = argv_buffer;
	while ((__argv_content = get_user_arg_ptr(__argv, argv_cur_pos)) != NULL) {
		/* Get at max argv_size bytes from __argv_content */
		/* argv_size is <= LONG_MAX, so we can cast it */
		argv_written = strncpy_from_user(argv_current_end,
						 __argv_content,
						 (long) argv_size);
		if (unlikely(argv_written < 0)) {
			if (argv_written == -EFAULT)
				pr_err("Unable to copy one of the arguments: Page fault");
			else
				pr_err("Unable to copy one of the arguments : %li", argv_written);
			/* We can just skip this argument for now */
			argv_written = 0;
		}
		/* Update the pointer and remaining size
		 * strncpy_from_user guaranties that argv_written <= argv_size, i-e argv_size will not loop (unsigned) */
		argv_current_end += (unsigned long) argv_written;
		argv_size -= (unsigned long) argv_written;
		/* As we calculated the size before, this should never occur, except if userspace is malicious or had to be truncated */
		if (unlikely(argv_size == 0)) {
			if (argv_truncated == 0) {
				pr_err("argv troncated (%zu, resized?)", argv_size);
				argv_truncated = 1;
			}
			/* We still need one char to write '\0' */
			/* The buffer is at least of size 2, we can always go back by one */
			--argv_current_end;
			break;
		}
		/* Add separator ' ' between arguments
		 * Previous check guaranties that argv_size >= 1, thus will not loop (unsigned) afterwards */
		/* TODO: Should we have a better separator ? */
		*argv_current_end = ' ';
		++argv_current_end;
		--argv_size;
		/* Next iteration */
		++argv_cur_pos;
	}
	*argv_current_end = '\0';

	/* Remove any new lines as some software don't support them properly */
	for (argv_loop = argv_buffer; argv_loop < argv_current_end; ++argv_loop) {
		if (*argv_loop == '\n' || *argv_loop == '\r')
			*argv_loop = ' ';
	}

	/* Add a symbol to represent truncated output */
	if (unlikely(argv_truncated && (argv_current_end > argv_buffer))) {
		*(argv_current_end - 1) = '$';
	}

	/* Update argv_size with real value */
	/* By construction, argv_current_end > argv_buffer, we can cast */
	argv_size = (size_t)(argv_current_end - argv_buffer + 1);

	/* Check whitelist */
	if (is_whitelisted(filename, argv_buffer, argv_size))
		goto exit;

log:
#ifdef USE_PRINK
	fill_current_details(&details);
	print_size = argv_size - 1;
	filename_len = strlen(filename);
	/* Rsyslog only reads 1000 char a time ... */
#define DATA_MAX_LEN 900
	if (print_size + filename_len < DATA_MAX_LEN) {
		printk(KERN_DEBUG pr_fmt(CURRENT_DETAILS_FORMAT" %s %.*s\n"),
		       CURRENT_DETAILS_ARGS(details), filename,
		       (int)print_size, argv_buffer);
	} else {
		size_t to_be_printed;
		if (filename_len > DATA_MAX_LEN) {
			to_be_printed = 0;
		} else {
			to_be_printed = DATA_MAX_LEN - filename_len;
		}
		printk(KERN_DEBUG pr_fmt(CURRENT_DETAILS_FORMAT" %.*s %.*s\n"),
		       CURRENT_DETAILS_ARGS(details), DATA_MAX_LEN, filename,
		       (int)to_be_printed, argv_buffer);
		printed = to_be_printed;
		print_size -= to_be_printed;
		while (print_size > 0) {
			if (print_size > DATA_MAX_LEN)
				to_be_printed = DATA_MAX_LEN;
			else
				to_be_printed = print_size;
			printk(KERN_DEBUG pr_fmt(CURRENT_DETAILS_FORMAT" @ %.*s\n"),
			       CURRENT_DETAILS_ARGS(details),
			       (int)to_be_printed, argv_buffer + printed);
			printed += to_be_printed;
			print_size -= to_be_printed;
		}
	}
#else /* ! USE_PRINK */
	store_execlog_record(filename, argv_buffer, argv_size);
#endif /* ? USE_PRINK */

exit:
	if (argv_buffer != default_argv)
		kfree(argv_buffer);
}

/**********************************/
/*           PROBES               */
/**********************************/

static int
pre_sys_execve(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct execve_data *priv = (struct execve_data*)ri->data;

	if (unlikely(current == NULL))
		return 1;

	priv->argv.is_compat = false;
	priv->argv.ptr.native = (const char __user *const __user *) GET_ARG_2(regs);
	priv->pid = current->pid;

	spin_lock(&active_kretprobes_lock);
	hlist_add_head(&priv->hlist, &active_kretprobes);
	spin_unlock(&active_kretprobes_lock);

	return 0;
}

#ifdef CONFIG_COMPAT
static int
pre_compat_sys_execve(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct execve_data *priv = (struct execve_data*)ri->data;

	if (unlikely(current == NULL))
		return 1;

	priv->argv.is_compat = true;
	priv->argv.ptr.compat = (const compat_uptr_t __user *) GET_ARG_2(regs);
	priv->pid = current->pid;

	spin_lock(&active_kretprobes_lock);
	hlist_add_head(&priv->hlist, &active_kretprobes);
	spin_unlock(&active_kretprobes_lock);

	return 0;
}
#endif /* CONFIG_COMPAT */

static const char *kretprobe_missed = "@Missed";

static int
pre_search_binary_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct execve_data *priv;
	struct linux_binprm *bprm = (struct linux_binprm *) GET_ARG_1(regs);

	if (unlikely(bprm == NULL)) {
		pr_err("search_binary_handler called with a NULL bprm\n");
		return 0;
	}

	priv = get_current_kretprobe_data();
	if (unlikely(priv == NULL)) {
#ifdef USE_PRINK
		struct current_details details;
		fill_current_details(&details);
		printk(KERN_DEBUG pr_fmt(CURRENT_DETAILS_FORMAT" %s %s\n"),
		       CURRENT_DETAILS_ARGS(details), bprm->filename,
		       kretprobe_missed);
#else /* ! USE_PRINK */
		store_execlog_record(bprm->filename, kretprobe_missed,
				     sizeof(kretprobe_missed));
#endif /* ? USE_PRINK */
		return 0;
	}
	execlog_common(bprm->filename, priv->argv);
	priv->argv.ptr.native = NULL;
	return 0;
}

static int
post_check(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct execve_data *priv = (struct execve_data*)ri->data;

	if (unlikely(priv == NULL))
		return 0;
	/* Log a missed instanced if:
	    - search_binary_handler did not clean priv->argv.ptr.native
	    - The syscall did work (no error)
	*/
	if (unlikely(priv->argv.ptr.native != NULL && !IS_ERR(ERR_PTR(regs_return_value(regs)))))
		pr_err("Execve probe: search_binary_handler not called\n");

	spin_lock(&active_kretprobes_lock);
	hlist_del(&priv->hlist);
	spin_unlock(&active_kretprobes_lock);

	return 0;
}

/*************************************/
/*          probe definitions        */
/*************************************/

static struct kretprobe kretprobe_sys_execve = {
	.entry_handler = pre_sys_execve,
	.handler = post_check,
	.data_size = sizeof(struct execve_data),
	.maxactive = 16 * NR_CPUS,
	.kp = {
		.symbol_name = "sys_execve",
		.fault_handler = handler_fault,
	},
};

#ifdef CONFIG_COMPAT
static struct kretprobe kretprobe_compat_sys_execve = {
	.entry_handler = pre_compat_sys_execve,
	.handler = post_check,
	.data_size = sizeof(struct execve_data),
	.maxactive = 16 * NR_CPUS,
	.kp = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
		.symbol_name = "sys32_execve",
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0) */
		.symbol_name = "compat_sys_execve",
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(3, 7, 0) */
		.fault_handler = handler_fault,
	},
};
#endif /* CONFIG_COMPAT */

static struct kprobe kprobe_search_binary_handler = {
	.pre_handler = pre_search_binary_handler,
	.symbol_name = "search_binary_handler",
	.fault_handler = handler_fault,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#warning "This kernel contains a new syscall, execveat, not supported by execlog!"
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0) */

/************************************/
/*             INIT MODULE          */
/************************************/

int probes_plant(void)
{
	int err;

	err = plant_kprobe(&kprobe_search_binary_handler);
	if (err < 0) {
		err = -1;
		goto err_cleaned;
	}

	err = plant_kretprobe(&kretprobe_sys_execve);
	if (err < 0) {
		err = -2;
		goto err_clean_kprobe;
	}

#ifdef CONFIG_COMPAT
	err = plant_kretprobe(&kretprobe_compat_sys_execve);
	if (err < 0) {
		err = -3;
		goto err_clean_kretprobe;
	}
#endif /* CONFIG_COMPAT */
	return 0;

#ifdef CONFIG_COMPAT
err_clean_kretprobe:
	unplant_kretprobe(&kretprobe_sys_execve);
#endif /* CONFIG_COMPAT */
err_clean_kprobe:
	unplant_kprobe(&kprobe_search_binary_handler);
err_cleaned:
	return err;
}

/************************************/
/*             EXIT MODULE          */
/************************************/

void probes_unplant(void)
{
	unplant_kretprobe(&kretprobe_sys_execve);
#ifdef CONFIG_COMPAT
	unplant_kretprobe(&kretprobe_compat_sys_execve);
#endif /* CONFIG_COMPAT */
	unplant_kprobe(&kprobe_search_binary_handler);
	destroy_whitelist();
}
