#include <linux/module.h>
#include <linux/binfmts.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/version.h>
#include "probes_helper.h"
#ifdef USE_PRINK
#include "current_details.h"
#else /* ! USE_PRINK */
#include "log.h"
#endif /* ? USE_PRINK */


/* Printing function */
#undef pr_fmt
#define pr_fmt(fmt) MODULE_NAME ": " fmt

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
	char *argv_buffer, *argv_current_end;
#ifdef USE_PRINK
	struct current_details details;
#endif /* USE_PRINK */

	/* Find total argv_size */
	argv_size = 2;
	argv_cur_pos = 0;
	while ((__argv_content = get_user_arg_ptr(__argv, argv_cur_pos)) != NULL) {
		argv_size += strlen_user(__argv_content);
		++argv_cur_pos;
	}

	/* strncpy can only take a long as it input, check for potential overflow */
	if (unlikely(argv_size > LONG_MAX)) {
		pr_err("argv troncated (%zu > %lu)", argv_size, LONG_MAX);
		argv_size = LONG_MAX;
	}

	/* Allocate memory for copying the argv from userspace */
	argv_buffer = kmalloc(argv_size, GFP_ATOMIC);
	if (unlikely(argv_buffer == NULL)) {
		pr_err("Unable to allocate memory for user argv");
		argv_buffer = (char *)default_argv;
		argv_current_end = ((char *)default_argv) + sizeof(default_argv);
		goto log;
	}

	/* Copy argv from userspace */
	argv_cur_pos = 0;
	argv_current_end = argv_buffer;
	while ((__argv_content = get_user_arg_ptr(__argv, argv_cur_pos)) != NULL) {
		/* Get at max argv_size bytes from __argv_content */
		argv_written = strncpy_from_user(argv_current_end,
						 __argv_content,
						 argv_size);
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
		argv_current_end += argv_written;
		argv_size -= argv_written;
		/* As we calculated the size before, this should never occur, except if userspace is malicious */
		if (unlikely(argv_size == 0))
			break;
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

log:
#ifdef USE_PRINK
	fill_current_details(&details);
	printk(KERN_DEBUG pr_fmt(CURRENT_DETAILS_FORMAT" %s %.*s\n"),
	       CURRENT_DETAILS_ARGS(details), filename,
	       (int)(argv_current_end - argv_buffer + 1), argv_buffer);
#else /* ! USE_PRINK */
	store_execlog_record(filename, argv_buffer,
			     argv_current_end - argv_buffer + 1);
#endif /* ? USE_PRINK */
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
		pr_err("search_binary_handler: No execve probe running\n");
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

/************************************/
/*             INIT MODULE          */
/************************************/

static int __init plant_probes(void)
{
	int err;

	pr_info("Light monitoring tool for execve by CERN Security Team\n");

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

	pr_info("[+] Deployed\n");
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

static void __exit unplant_probes(void)
{
	unplant_kretprobe(&kretprobe_sys_execve);
#ifdef CONFIG_COMPAT
	unplant_kretprobe(&kretprobe_compat_sys_execve);
#endif /* CONFIG_COMPAT */
	unplant_kprobe(&kprobe_search_binary_handler);
}

/************************************/
/*             MODULE DEF           */
/************************************/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Brillault <vincent.brillault@cern.ch>");
MODULE_DESCRIPTION("execlog logs information about every 'execve' syscall.");

module_init(plant_probes);
module_exit(unplant_probes);
