#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/tty.h>
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
/*          common core           */
/**********************************/

static const char bad_file[] = "BAD_FILE";

static void
execlog_common(const char __user * __filename,
	       const struct user_arg_ptr __argv,
	       const struct user_arg_ptr __envp)
{
	const char __user *__argv_content;
	int argv_cur_pos;
	size_t argv_size, filename_size;
	long argv_written;
	char *argv_buffer, *argv_current_end, *filename_buffer;
#ifdef USE_PRINK
	struct current_details details;
#endif /* USE_PRINK */

	/* Get Filename */
	filename_size = strnlen_user(__filename, PATH_MAX);
	if (unlikely(filename_size < 0 || filename_size > PATH_MAX)) {
		filename_buffer = kmalloc(sizeof(bad_file), GFP_ATOMIC);
	} else {
		filename_buffer = kmalloc(filename_size, GFP_ATOMIC);
	}
	if (unlikely(filename_buffer == NULL))
		return;
	if (unlikely(filename_size < 0 || filename_size > PATH_MAX)) {
		strncpy(filename_buffer, bad_file, sizeof(bad_file));
        } else {
		if (unlikely(strncpy_from_user(filename_buffer, __filename,
					       filename_size) < 0)) {
			strncpy(filename_buffer, bad_file, sizeof(bad_file));
		}
	}

	/* Find total argv_size */
	argv_size = 2;
	argv_cur_pos = 0;
	while ((__argv_content = get_user_arg_ptr(__argv, argv_cur_pos)) != NULL) {
		argv_size += strlen_user(__argv_content) + 1;
		++argv_cur_pos;
	}

	/* strncpy can only take a long as it input, check for potential overflow */
	if (unlikely(argv_size > LONG_MAX)) {
		/* TODO: we should probably log this failure somewhere */
		argv_size = LONG_MAX;
	}

	/* Allocate memory for copying the argv from userspace */
	argv_buffer = kmalloc(argv_size, GFP_ATOMIC);
	if (unlikely(argv_buffer == NULL))
		goto free_filename;

	/* Copy argv from userspace */
	argv_cur_pos = 0;
	argv_current_end = argv_buffer;
	while ((__argv_content = get_user_arg_ptr(__argv, argv_cur_pos)) != NULL) {
		/* Get at max argv_size bytes from __argv_content */
		argv_written = strncpy_from_user(argv_current_end,
						 __argv_content,
						 argv_size);
		if (unlikely(argv_written < 0)) {
			/* TODO: we should probably log this failure somewhere */
			goto free_argv;
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

#ifdef USE_PRINK
	fill_current_details(&details);
	printk(KERN_DEBUG pr_fmt(CURRENT_DETAILS_FORMAT" %s %.*s\n"),
	       CURRENT_DETAILS_ARGS(details), filename_buffer,
	       (int)(argv_current_end - argv_buffer + 1), argv_buffer);
#else /* ! USE_PRINK */
	store_execlog_record(filename_buffer, argv_buffer,
			     argv_current_end - argv_buffer + 1);
#endif /* ? USE_PRINK */
free_argv:
	kfree(argv_buffer);
free_filename:
	kfree(filename_buffer);
}

/**********************************/
/*           PROBES               */
/**********************************/

static asmlinkage long
probe_sys_execve(const char __user * __filename,
		 const char __user * const __user * __argv,
		 const char __user * const __user * __envp)
{
	struct user_arg_ptr argv = {
		.is_compat = false,
		.ptr.native = __argv,
	 };
	struct user_arg_ptr envp = {
		.is_compat = false,
		.ptr.native = __envp,
	};

	execlog_common(__filename, argv, envp);

	/* Mandatory return for jprobes */
	jprobe_return();
	return 0;
}

#ifdef CONFIG_COMPAT
static asmlinkage long
probe_compat_sys_execve(const char __user * __filename,
			const compat_uptr_t __user * __argv,
			const compat_uptr_t __user * __envp)
{
	struct user_arg_ptr argv = {
		.is_compat = true,
		.ptr.compat = __argv,
	 };
	struct user_arg_ptr envp = {
		.is_compat = true,
		.ptr.compat = __envp,
	};

	execlog_common(__filename, argv, envp);

	/* Mandatory return for jprobes */
	jprobe_return();
	return 0;
}
#endif /* CONFIG_COMPAT */

/*************************************/
/*          probe definitions        */
/*************************************/

static struct jprobe execve_jprobe = {
	.entry = (kprobe_opcode_t *)probe_sys_execve,
	.kp = {
	       .symbol_name = "sys_execve",
	       .fault_handler = handler_fault,
	},
};

#ifdef CONFIG_COMPAT
static struct jprobe execve_compat_jprobe = {
	.entry = (kprobe_opcode_t *)probe_compat_sys_execve,
	.kp = {
	       .symbol_name = "compat_sys_execve",
	       .fault_handler = handler_fault,
	},
};
#endif /* CONFIG_COMPAT */

/************************************/
/*             INIT MODULE          */
/************************************/

static int __init plant_probes(void)
{
	int err;

	pr_info("Light monitoring tool for execve by CERN Security Team\n");

	err = plant_jprobe(&execve_jprobe);
	if (err < 0)
		return -1;

#ifdef CONFIG_COMPAT
	err = plant_jprobe(&execve_compat_jprobe);
	if (err < 0) {
		unplant_jprobe(&execve_jprobe);
		return -2;
	}
#endif /* CONFIG_COMPAT */

	pr_info("[+] Deployed\n");
	return 0;
}

/************************************/
/*             EXIT MODULE          */
/************************************/

static void __exit unplant_probes(void)
{
	unplant_jprobe(&execve_jprobe);
#ifdef CONFIG_COMPAT
	unplant_jprobe(&execve_compat_jprobe);
#endif /* CONFIG_COMPAT */
}

/************************************/
/*             MODULE DEF           */
/************************************/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Brillault <vincent.brillault@cern.ch>");
MODULE_DESCRIPTION("execlog logs information about every 'execve' syscall.");

module_init(plant_probes);
module_exit(unplant_probes);
