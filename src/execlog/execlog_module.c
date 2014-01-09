#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include "log.h"
#include "../lib/probes_helper.h"

/* Printing function */
#undef pr_fmt
#define pr_fmt(fmt) MODULE_NAME ": " fmt

/**********************************/
/*           PROBES               */
/**********************************/

static int execlog_do_execve(char *filename, char __user *__user *__argv,
			     char __user *__user *__envp,
			     struct pt_regs *not_used)
{
	char __user *__user *__argv_pointer;
	char __user *__argv_content;
	size_t argv_size;
	long argv_written;
	char *argv_buffer, *argv_current_end;

	/* Find total argv_size */
	argv_size = 2;
	__argv_pointer = __argv;
	while (get_user(__argv_content, __argv_pointer) == 0 &&
	       __argv_content != NULL) {
		argv_size += strlen_user(__argv_content) + 1;
		++__argv_pointer;
	}

	/* strncpy can only take a long as it input, check for potential overflow */
	if (unlikely(argv_size > LONG_MAX)) {
		/* TODO: we should probably log this failure somewhere */
		argv_size = LONG_MAX;
	}

	/* Allocate memory for copying the argv from userspace */
	argv_buffer = kmalloc(argv_size, GFP_ATOMIC);
	if (unlikely(argv_buffer == NULL))
		goto out;

	/* Copy argv from userspace */
	__argv_pointer = __argv;
	argv_current_end = argv_buffer;
	while (get_user(__argv_content, __argv_pointer) == 0 &&
	       __argv_content != NULL) {
		/* Get at max argv_size bytes from __argv_content */
		argv_written = strncpy_from_user(argv_current_end,
						 __argv_content,
						 argv_size);
		if (unlikely(argv_written < 0)) {
			/* TODO: we should probably log this failure somewhere */
			goto free;
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
		++__argv_pointer;
	}
	*argv_current_end = '\0';

	store_execlog_record(filename, argv_buffer,
			     argv_current_end - argv_buffer + 1);
free:
	kfree(argv_buffer);
out:
	/* Mandatory return for jprobes */
	jprobe_return();
	return 0;
}

/*************************************/
/*         probe definitions        */
/*************************************/

static struct jprobe execve_jprobe = {
	.entry = (kprobe_opcode_t *)execlog_do_execve,
	.kp = {
	       .symbol_name = "do_execve",
	       .fault_handler = handler_fault,
	},
};

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

	pr_info("\t[+] Deployed\n");
	return 0;
}

/************************************/
/*             EXIT MODULE          */
/************************************/

static void __exit unplant_probes(void)
{
	unplant_jprobe(&execve_jprobe);
}

/************************************/
/*             MODULE DEF           */
/************************************/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Brillault <vincent.brillault@cern.ch>");
MODULE_DESCRIPTION("execlog logs information about every 'execve' syscall.");

module_init(plant_probes);
module_exit(unplant_probes);
