#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include "log.h"

/**********************************/
/*           PROBES               */
/**********************************/

static int execlog_do_execve(char *filename, char __user *__user *__argv, char __user *__user *__envp, struct pt_regs *not_used)
{
        char __user *__user *__argv_pointer;
        char __user *__argv_content;
        size_t argv_size, argv_written;
        char *argv_buffer, *argv_current_end;

        /* Find total argv_size */
        argv_size = 2;
        __argv_pointer = __argv;
        while (get_user(__argv_content, __argv_pointer) == 0 && __argv_content != NULL) {
                argv_size += strlen_user(__argv_content) + 1;
                ++__argv_pointer;
        }

        /* Allocate memory for copying the argv from userspace */
        argv_buffer = kmalloc(argv_size, GFP_ATOMIC);
        if (unlikely(argv_buffer == NULL))
                goto out;

        /* Copy argv from userspace */
        __argv_pointer = __argv;
        argv_current_end = argv_buffer;
        while (get_user(__argv_content, __argv_pointer) == 0 && __argv_content != NULL) {
                argv_written = strncpy_from_user(argv_current_end, __argv_content, argv_size);
                if (unlikely(argv_written < 0)) {
                        goto free;
                }
                argv_current_end += argv_written;
                *(argv_current_end++) = ' ';
                argv_size -= (argv_written + 1);
                ++__argv_pointer;
        }
        *argv_current_end = '\0';

        store_execlog_record(filename, argv_buffer, argv_size);
free:
        kfree(argv_buffer);
out:
        /* Mandatory return for jprobes */
        jprobe_return();
        return 0;
}

static int signal_that_will_cause_exit(int trap_number)
{
        switch(trap_number)
        {
                case SIGABRT:
                case SIGSEGV:
                case SIGQUIT:
                //TODO Other signals that we need to handle?
                        return 1;
                        break;
                default:
                        return 0;
                        break;
        }
}

static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trap_number)
{
        if(signal_that_will_cause_exit(trap_number))
        {
                printk(KERN_ERR KBUILD_MODNAME ": fault handler: Detected fault %d from inside probes.", trap_number);
        }

        return 0;
}

/*************************************/
/*         probe definitions        */
/*************************************/

static struct jprobe execve_jprobe =
{
        .entry = (kprobe_opcode_t *) execlog_do_execve,
        .kp =
        {
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

        printk(KERN_INFO KBUILD_MODNAME ": Light monitoring tool for execve by CERN Security Team\n");

        err = register_jprobe(&execve_jprobe);

        if(err < 0)
        {
                printk(KERN_ERR KBUILD_MODNAME ":\t[-] Failed to plant execve pre handler\n");
                return -1;
        }

        printk(KERN_INFO KBUILD_MODNAME ":\t[+] Planted execve pre handler\n");

        printk(KERN_INFO KBUILD_MODNAME ":\t[+] Deployed\n");

        return 0;
}

/************************************/
/*             EXIT MODULE          */
/************************************/

static void __exit unplant_probes(void)
{
        unregister_jprobe(&execve_jprobe);
        printk(KERN_INFO KBUILD_MODNAME ":\t[+] Unplanted execve pre handler probe\n");
}

/************************************/
/*             MODULE DEF           */
/************************************/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Brillault <vincent.brillault@cern.ch>");
MODULE_DESCRIPTION("execlog logs information about every 'execve' syscall.");

module_init(plant_probes);
module_exit(unplant_probes);

