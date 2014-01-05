#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include "sparse_compat.h"

int handler_fault(struct kprobe *p, struct pt_regs *regs, int trap_number)
{
	switch(trap_number)
	{
		case SIGABRT:
		case SIGSEGV:
		case SIGQUIT:
			//TODO Other signals that we need to handle?
			printk(KERN_ERR MODULE_NAME ": fault handler: Detected fault %d from inside probes.", trap_number);
			return 0;
		default:
			return 0;
	}
}

void unplant_jprobe(struct jprobe * probe) __must_hold(probe_lock)
{
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanting jprobe on %s\n", probe->kp.symbol_name);
	unregister_jprobe(probe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted jprobe on %s\n", probe->kp.symbol_name);
	probe->kp.addr = NULL;
}

int plant_jprobe(struct jprobe * probe) __must_hold(probe_lock)
{
	int err;

	printk(KERN_INFO MODULE_NAME ":\t[+] Planting jprobe on %s\n", probe->kp.symbol_name);
	err = register_jprobe(probe);
	if (err < 0)
		printk(KERN_INFO MODULE_NAME ":\t[-] Failed to planted jprobe on %s: %i\n", probe->kp.symbol_name, err);
	else
		printk(KERN_INFO MODULE_NAME ":\t[+] Planted jprobe on %s\n", probe->kp.symbol_name);

	return err;
}

void unplant_kretprobe(struct kretprobe * probe) __must_hold(probe_lock)
{
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanting kretprobe on %s\n", probe->kp.symbol_name);
	unregister_kretprobe(probe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted kretprobe on %s\n", probe->kp.symbol_name);
	probe->kp.addr = NULL;
}

int plant_kretprobe(struct kretprobe * probe) __must_hold(probe_lock)
{
	int err;

	printk(KERN_INFO MODULE_NAME ":\t[+] Planting kretprobe on %s\n", probe->kp.symbol_name);
	err = register_kretprobe(probe);
	if (err < 0)
		printk(KERN_INFO MODULE_NAME ":\t[-] Failed to planted kretprobe on %s: %i\n", probe->kp.symbol_name, err);
	else
		printk(KERN_INFO MODULE_NAME ":\t[+] Planted kretprobe on %s\n", probe->kp.symbol_name);

	return err;
}
