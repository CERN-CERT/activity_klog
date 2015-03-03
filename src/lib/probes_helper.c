#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include "sparse_compat.h"
#include "probes_helper.h"

/* Printing function */
#undef pr_fmt
#define pr_fmt(fmt) MODULE_NAME ": " fmt

int handler_fault(struct kprobe *p, struct pt_regs *regs, int trap_number)
{
	switch (trap_number) {
	case SIGABRT:
	case SIGSEGV:
	case SIGQUIT:
		/* TODO Other signals that we need to handle? */
		pr_err(" fault handler: Detected fault %d from inside probes.", trap_number);
		return 0;
	default:
		return 0;
	}
}

void unplant_kprobe(struct kprobe *probe) __must_hold(probe_lock)
{
	pr_info("[+] Unplanting kprobe on %s\n", probe->symbol_name);
	unregister_kprobe(probe);
	pr_info("[+] Unplanted kprobe on %s\n", probe->symbol_name);
	probe->addr = NULL;
}

int plant_kprobe(struct kprobe *probe) __must_hold(probe_lock)
{
	int err;

	pr_info("[+] Planting kprobe on %s\n", probe->symbol_name);
	err = register_kprobe(probe);
	if (err < 0)
		pr_err("[-] Failed to planted kprobe on %s: %i\n", probe->symbol_name, err);
	else
		pr_info("[+] Planted kprobe on %s\n", probe->symbol_name);

	return err;
}

void unplant_kretprobe(struct kretprobe *probe) __must_hold(probe_lock)
{
	pr_info("[+] Unplanting kretprobe on %s\n", probe->kp.symbol_name);
	unregister_kretprobe(probe);
	pr_info("[+] Unplanted kretprobe on %s\n", probe->kp.symbol_name);
	probe->kp.addr = NULL;
}

int plant_kretprobe(struct kretprobe *probe) __must_hold(probe_lock)
{
	int err;

	pr_info("[+] Planting kretprobe on %s\n", probe->kp.symbol_name);
	err = register_kretprobe(probe);
	if (err < 0)
		pr_err("[-] Failed to planted kretprobe on %s: %i\n", probe->kp.symbol_name, err);
	else
		pr_info("[+] Planted kretprobe on %s\n", probe->kp.symbol_name);

	return err;
}

