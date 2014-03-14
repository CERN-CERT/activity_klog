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

void unplant_jprobe(struct jprobe *probe) __must_hold(probe_lock)
{
	pr_info("[+] Unplanting jprobe on %s\n", probe->kp.symbol_name);
	unregister_jprobe(probe);
	pr_info("[+] Unplanted jprobe on %s\n", probe->kp.symbol_name);
	probe->kp.addr = NULL;
}

int plant_jprobe(struct jprobe *probe) __must_hold(probe_lock)
{
	int err;

	pr_info("[+] Planting jprobe on %s\n", probe->kp.symbol_name);
	err = register_jprobe(probe);
	if (err < 0)
		pr_info("[-] Failed to planted jprobe on %s: %i\n", probe->kp.symbol_name, err);
	else
		pr_info("[+] Planted jprobe on %s\n", probe->kp.symbol_name);

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
		pr_info("[-] Failed to planted kretprobe on %s: %i\n", probe->kp.symbol_name, err);
	else
		pr_info("[+] Planted kretprobe on %s\n", probe->kp.symbol_name);

	return err;
}

