#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include "sparse_compat.h"
#include "probes_helper.h"

/* Printing function */
#undef pr_fmt
#define pr_fmt(fmt) MODULE_NAME ": " fmt

/* Interrupts/Exceptions */
enum {
        X86_TRAP_DE = 0,        /*  0, Divide-by-zero */
        X86_TRAP_DB,            /*  1, Debug */
        X86_TRAP_NMI,           /*  2, Non-maskable Interrupt */
        X86_TRAP_BP,            /*  3, Breakpoint */
        X86_TRAP_OF,            /*  4, Overflow */
        X86_TRAP_BR,            /*  5, Bound Range Exceeded */
        X86_TRAP_UD,            /*  6, Invalid Opcode */
        X86_TRAP_NM,            /*  7, Device Not Available */
        X86_TRAP_DF,            /*  8, Double Fault */
        X86_TRAP_OLD_MF,        /*  9, Coprocessor Segment Overrun */
        X86_TRAP_TS,            /* 10, Invalid TSS */
        X86_TRAP_NP,            /* 11, Segment Not Present */
        X86_TRAP_SS,            /* 12, Stack Segment Fault */
        X86_TRAP_GP,            /* 13, General Protection Fault */
        X86_TRAP_PF,            /* 14, Page Fault */
        X86_TRAP_SPURIOUS,      /* 15, Spurious Interrupt */
        X86_TRAP_MF,            /* 16, x87 Floating-Point Exception */
        X86_TRAP_AC,            /* 17, Alignment Check */
        X86_TRAP_MC,            /* 18, Machine Check */
        X86_TRAP_XF,            /* 19, SIMD Floating-Point Exception */
        X86_TRAP_IRET = 32,     /* 32, IRET Exception */
};

int handler_fault(struct kprobe *p, struct pt_regs *regs, int trap_number)
{
	switch (trap_number) {
	case X86_TRAP_PF:       /* 14: Page Fault */
		return 0;
	case X86_TRAP_DE:       /*  0, Divide-by-zero */
	case X86_TRAP_DB:       /*  1: Debug */
	case X86_TRAP_NMI:      /*  2: Non-maskable Interrupt */
	case X86_TRAP_BP:       /*  3: Breakpoint */
	case X86_TRAP_OF:       /*  4: Overflow */
	case X86_TRAP_BR:       /*  5: Bound Range Exceeded */
	case X86_TRAP_UD:       /*  6: Invalid Opcode */
	case X86_TRAP_NM:       /*  7: Device Not Available */
	case X86_TRAP_DF:       /*  8: Double Fault */
	case X86_TRAP_OLD_MF:   /*  9: Coprocessor Segment Overrun */
	case X86_TRAP_TS:       /* 10: Invalid TSS */
	case X86_TRAP_NP:       /* 11: Segment Not Present */
	case X86_TRAP_SS:       /* 12: Stack Segment Fault */
	case X86_TRAP_GP:       /* 13: General Protection Fault */
	case X86_TRAP_SPURIOUS: /* 15: Spurious Interrupt */
	case X86_TRAP_MF:       /* 16: x87 Floating-Point Exception */
	case X86_TRAP_AC:       /* 17: Alignment Check */
	case X86_TRAP_MC:       /* 18: Machine Check */
	case X86_TRAP_XF:       /* 19: SIMD Floating-Point Exception */
	case X86_TRAP_IRET:     /* 32: IRET Exception */
	default:
		pr_err(" fault handler: Detected fault %d from inside probe on %s\n", trap_number, p->symbol_name);
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

