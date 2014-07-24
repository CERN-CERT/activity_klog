#include <linux/kprobes.h>

#ifdef CONFIG_X86
#ifdef CONFIG_X86_64
/* Calling conventions: RDI, RSI, RDX */
#define GET_ARG_1(regs) regs->di
#define GET_ARG_2(regs) regs->si
#define GET_ARG_3(regs) regs->dx
#else /* !CONFIG_X86_64 */
/* Calling conventions: AX, DX, BX */
#define GET_ARG_1(regs) regs->ax
#define GET_ARG_2(regs) regs->dx
#define GET_ARG_3(regs) regs->bx
#endif /* CONFIG_X86_64 ? */
#else
#error Unsupported architecture
#endif

int handler_fault(struct kprobe *p, struct pt_regs *regs, int trap_number);

void unplant_jprobe(struct jprobe *probe);
int plant_jprobe(struct jprobe *probe);

void unplant_kretprobe(struct kretprobe *probe);
int plant_kretprobe(struct kretprobe *probe);
