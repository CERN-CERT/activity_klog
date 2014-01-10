#include <linux/kprobes.h>
#include "sparse_compat.h"

int handler_fault(struct kprobe *p, struct pt_regs *regs, int trap_number);

void unplant_jprobe(struct jprobe *probe) __must_hold(probe_lock);
int plant_jprobe(struct jprobe *probe) __must_hold(probe_lock);

void unplant_kretprobe(struct kretprobe *probe) __must_hold(probe_lock);
int plant_kretprobe(struct kretprobe *probe) __must_hold(probe_lock);
