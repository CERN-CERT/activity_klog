#ifndef __EXECLOG_PROBES__
#define __EXECLOG_PROBES__

#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/version.h>

int probes_plant(void);
void probes_unplant(void);


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
int argv_max_size_set(const char *buf, struct kernel_param *kp);
int argv_max_size_get(char *buffer, struct kernel_param *kp);
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
extern const struct kernel_param_ops argv_max_size_param;
#endif /* if LINUX_VERSION_CODE ? KERNEL_VERSION(2, 6, 36) */



#endif /* __EXECLOG_PROBES__ */
