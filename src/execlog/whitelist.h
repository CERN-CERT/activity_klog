#ifndef __EXECLOG_WHITELIST__
#define __EXECLOG_WHITELIST__

#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/version.h>

#define WHITELIST_FAIL -1

#define WHITELISTED 1
#define NOT_WHITELISTED 0

/* Probes need to resolve those absolute path.
 * For memory reason, those path lentgh must be bounded.
 */
#define MAX_EXEC_PATH 950

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
int whitelist_param_set(const char *buf, struct kernel_param *kp);
int whitelist_param_get(char *buffer, struct kernel_param *kp);
int whitelist_root_param_set(const char *buf, struct kernel_param *kp);
int whitelist_root_param_get(char *buffer, struct kernel_param *kp);
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
extern const struct kernel_param_ops whitelist_param;
extern const struct kernel_param_ops whitelist_root_param;
#endif /* if LINUX_VERSION_CODE ? KERNEL_VERSION(2, 6, 36) */

int is_whitelisted(const char *filename, const char *argv_start, size_t argv_size);

void destroy_whitelist(void);

#endif /* __EXECLOG_WHITELIST__ */
