#ifndef __NETLOG_WHITELIST__
#define __NETLOG_WHITELIST__

#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/version.h>

#define WHITELIST_FAIL -1

#define WHITELISTED 1
#define NOT_WHITELISTED 0

void set_whitelist_from_array(char **raw_array, int raw_len);
void set_whitelist_from_string(char *raw_list);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
int whitelist_param_set(const char *buf, struct kernel_param *kp);
int whitelist_param_get(char *buffer, struct kernel_param *kp);
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
extern const struct kernel_param_ops whitelist_param;
#endif /* if LINUX_VERSION_CODE ? KERNEL_VERSION(2, 6, 36) */

int is_whitelisted(const char *path, unsigned short family, const void *ip, int port);

void destroy_whitelist(void);

#endif /* __NETLOG_WHITELIST__ */
