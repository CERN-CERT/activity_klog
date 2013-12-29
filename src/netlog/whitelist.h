#ifndef __NETLOG_WHITELIST__
#define __NETLOG_WHITELIST__

#include <linux/sched.h>
#include <linux/seq_file.h>

#define WHITELIST_FAIL -1

#define WHITELISTED 1
#define NOT_WHITELISTED 0

void set_whitelist_from_array(char **raw_array, int raw_len);
void set_whitelist_from_string(char *raw_list);

extern struct seq_operations whitelist_file;

int is_whitelisted(const char *path, unsigned short family, const void *ip, int port);

void destroy_whitelist(void);

#endif /* __NETLOG_WHITELIST__ */
