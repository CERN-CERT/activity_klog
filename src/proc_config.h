#ifndef __NETLOG_PROC_CONFIG__
#define __NETLOG_PROC_CONFIG__

#define PROC_DIR_NAME MODULE_NAME
#define PROC_WHITELIST_NAME "whitelist"

int create_proc(void);
void destroy_proc(void);

#endif /* __NETLOG_PROC_CONFIG__ */
