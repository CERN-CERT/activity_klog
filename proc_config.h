#ifndef __PROC_CONFIG__
#define __PROC_CONFIG__

#define PROCFS_MAX_SIZE 4096
#define PROC_CONFIG_NAME "netlog-config"

#define CREATE_PROC_FAILED 5

int create_proc_config(void);

void destroy_proc_config(void);

void add_connection_string_to_proc_config(char *connection_string);

#endif
