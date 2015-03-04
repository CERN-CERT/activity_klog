#ifndef __SECURE_LOG__
#define __SECURE_LOG__

#include <linux/types.h>

/**
 * Type of a secure log
 */
enum secure_log_type {
	LOG_NETWORK_INTERACTION  /** High level network interaction log */ = 0,
	LOG_EXECUTION			/** Execve (file execution) with arguments log */,
};


/* Size of the buffer containing the logs */
#define LOG_BUF_LEN (1 << 20)

/* Log facility and level for our devicde */
#define LOG_FACILITY 0
#define LOG_LEVEL    6

/* User data buffer */
#define USER_BUFFER_SIZE 8000

#if defined(MODULE_NETLOG) || defined(MODULE_SECURE_LOG)
#include "print_netlog.h"

void
store_netlog_record(const char *path, enum netlog_action action,
		    enum netlog_protocol protocol, unsigned short family,
		    const void *src_ip, int src_port,
		    const void *dst_ip, int dst_port);
#endif /* ?MODULE_NETLOG */

#if defined(MODULE_EXECLOG) || defined(MODULE_SECURE_LOG)
void
store_execlog_record(const char *path, const char *argv, size_t argv_size);
#endif /* ?MODULE_EXECLOG */

#endif /* __SECURE_LOG__ */
