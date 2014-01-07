#ifndef __SECURE_LOG__
#define __SECURE_LOG___

#include <linux/types.h>

/**
 * Type of a secure log
 */
enum secure_log_type
{
	LOG_NETWORK_INTERACTION  /** High level network interaction log */ = 0,
	LOG_EXECUTION			/** Execve (file execution) with arguments log */,
};


/**
 * Which protocol was used ?
 */
enum secure_log_protocol
{
	PROTO_TCP = 0,
	PROTO_UDP,
};

/**
 * What was the network action ?
 */
enum secure_log_action
{
	ACTION_CONNECT,
	ACTION_ACCEPT,
	ACTION_CLOSE,
	ACTION_BIND,
};

/* Size of the buffer containing the logs */
#define LOG_BUF_LEN (1 << 20)

/* Log facility and level for our devicde */
#define LOG_FACILITY 0
#define LOG_LEVEL    6

/* User data buffer */
#define USER_BUFFER_SIZE 8000

void
store_netlog_record(const char* path, enum secure_log_action action,
                    enum secure_log_protocol protocol, unsigned short family,
                    const void *src_ip, int src_port,
                    const void *dst_ip, int dst_port);

void
store_execlog_record(const char* path,
                     const char* argv, size_t argv_size);

#endif /* __SECURE_LOG__ */
