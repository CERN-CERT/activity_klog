#ifndef __NETLOG_PRINT__
#define __NETLOG_PRINT__

/**
 * Which protocol was used ?
 */
enum netlog_protocol {
	PROTO_UNK = 0,
        PROTO_TCP,
        PROTO_UDP,
};

/**
 * What was the network action ?
 */
enum netlog_action {
	ACTION_UNK = 0,
        ACTION_BIND,
        ACTION_CONNECT,
        ACTION_ACCEPT,
        ACTION_CLOSE,
};

#define NETLOG_PRINT_SIZE 128

/**
 * Write netlog log to buffer
 */
ssize_t
print_netlog(char *buffer, size_t len,
	     enum netlog_protocol prot, int family,
	     enum netlog_action action,
	     const void *src_ip, int src_port,
	     const void *dst_ip, int dst_port);

#endif /* __NETLOG_PRINT__ */
