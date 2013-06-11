#ifndef __NETLOG_LOG__
#define __NETLOG_LOG___

#include <linux/types.h>

#define NO_IP 0

#define PROTO_TCP 0
#define PROTO_UDP 1

#define ACTION_CONNECT 0
#define ACTION_ACCEPT  1
#define ACTION_CLOSE   2
#define ACTION_BIND    3

void store_record(pid_t pid, uid_t uid, const char* path, u8 action,
                  u8 protocol, unsigned short family,
                  const void *src_ip, int src_port, const void *dst_ip, int dst_port);

int init_netlog_dev(void);
void destroy_netlog_dev(void);

#endif /* __NETLOG_LOG__ */
