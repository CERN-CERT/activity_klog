#ifndef __NETLOG_IPUTILS__
#define __NETLOG_IPUTILS__

/* API that provides destination and source ip addresses,
 * given the target struct sock, struct socket or
 *the struct sockaddr.
 */

struct sock;
struct socket;
struct sockaddr;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 25)
        #define SADDR saddr
        #define DADDR daddr
        #define SPORT sport
        #define DPORT dport
#else
        #define SADDR inet_saddr
        #define DADDR inet_daddr
        #define SPORT inet_sport
        #define DPORT inet_dport
#endif

int is_inet(struct socket *sock);

int is_tcp(struct socket *sock);

int is_udp(struct socket *sock);

int valid_port_number(const int port);

void copy_ip(void *dst, void *src, unsigned short family);

#endif /* __NETLOG_IPUTILS__ */
