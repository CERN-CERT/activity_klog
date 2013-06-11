#include <linux/ipv6.h>
#include <net/ip.h>
#include <linux/version.h>
#include "inet_utils.h"

/* Needed in order to convert binary network address to readable.
 * these macros were existing in previous kernel versions but were removed.
 * NIPQUAD is for IPv4 and NIP6 for IPv6 addresses.
 */

#ifndef NIPQUAD
	#define NIPQUAD(addr) \
	    ((unsigned char *)&addr)[0], \
	    ((unsigned char *)&addr)[1], \
	    ((unsigned char *)&addr)[2], \
	    ((unsigned char *)&addr)[3]
#endif

#ifndef NIP6
	#define NIP6(addr) \
	    ntohs((addr).s6_addr16[0]), \
	    ntohs((addr).s6_addr16[1]), \
	    ntohs((addr).s6_addr16[2]), \
	    ntohs((addr).s6_addr16[3]), \
	    ntohs((addr).s6_addr16[4]), \
	    ntohs((addr).s6_addr16[5]), \
	    ntohs((addr).s6_addr16[6]), \
	    ntohs((addr).s6_addr16[7])
#endif

int is_inet(struct socket *sock)
{
	if(unlikely(sock == NULL) || unlikely(sock->sk == NULL))
		return 0;
	return (sock->sk->sk_family == AF_INET || sock->sk->sk_family == AF_INET6);
}

int is_tcp(struct socket *sock)
{
	if(unlikely(sock == NULL) || unlikely(sock->sk == NULL))
		return 0;
	return (sock->sk->sk_protocol == IPPROTO_TCP);
}

int is_udp(struct socket *sock)
{
	if(unlikely(sock == NULL) || unlikely(sock->sk == NULL))
		return 0;
	return (sock->sk->sk_protocol == IPPROTO_UDP);
}

int valid_port_number(const int port)
{
	/*Port 0 useless in this case, so we consider it invalid*/

	return (port > 0 && port < 65536);
}

void copy_ip(void *dst, const void *src, unsigned short family)
{
	switch(family)
	{
		case AF_INET:
			memcpy(dst, src, sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(dst, src, sizeof(struct in6_addr));
			break;
		default:
			break;
	}
}
