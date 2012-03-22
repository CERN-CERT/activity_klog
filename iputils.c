#include "iputils.h"
#include <linux/ipv6.h>
#include <net/ip.h>
#include <linux/socket.h>
#include <linux/version.h>

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

#ifndef INET6_ADDRSTRLEN
	#define INET6_ADDRSTRLEN 48
#endif

#ifndef INET_ADDRSTRLEN
	#define INET_ADDRSTRLEN 16
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 25)
#define SADDR saddr
#else
#define SADDR inet_saddr
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 25)
#define DADDR daddr
#else
#define DADDR inet_daddr
#endif


char *get_local_ip(const struct socket *sock)
{
	if(sock == NULL || sock->sk == NULL ||sock->ops == NULL)
	{
		return NULL;
	}

	if(sock->ops->family == AF_INET)
	{
		static char ipv4[INET_ADDRSTRLEN];
			
	        snprintf(ipv4, sizeof(ipv4), "%u.%u.%u.%u", NIPQUAD(inet_sk(sock->sk)->SADDR));
		return ipv4;
	}
	else if(sock->ops->family == AF_INET6)
	{
		static char ipv6[INET6_ADDRSTRLEN + 2];
		snprintf(ipv6, sizeof(ipv6), "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]", 
							NIP6(inet6_sk(sock->sk)->saddr));

		return ipv6;
	}
	else
	{
		return NULL;
	}
}

char *get_remote_ip(const struct socket *sock)
{
	if(sock == NULL || sock->sk == NULL ||sock->ops == NULL)
	{
		return NULL;
	}

	if(sock->ops->family == AF_INET)
	{
		static char ipv4[INET_ADDRSTRLEN];
		
		snprintf(ipv4, sizeof(ipv4), "%u.%u.%u.%u", NIPQUAD(inet_sk(sock->sk)->DADDR));
		return ipv4;
	}
	else if(sock->ops->family == AF_INET6)
	{
		static char ipv6[INET6_ADDRSTRLEN + 2];
                
		snprintf(ipv6, sizeof(ipv6), "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]", 
							NIP6(inet6_sk(sock->sk)->daddr));
                return ipv6;

	}
	else
	{
		return NULL;
	}
}

char *get_ip(const struct sockaddr *addr)
{
	if(addr == NULL)
	{
		return NULL;
	}
	
	if(addr->sa_family == AF_INET)
	{
		static char ipv4[INET_ADDRSTRLEN];
		struct sockaddr_in *addrin = (struct sockaddr_in *) addr;

		snprintf(ipv4, sizeof(ipv4), "%u.%u.%u.%u", NIPQUAD(addrin->sin_addr.s_addr));
		return ipv4;
	}
	else if(addr->sa_family == AF_INET6)
	{
		static char ipv6[INET6_ADDRSTRLEN + 2];
		struct sockaddr_in6 *addrin6 = (struct sockaddr_in6 *) addr;
		snprintf(ipv6, sizeof(ipv6), "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]",
							NIP6(addrin6->sin6_addr));	
									 
		return ipv6;							 
	}
	else
	{
		return NULL;
	}
}

int any_ip_address(const char *ip)
{
	if (ip == NULL)
	{
		return 0;
	}

	return (!strncmp(ip, "0.0.0.0", sizeof(ip)) ||
		!strncmp(ip, "[0000:0000:0000:0000:0000:0000:0000:0000]", sizeof(ip)));
}









