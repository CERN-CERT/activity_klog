#include "iputils.h"

/* For *forward* compatibility... God bless linux kernel developers. NOT */

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

char *get_local_ip(struct socket *sock)
{
	if(sock == NULL || sock->sk == NULL)
	{
		return NULL;
	}

	if(sock->ops->family == AF_INET)
	{
		static char ipv4[INET_ADDRSTRLEN];
			
	        snprintf(ipv4, sizeof(ipv4), "%u.%u.%u.%u", NIPQUAD(inet_sk(sock->sk)->inet_saddr));
		return ipv4;
	}
	else if(sock->ops->family == AF_INET6)
	{
		static char ipv6[INET6_ADDRSTRLEN + 2];
		snprintf(ipv6, sizeof(ipv6), "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]", NIP6(inet6_sk(sock->sk)->saddr));

		return ipv6;
	}
	else
	{
		return NULL;
	}
}

char *get_remote_ip(struct socket *sock)
{
	if(sock == NULL || sock->sk == NULL)
	{
		return NULL;
	}

	if(sock->ops->family == AF_INET)
	{
		static char ipv4[INET_ADDRSTRLEN];
		
		snprintf(ipv4, sizeof(ipv4), "%u.%u.%u.%u", NIPQUAD(inet_sk(sock->sk)->inet_daddr));
		return ipv4;
	}
	else if(sock->ops->family == AF_INET6)
	{
		static char ipv6[INET6_ADDRSTRLEN + 2];
                
		snprintf(ipv6, sizeof(ipv6), "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]", NIP6(inet6_sk(sock->sk)->daddr));
                return ipv6;

	}
	else
	{
		return NULL;
	}
}

