#include <linux/ipv6.h>
#include <net/ip.h>
#include <linux/socket.h>
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 25)
	#define SPORT sport
#else
	#define SPORT inet_sport
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 25)
	#define DPORT dport
#else
	#define DPORT inet_dport
#endif

static char source_ipv4[INET_ADDRSTRLEN];
static char source_ipv6[INET6_ADDRSTRLEN + 2];

static char destination_ipv4[INET_ADDRSTRLEN];
static char destination_ipv6[INET6_ADDRSTRLEN + 2];

int is_inet(struct socket *sock)
{
	if(unlikely(sock == NULL) || unlikely(sock->sk == NULL))
	{
		return 0;
	}
	else
	{
		return (sock->sk->sk_family == AF_INET || sock->sk->sk_family == AF_INET6);
	}
}

int is_tcp(struct socket *sock)
{
	if(unlikely(sock == NULL) || unlikely(sock->sk == NULL))
	{
		return 0;
	}
	else
	{
		return (sock->sk->sk_protocol == IPPROTO_TCP);
	}
}

int is_udp(struct socket *sock)
{
	if(unlikely(sock == NULL) || unlikely(sock->sk == NULL))
	{
		return 0;
	}
	else
	{
		return (sock->sk->sk_protocol == IPPROTO_UDP);
	}
}

int get_source_port(struct socket *sock)
{
	if(unlikely(sock == NULL) || unlikely(sock->sk == NULL))
	{
		return 0;
	}
	else
	{
		return (ntohs(inet_sk(sock->sk)->SPORT));
	}
}

int get_destination_port(struct socket *sock)
{
	if(unlikely(sock == NULL) || unlikely(sock->sk == NULL))
	{
		return 0;
	}
	else
	{
		return (ntohs(inet_sk(sock->sk)->DPORT));
	}
}


char *get_source_ip_sk(const struct sock *sk)
{
	if(unlikely(sk == NULL))
	{
		return NULL;
	}
	
	switch(sk->sk_family)
	{
		case AF_INET:
		        snprintf(source_ipv4, sizeof(source_ipv4), "%u.%u.%u.%u", NIPQUAD(inet_sk(sk)->SADDR));

			return source_ipv4;
			break;
		case AF_INET6:
			snprintf(source_ipv6, sizeof(source_ipv6), "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]", 
								NIP6(inet6_sk(sk)->saddr));

			return source_ipv6;
			break;
		default:
			return NULL;
			break;
	}
}

char *get_source_ip(const struct socket *sock)
{
	if(unlikely(sock == NULL))
	{
		return NULL;
	}

	return get_source_ip_sk(sock->sk);
}

char *get_destination_ip_sk(const struct sock *sk)
{
	if(unlikely(sk == NULL))
	{
		return NULL;
	}
	
	switch(sk->sk_family)
	{
		case AF_INET:
			snprintf(destination_ipv4, sizeof(destination_ipv4), "%u.%u.%u.%u", NIPQUAD(inet_sk(sk)->DADDR));

			return destination_ipv4;
			break;
		case AF_INET6:
			snprintf(destination_ipv6, sizeof(destination_ipv6), "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]", 
								NIP6(inet6_sk(sk)->daddr));
		        return destination_ipv6;		
			break;
		default:
			return NULL;
			break;
	}
}

char *get_destination_ip(const struct socket *sock)
{
	if(unlikely(sock == NULL))
	{
		return NULL;
	}

	return get_destination_ip_sk(sock->sk);
}

char *get_ip(const struct sockaddr *addr)
{
	if(unlikely(addr == NULL))
	{
		return NULL;
	}
	
	switch(addr->sa_family)
	{
		struct sockaddr_in *addrin;
		struct sockaddr_in6 *addrin6;
		static char ipv4[INET_ADDRSTRLEN];
		static char ipv6[INET6_ADDRSTRLEN + 2];
	
		case AF_INET:
			addrin = (struct sockaddr_in *) addr;
			snprintf(ipv4, sizeof(ipv4), "%u.%u.%u.%u", NIPQUAD(addrin->sin_addr.s_addr));
			
			return ipv4;
			break;
		case AF_INET6:
			addrin6 = (struct sockaddr_in6 *) addr;
			snprintf(ipv6, sizeof(ipv6), "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]",
									NIP6(addrin6->sin6_addr));	
										 
			return ipv6;							 
			break;
		default:
			return NULL;
			break;				
	}
}

int any_ip_address(const char *ip)
{
	if(unlikely(ip == NULL))
	{
		return 0;
	}

	return (!strncmp(ip, "0.0.0.0", INET_ADDRSTRLEN) ||
		!strncmp(ip, "[0000:0000:0000:0000:0000:0000:0000:0000]", INET6_ADDRSTRLEN + 2));
}

int looks_like_ipv6(const char *ip)
{
	int i;
	
	if(ip == NULL)
	{
		return 0;
	}
	
	for(i = 0; i < INET6_ADDRSTRLEN && ip[i] != '\0'; ++i)
	{
		if(ip[i] == ':')
		{
			return 1;
		}
	}
	
	return 0;
}


int valid_port_number(const int port)
{
	/*Port 0 useless in this case, so we consider it invalid*/
	
	return (port > 0 && port < 65536);
}

int ip_character(const char ch)
{
	/*Decimal characters and '.'*/

	return (ch == '.' || (ch >= '0' && ch <= '9'));
}

int ipv6_character(const char ch)
{
	/*Hexadecimal characters and ':'s.
	 *Tolerate existance of '[' and ']'
	 */
	
	return (ch == ':' || ch == '[' || ch == ']' ||(ch >= '0' && ch <= '9') || 
		(ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'));
}

int looks_like_valid_ip(const char *ip)
{
	if(ip == NULL)
	{
		return 0;
	}

	if(looks_like_ipv6(ip))
	{
		int i;

		for(i = 0; i < (INET6_ADDRSTRLEN + 2) && ip[i] != '\0'; ++i)
		{
			if(!ipv6_character(ip[i]))
			{
				return 0;
			}
		}

		return 1;
	}
	else
	{
		int i;
		
		for(i = 0; i < INET_ADDRSTRLEN && ip[i] != '\0'; ++i)
		{
			if(!ip_character(ip[i]))
			{
				return 0;
			}
		}
		
		return 1;
		
	}
	
	return 0;
}


