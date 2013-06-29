/* This file is included for retro-compatibility purposes */

#include <linux/version.h>

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
int kstrtoint(const char *s, unsigned int base, int *res);

#define INET6_ADDRSTRLEN 46

int in4_pton(const char *src, int srclen, u8 *dst, int delim, const char **end);
int in6_pton(const char *src, int srclen, u8 *dst, int delim, const char **end);

size_t print_ipv4(char *buf, const struct in_addr *ip4);
size_t print_ipv6(char *buf, const struct in6_addr *ip6);

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
#ifndef __must_hold
#define __must_hold(x)
#endif
#endif
