#ifndef __IPUTILS__
#define __IPUTILS__

#include <linux/ipv6.h>
#include <net/ip.h>
#include <linux/socket.h>
#include <linux/version.h>

char *get_remote_ip(const struct socket *sock);

char *get_local_ip(const struct socket *sock);

char *get_ip(const struct sockaddr *addr);

int any_ip_address(const char *ip);

#endif

