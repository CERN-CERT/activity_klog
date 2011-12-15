#ifndef __IPUTILS__
#define __IPUTILS__

#include <linux/module.h>
#include <linux/kprobes.h>
#include <net/sock.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
#include <linux/ipv6.h>

char *get_remote_ip(struct socket *sock);
char *get_local_ip(struct socket *sock);

#endif
