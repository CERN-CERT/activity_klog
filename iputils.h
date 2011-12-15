#ifndef __IPUTILS__
#define __IPUTILS__

#include <linux/socket.h>

char *get_remote_ip(struct socket *sock);
char *get_local_ip(struct socket *sock);
char *get_ip(const struct sockaddr *addr);

#endif
