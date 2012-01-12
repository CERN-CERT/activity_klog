#ifndef __IPUTILS__
#define __IPUTILS__

struct socket;
struct sockaddr;

char *get_remote_ip(const struct socket *sock);
char *get_local_ip(const struct socket *sock);
char *get_ip(const struct sockaddr *addr);

#endif
