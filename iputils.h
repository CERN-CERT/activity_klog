#ifndef __IPUTILS__
#define __IPUTILS__

/* API that provided remote and local ip addresses, 
 * given the target struct sock, struct socket or 
 *the struct sockaddr. 
 */

char *get_remote_ip_sk(const struct sock *sk);

char *get_remote_ip(const struct socket *sock);

char *get_local_ip_sk(const struct sock *sk);

char *get_local_ip(const struct socket *sock);

char *get_ip(const struct sockaddr *addr);

int any_ip_address(const char *ip);

#endif

