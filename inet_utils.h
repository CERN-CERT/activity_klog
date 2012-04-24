#ifndef __IPUTILS__
#define __IPUTILS__

/* API that provided destination and source ip addresses, 
 * given the target struct sock, struct socket or 
 *the struct sockaddr. 
 */

int is_inet(struct socket *sock);

int is_tcp(struct socket *sock);

int is_udp(struct socket *sock);

char *get_destination_ip_sk(const struct sock *sk);

char *get_destination_ip(const struct socket *sock);

int get_source_port(struct socket *sock);

int get_destination_port(struct socket *sock);

char *get_source_ip_sk(const struct sock *sk);

char *get_source_ip(const struct socket *sock);

char *get_ip(const struct sockaddr *addr);

int any_ip_address(const char *ip);

#endif

