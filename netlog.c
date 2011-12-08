/* 
 * Author:	Panos Sakkos
 * Email:	panos.sakkos@cern.ch
 * Description:	TODO
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <net/sock.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/kallsyms.h>
#include <net/inet_common.h>
#include <net/inet_sock.h>
#include <linux/tcp.h>
#include <net/tcp.h>

#define PROBE_UDP 0
#define INET6_ADDRSTRLEN 48



char *inet_ntoa(struct in_addr in);
char *get_ip(int number);

/* Probe for int inet_stream_connect(struct socket *sock, struct sockaddr * uaddr, int addr_len, int flags) */
/* This function is called when a socket of SOCK_STREAM type tries to connect*/

static int my_inet_stream_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{	
	if(sock->sk->sk_protocol == IPPROTO_TCP)
	{
		if(sock->ops->family == PF_INET)
		{
			struct sockaddr_in *addrin = (struct sockaddr_in *)addr;

			printk("%s[%d] TCP connect to %s %d by UID %d\n", current->comm, current->pid, 
				inet_ntoa(addrin->sin_addr), ntohs(addrin->sin_port), sock_i_uid(sock->sk));
		}
		else if(sock->ops->family == PF_INET6)
		{
			//TODO ipv6 handling by calling ipv6 version of inet_ntoa
		}
	}
	
	jprobe_return();
	return 0;
}

/* Probe for long sys_accept(int sockfd, struct sockaddr *uaddr, int *addr_len, int flags) */
/* This function is called when accept system call is called from the user space*/
                                        //BUG

static char output[512];

static long my_sys_accept(int sockfd, struct sockaddr *addr, int *addr_len, int flags)
{
	int err;
	struct socket * sock;
	
	sock = sockfd_lookup(sockfd, &err);
		
	if(sock->sk->sk_protocol == IPPROTO_TCP)
	{
		if(sock->ops->family == PF_INET)
		{
			sprintf(output, "%s[%d %%d] TCP accept from %%s %%d by UID %d\n", 
						current->comm, current->pid, 
				sock_i_uid(sock->sk));
		}
		else if(sock->ops->family == PF_INET6)
		{
			//TODO ipv6 handling by calling the ipv6 version of inet_ntoa
		}
	}
	
	jprobe_return();
	return 0;
}

static struct sk_buff *my_tcp_make_synack(struct sock *sk, struct dst_entry *dst, struct request_sock *req,
                                						struct request_values *rvp)
{

	struct inet_request_sock *ireq = inet_rsk(req);


	printk(output, ntohs(ireq->loc_port), get_ip(ireq->rmt_addr), ntohs(ireq->rmt_port));
	
	jprobe_return();
	return 0;
}

/* UDP protocol is connectionless protocol, so we probe the bind system call */

#if PROBE_UDP
static int my_sys_bind(int sockfd, const struct sockaddr *addr, int addrlen)
{
	int err;
	struct socket * sock;

	sock = sockfd_lookup(sockfd, &err);

	if(sock->sk->sk_protocol == IPPROTO_UDP)
	{
		if(sock->ops->family == PF_INET)
		{
			struct sockaddr_in *addrin = (struct sockaddr_in *)addr;
			char *ip = inet_ntoa(addrin->sin_addr);
			
			if(!strcmp(ip, "0.0.0.0"))
			{
				printk("%s[%d] accepts UDP at port %d by UID %d\n", 
				current->comm, current->pid, ntohs(addrin->sin_port), sock_i_uid(sock->sk));
			}
			else
			{
				printk("%s[%d] UDP connect to %s %d by UID %d\n", current->comm,
					current->pid, ip, ntohs(addrin->sin_port), sock_i_uid(sock->sk));
			}
		}
		else if(sock->ops->family == PF_INET6)
		{
			//TODO ipv6 handling by calling the ipv6 version of inet_ntoa
		}
	}
	
	jprobe_return();
	return 0;
}
#endif

/*************************************/
/*         probe definitions        */
/*************************************/

static struct jprobe inet_stream_connect_jprobe = {	
	.entry 			= my_inet_stream_connect,
	.kp = {
		.symbol_name 	= "inet_stream_connect",
	},
};

static struct jprobe accept_jprobe = {	
	.entry 			= my_sys_accept,
	.kp = {
		.symbol_name 	= "sys_accept",
	},
};


static struct jprobe synack_jprobe = {	
	.entry 			= my_tcp_make_synack,
	.kp = {
		.symbol_name 	= "tcp_make_synack",
	},
};

#if PROBE_UDP
static struct jprobe bind_jprobe = {	
	.entry 			= my_sys_bind,
	.kp = {
		.symbol_name 	= "sys_bind",
	},
};
#endif



/************************************/
/*             INIT MODULE          */
/************************************/

int init_module(void)
{	
	register_jprobe(&inet_stream_connect_jprobe);
	register_jprobe(&accept_jprobe);
	register_jprobe(&synack_jprobe);
#if PROBE_UDP
	register_jprobe(&bind_jprobe);
#endif
	
	printk(KERN_INFO "netlog planted\n");

	return 0;
}

/************************************/
/*             EXIT MODULE          */
/************************************/

void cleanup_module(void)
{
  	unregister_jprobe(&inet_stream_connect_jprobe);
  	unregister_jprobe(&accept_jprobe);
  	unregister_jprobe(&synack_jprobe);
#if PROBE_CONNECTION_CLOSE
  	unregister_jprobe(&close_jprobe);
#endif
#if PROBE_UDP
  	unregister_jprobe(&bind_jprobe);
#endif

  	printk(KERN_INFO  "netlog unplanted\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Panos Sakkos <panos.sakkos@cern.ch>");
MODULE_DESCRIPTION("TODO");

char *get_ip(int in)
{
	static char b[18];
	register char*p;
	
	p = (char *)&in;
#define	UC(b)	(((int)b)&0xff)
	(void)snprintf(b, sizeof(b),
	    "%u.%u.%u.%u", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));
	return (b);		
}

char *inet_ntoa(struct in_addr in)
{
	static char b[18];
	register char *p;

	p = (char *)&in;
#define	UC(b)	(((int)b)&0xff)
	(void)snprintf(b, sizeof(b),
	    "%u.%u.%u.%u", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));
	return (b);
}

/*

	struct inet_sock *inet = inet_sk(sk);
			
	printk("%s[%d] %d %d TCP accept from %d %d by UID: %d\n",
			current->comm, current->pid, inet->inet_saddr,
			ntohs(inet->inet_sport), inet->inet_daddr, 
			ntohs(inet->inet_dport), sock_i_uid(sk));
	
*/
