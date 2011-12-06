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

#define PROBE_UDP 1
#define INET6_ADDRSTRLEN 48

char *inet_ntoa(struct in_addr in);

char host_ip[INET6_ADDRSTRLEN];

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

/* UDP protocol is connectionless protocol, so we probe the bind system call */

#if PROBE_UDP
static int my_sys_bind(int sockfd, const struct sockaddr *addr, size_t addrlen)
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

/* Probe for long sys_accept(int sockfd, struct sockaddr *uaddr, int *addr_len, int flags) */
/* This function is called when accept system call is called from the user space*/

static long my_sys_accept(int sockfd, struct sockaddr *addr, int *addr_len, int flags)
{
	int err;
	struct socket * sock;
	
	sock = sockfd_lookup(sockfd, &err);
		
	if(sock->sk->sk_protocol == IPPROTO_TCP)
	{
		if(sock->ops->family == PF_INET)
		{
			struct sockaddr_in *addrin = (struct sockaddr_in *)addr;
			printk("%s[%d] TCP accept from %s %d by UID: %d\n", current->comm, current->pid, 
				inet_ntoa(addrin->sin_addr), ntohs(addrin->sin_port), sock_i_uid(sock->sk));
		}
		else if(sock->ops->family == PF_INET6)
		{
			//TODO ipv6 handling by calling the ipv6 version of inet_ntoa
		}
	}
	
	jprobe_return();
	return 0;
}

/*************************************/
/*         jprobe definitions        */
/*************************************/

static struct jprobe inet_stream_connect_jprobe = {	
	.entry 			= my_inet_stream_connect,
	.kp = {
		.symbol_name 	= "inet_stream_connect",
	},
};

#if PROBE_UDP
static struct jprobe inet_dgram_connect_jprobe = {	
	.entry 			= my_sys_bind,
	.kp = {
		.symbol_name 	= "sys_bind",
	},
};
#endif

static struct jprobe accept_jprobe = {	
	.entry 			= my_sys_accept,
	.kp = {
		.symbol_name 	= "sys_accept",
	},
};


/************************************/
/*             INIT MODULE          */
/************************************/

int init_module(void)
{
	//TODO get the host ip

	register_jprobe(&inet_stream_connect_jprobe);
#if PROBE_UDP
	register_jprobe(&inet_dgram_connect_jprobe);
#endif
	register_jprobe(&accept_jprobe);
	
	printk(KERN_INFO "netlog planted\n");

	return 0;
}

/************************************/
/*             EXIT MODULE          */
/************************************/

void cleanup_module(void)
{
  	unregister_jprobe(&inet_stream_connect_jprobe);
#if PROBE_UDP
  	unregister_jprobe(&inet_dgram_connect_jprobe);
#endif
  	unregister_jprobe(&accept_jprobe);

  	printk(KERN_INFO  "netlog unplanted\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Panos Sakkos <panos.sakkos@cern.ch>");
MODULE_DESCRIPTION("TODO");

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

