/* 
 * Author:	Panos Sakkos
 * Email:	panos.sakkos@cern.ch
 * Description:	TODO
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <net/sock.h>
//#include <arpa/inet>

//I miss the header file for this function. Normally it should by at arpa/inet.h
char *inet_ntoa(struct in_addr in);

/* Probe for int inet_stream_connect(struct socket *sock, struct sockaddr * uaddr, int addr_len, int flags) */
/* This function is called when a socket of SOCK_STREAM type tries to connect*/

static int my_inet_stream_connect(struct socket *sock, struct sockaddr * uaddr, int addr_len, int flags)
{	
	if(sock-> ops != NULL && sock->ops->family == AF_INET)
	{
		printk("SOCK_STREAM connect to IP %s UID: %d PID: %d Process name: %s\n", 
			inet_ntoa(((struct sockaddr_in *)uaddr)->sin_addr), sock_i_uid(sock->sk), current->pid, current->comm);
	}
	else if(sock-> ops != NULL && sock->ops->family == AF_INET6)
	{
		//TODO ipv6 handling by calling ipv6 version of inet_ntoa
	}

	jprobe_return();
	return 0;
}

/* Probe for int inet_dgram_connect(struct socket *sock, struct sockaddr * uaddr, int addr_len, int flags) */
/* This function is called when a socket of SOCK_DGRAM type tries to connect*/

static int my_inet_dgram_connect(struct socket *sock, struct sockaddr * uaddr, int addr_len, int flags)
{
	if(sock-> ops != NULL && sock->ops->family == AF_INET)
	{
		printk("SOCK_DGRAM connect to IP %s UID: %d PID: %d Process name: %s\n", 
			inet_ntoa(((struct sockaddr_in *)uaddr)->sin_addr), sock_i_uid(sock->sk), current->pid, current->comm);
	}
	else if(sock-> ops != NULL && sock->ops->family == AF_INET6)
	{
		//TODO ipv6 handling by calling the ipv6 version of inet_ntoa
	}

	jprobe_return();
	return 0;
}

/* Probe for long sys_accept4(int fd, struct sockaddr *uaddr, int *addr_len, int flags) */
/* This functions is called when accept4 system called is called from the user space*/

static long my_sys_accept4(int fd, struct sockaddr *uaddr, int *addr_len, int flags)
{
	int err;
	struct socket * sock;
	
	sock = sockfd_lookup(fd, &err);
	
	if(!sock)
	{
		jprobe_return();
		return 0;
	}
	
	if(sock-> ops != NULL && sock->ops->family == AF_INET)
	{
		if(sock->type == SOCK_STREAM)
		{
		printk("SOCK_STREAM accept from IP %s UID: %d PID: %d Process name: %s\n", 
			inet_ntoa(((struct sockaddr_in *)uaddr)->sin_addr), sock_i_uid(sock->sk), current->pid, current->comm);
		}
		else if(sock->type == SOCK_DGRAM)
		{
		printk("SOCK_DGRAM accept from IP %s UID: %d PID: %d Process name: %s\n", 
			inet_ntoa(((struct sockaddr_in *)uaddr)->sin_addr), sock_i_uid(sock->sk), current->pid, current->comm);
		}	
	}	
	else if(sock-> ops != NULL && sock->ops->family == AF_INET6)
	{
		//TODO ipv6 handling by calling the ipv6 version of inet_ntoa
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

static struct jprobe inet_dgram_connect_jprobe = {	
	.entry 			= my_inet_dgram_connect,
	.kp = {
		.symbol_name 	= "inet_dgram_connect",
	},
};

static struct jprobe accept_jprobe = {	
	.entry 			= my_sys_accept4,
	.kp = {
		.symbol_name 	= "sys_accept4",
	},
};


/************************************/
/*             INIT MODULE          */
/************************************/

int init_module(void)
{
	register_jprobe(&inet_stream_connect_jprobe);
	register_jprobe(&inet_dgram_connect_jprobe);
	register_jprobe(&accept_jprobe);
	
	printk(KERN_INFO "probes planted\n");

	return 0;
}

/************************************/
/*             EXIT MODULE          */
/************************************/

void cleanup_module(void)
{
  	unregister_jprobe(&inet_stream_connect_jprobe);
  	unregister_jprobe(&inet_dgram_connect_jprobe);
  	unregister_jprobe(&accept_jprobe);

  	printk(KERN_INFO  "probes unplanted\n");
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

