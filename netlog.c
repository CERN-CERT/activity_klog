#include <linux/module.h>
#include <linux/kprobes.h>
#include <net/sock.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <net/inet_sock.h>

#define CONNECT_PROBE_FAILED -1
#define ACCEPT_PROBE_FAILED -2
#define SHUTDOWN_PROBE_FAILED -3
#define BIND_PROBE_FAILED -4 

#define PROBE_UDP 0
#define PROBE_CONNECTION_CLOSE 1

#define MAX_ACTIVE 100

#ifndef INET6_ADDRSTRLEN
	#define INET6_ADDRSTRLEN 48
#endif

/* For *forward* compatibility... God bless linux kernel developers. NOT */

#ifndef NIPQUAD
	#define NIPQUAD(addr) \
	    ((unsigned char *)&addr)[0], \
	    ((unsigned char *)&addr)[1], \
	    ((unsigned char *)&addr)[2], \
	    ((unsigned char *)&addr)[3]
#endif

#ifndef NIP6
	#define NIP6(addr) \
	    ntohs((addr).s6_addr16[0]), \
	    ntohs((addr).s6_addr16[1]), \
	    ntohs((addr).s6_addr16[2]), \
	    ntohs((addr).s6_addr16[3]), \
	    ntohs((addr).s6_addr16[4]), \
	    ntohs((addr).s6_addr16[5]), \
	    ntohs((addr).s6_addr16[6]), \
	    ntohs((addr).s6_addr16[7])
#endif

char *get_remote_ip(struct socket *sock);
char *get_local_ip(struct socket *sock);

static struct socket *socket_hash[PID_MAX_LIMIT];

static int my_inet_stream_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{	
	socket_hash[current->pid] = sock;

	jprobe_return();
	return 0;
}

static int post_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct socket *sock = socket_hash[current->pid];
	
	if(sock == NULL || sock->sk == NULL)
	{
		return 0;
	}
	
	if(sock->sk->sk_protocol != IPPROTO_TCP)
	{
		return 0;
	}
	
	printk("netlog: %s[%d] TCP %s:%d -> %s:%d (uid=%d)\n", current->comm, current->pid, 
				get_local_ip(sock), ntohs(((struct inet_sock *)sock->sk)->inet_sport),
				get_remote_ip(sock), ntohs(((struct inet_sock *)sock->sk)->inet_dport), 
				sock_i_uid(sock->sk));	
	
	return 0;
}


/* Post handler probe for accept system call */

static int post_accept(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int err;
	struct socket *sock = sockfd_lookup(regs_return_value(regs), &err);
		
	if(sock == NULL || sock->sk == NULL)
	{
		return 0;
	}
	
	if(sock->sk->sk_protocol != IPPROTO_TCP)
	{
		return 0;
	}
	
	printk("netlog: %s[%d] TCP %s:%d <- %s:%d (uid=%d)\n", current->comm, current->pid, 
				get_local_ip(sock), ntohs(((struct inet_sock *)sock->sk)->inet_sport),
				get_remote_ip(sock), ntohs(((struct inet_sock *)sock->sk)->inet_dport), 
				sock_i_uid(sock->sk));	

        return 0;
}

#if PROBE_CONNECTION_CLOSE
static int my_inet_shutdown(struct socket *sock, int how)
{
	if(sock == NULL || sock->sk == NULL)
	{
		jprobe_return();
		return 0;
	}
	
	if(sock->sk->sk_protocol == IPPROTO_TCP)
	{
		struct inet_sock *inet = inet_sk(sock->sk);
	
		if(inet == NULL)
		{
			jprobe_return();
			return 0;
		}
	
		printk("netlog: %s[%d] TCP %s:%d <-> %s:%d (uid=%d)\n", current->comm, current->pid, 
				get_local_ip(sock), ntohs(((struct inet_sock *)sock->sk)->inet_sport),
				get_remote_ip(sock), ntohs(((struct inet_sock *)sock->sk)->inet_dport), 
				sock_i_uid(sock->sk));	
	}
#if PROBE_UDP
	if(sock->sk->sk_protocol == IPPROTO_UDP)
	{	
		printk("netlog: %s[%d] UDP %s:%d <-> %s:%d (uid=%d)\n", current->comm, current->pid, 
				get_local_ip(sock), ntohs(((struct inet_sock *)sock->sk)->inet_sport),
				get_remote_ip(sock), ntohs(((struct inet_sock *)sock->sk)->inet_dport), 
				sock_i_uid(sock->sk));	
	}

#endif

	jprobe_return();
	return 0;
}
#endif

/* UDP protocol is connectionless protocol, so we probe the bind system call */

#if PROBE_UDP
static int my_sys_bind(int sockfd, const struct sockaddr *addr, int addrlen)
{
	int err;
	struct socket * sock;

	sock = sockfd_lookup(sockfd, &err);

	if(sock == NULL || sock->sk == NULL)
	{
		jprobe_return();
	}

	if(sock->sk->sk_protocol == IPPROTO_UDP)
	{
		char *ip = get_local_ip(sock);
			
		if(!strncmp(ip, "0.0.0.0", sizeof(ip)) ||
		   !strncmp(ip, "[0000:0000:0000:0000:0000:0000:0000:0000]", sizeof(ip)))
		{
			printk("netlog: %s[%d] accepts UDP at port %d (uid=%d)\n", 
				current->comm, current->pid, ((struct inet_sock *)sock->sk)->inet_sport,
				sock_i_uid(sock->sk));
		}
		else
		{
			printk("netlog: %s[%d] UDP connect to %s:%d by (uid=%d)\n", current->comm,
				current->pid, ip, ntohs(((struct inet_sock *)sock->sk)->inet_dport),
				sock_i_uid(sock->sk));
		}
	}

	jprobe_return();
	return 0;
}
#endif

/*************************************/
/*         probe definitions        */
/*************************************/

static struct jprobe connect_jprobe = {	
	.entry 			= my_inet_stream_connect,
	.kp = {
		.symbol_name 	= "inet_stream_connect",
	},
};

static struct kretprobe connect_kretprobe = {
        .handler                = post_connect,
        .maxactive              = MAX_ACTIVE,
        .kp = {
        	.symbol_name = "inet_stream_connect"
        	},
};

static struct kretprobe accept_kretprobe = {
        .handler                = post_accept,
        .maxactive              = MAX_ACTIVE,
        .kp = {
        	.symbol_name = "sys_accept4"
        	},
};

#if PROBE_CONNECTION_CLOSE
static struct jprobe shutdown_jprobe = {	
	.entry 			= my_inet_shutdown,
	.kp = {
		.symbol_name 	= "inet_shutdown",
	},
};
#endif

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
	int return_value;
	

	return_value = register_jprobe(&connect_jprobe);

	if(return_value < 0)
	{
		return CONNECT_PROBE_FAILED;
	}

	return_value = register_kretprobe(&connect_kretprobe);
        
        if(return_value < 0) 
        {
                return CONNECT_PROBE_FAILED;
        }

	return_value = register_kretprobe(&accept_kretprobe);
        
        if(return_value < 0) 
        {
                return ACCEPT_PROBE_FAILED;
        }
#if PROBE_CONNECTION_CLOSE
	return_value = register_jprobe(&shutdown_jprobe);

	if(return_value < 0)
	{
		return SHUTDOWN_PROBE_FAILED;
	}
#endif
	
#if PROBE_UDP
	return_value = register_jprobe(&bind_jprobe);

	if(return_value < 0)
	{
		return BIND_PROBE_FAILED;
	}
#endif	
	
	printk("netlog: planted\n");        

	return 0;
}

/************************************/
/*             EXIT MODULE          */
/************************************/

void cleanup_module(void)
{
  	unregister_jprobe(&connect_jprobe);
	unregister_kretprobe(&connect_kretprobe);
	unregister_kretprobe(&accept_kretprobe);
#if PROBE_CONNECTION_CLOSE
  	unregister_jprobe(&shutdown_jprobe);
#endif
#if PROBE_UDP
  	unregister_jprobe(&bind_jprobe);
#endif
	
	printk("netlog: unplanted\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Panos Sakkos <panos.sakkos@cern.ch>");
MODULE_DESCRIPTION("TODO");

/************************************/
/*             IP UTILS             */
/************************************/

char *get_local_ip(struct socket *sock)
{
	if(sock == NULL)
	{
		return NULL;
	}

	if(sock->ops->family == PF_INET)
	{
		int len;
		static char ipv4[INET_ADDRSTRLEN];
		struct sockaddr_in addrin;
		
		kernel_getsockname(sock, (struct sockaddr *) &addrin, &len);
		snprintf(ipv4, sizeof(ipv4), "%d.%d.%d.%d", NIPQUAD(addrin.sin_addr));
		return ipv4;
	}
	else if(sock->ops->family == PF_INET6)
	{
		int len;
		static char ipv6[INET6_ADDRSTRLEN];
		struct sockaddr_in6 addrin6;

		kernel_getsockname(sock, (struct sockaddr *) &addrin6, &len);
		snprintf(ipv6, sizeof(ipv6), "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]", 
								NIP6(addrin6.sin6_addr));
		return ipv6;
	}
	else
	{
		return NULL;
	}
}

char *get_remote_ip(struct socket *sock)
{
	if(sock == NULL)
	{
		return NULL;
	}

	if(sock->ops->family == PF_INET)
	{
		int len;
		static char ipv4[INET_ADDRSTRLEN];
		struct sockaddr_in addrin;
		
		kernel_getpeername(sock, (struct sockaddr *) &addrin, &len);
		snprintf(ipv4, sizeof(ipv4), "%d.%d.%d.%d", NIPQUAD(addrin.sin_addr));
		return ipv4;
	}
	else if(sock->ops->family == PF_INET6)
	{
		int len;
		static char ipv6[INET6_ADDRSTRLEN];
		struct sockaddr_in6 addrin6;

		kernel_getpeername(sock, (struct sockaddr *) &addrin6, &len);
		snprintf(ipv6, sizeof(ipv6), "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]", 
								NIP6(addrin6.sin6_addr));
		return ipv6;
	}
	else
	{
		return NULL;
	}
}


