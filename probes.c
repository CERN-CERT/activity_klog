#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/net.h>
#include <net/ip.h>
#include <linux/socket.h>
#include "netlog.h"
#include "iputils.h"

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
				get_local_ip(sock), ntohs(inet_sk(sock->sk)->sport),
				get_remote_ip(sock), ntohs(inet_sk(sock->sk)->dport), 
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
				get_local_ip(sock), ntohs(inet_sk(sock->sk)->sport),
				get_remote_ip(sock), ntohs(inet_sk(sock->sk)->dport), 
				sock_i_uid(sock->sk));	

        return 0;
}

#if PROBE_CONNECTION_CLOSE
static int my_inet_shutdown(struct socket *sock, int how)
{
	if(sock == NULL || sock->sk == NULL)
	{
		jprobe_return();
	}
	
	if(sock->sk->sk_protocol == IPPROTO_TCP)
	{
		printk("netlog: %s[%d] TCP %s:%d <-> %s:%d (uid=%d)\n", current->comm, current->pid, 
				get_local_ip(sock), ntohs(inet_sk(sock->sk)->sport),
				get_remote_ip(sock), ntohs(inet_sk(sock->sk)->dport), 
				sock_i_uid(sock->sk));	
	}
#if PROBE_UDP
	if(sock->sk->sk_protocol == IPPROTO_UDP)
	{	
		printk("netlog: %s[%d] UDP %s:%d <-> %s:%d (uid=%d)\n", current->comm, current->pid, 
				get_local_ip(sock), ntohs(inet_sk(sock->sk)->sport),
				get_remote_ip(sock), ntohs(inet_sk(sock->sk)->dport), 
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

	if(sock == NULL)
	{
		jprobe_return();
	}

	if(sock->sk->sk_protocol == IPPROTO_UDP)
	{
		char *ip = get_ip(addr);
			
		if(!strncmp(ip, "0.0.0.0", sizeof(ip))
		   || !strncmp(ip, "[0000:0000:0000:0000:0000:0000:0000:0000]", sizeof(ip)))
		{				
			printk("netlog: %s[%d] UDP bind  (any ip address):%d (uid=%d)\n", 
				current->comm, current->pid, ntohs(((struct sockaddr_in *)addr)->sin_port),
				sock_i_uid(sock->sk));
		}
		else
		{
			printk("netlog: %s[%d] UDP bind %s:%d (uid=%d)\n", current->comm,
				current->pid, ip, ntohs(((struct sockaddr_in6 *)addr)->sin6_port),	
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
        	.symbol_name = "sys_accept"
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

int __init plant_probes(void)
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

void __exit unplant_probes(void)
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