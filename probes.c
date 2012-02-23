#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/net.h>
#include <net/ip.h>
#include <linux/socket.h>
#include <linux/version.h>
#include "netlog.h"
#include "iputils.h"
#include "whitelist.h"

/* The following code is a *dirty patch* for the crashes on SLC 6.
 * TODO: Find the exact kernel version where they removed the uid member from task_struct
 * and update the kernel version macro with this.
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
#define CURRENT_UID current->uid
#else
#define CURRENT_UID current_uid()
#endif


/* The next two probes are for the connect system call. We need to associate the process that 
 * requested the connection with the socket file descriptor that the kernel returned.
 * The socket file descriptor is available only after the system call returns. 
 * Though we need to be able to get the pointer to the socket struct that was given as a parameter
 * to connect and log its contents. We cannot have a process requesting two connects in the same time,
 * because when a system call is called, the process is suspended untill its end of execution.
 */

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

#if WHITELISTING
	if(is_whitelisted(current))
	{
		return 0;
	}
#endif
	
	printk("netlog: %s[%d] TCP %s:%d -> %s:%d (uid=%d)\n", current->comm, current->pid, 
				get_local_ip(sock), ntohs(inet_sk(sock->sk)->sport),
				get_remote_ip(sock), ntohs(inet_sk(sock->sk)->dport), 
				CURRENT_UID);
	
	return 0;
}

/* post_accept probe is called right after the accept system call returns.
 * In the return register is placed the socket file descriptor. So with the
 * user of regs_register_status we can get the socket file descriptor and log
 * the data that we want for the socket.
 */

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

#if WHITELISTING
	if(is_whitelisted(current))
	{
		return 0;
	}
#endif

	printk("netlog: %s[%d] TCP %s:%d <- %s:%d (uid=%d)\n", current->comm, current->pid, 
				get_local_ip(sock), ntohs(inet_sk(sock->sk)->sport),
				get_remote_ip(sock), ntohs(inet_sk(sock->sk)->dport), 
				CURRENT_UID);

        return 0;
}

/* Probe for inet_shutdown kernel call. This kernel call is called
 * When close system call is called.
 */
 
#if PROBE_CONNECTION_CLOSE
static int my_inet_shutdown(struct socket *sock, int how)
{
	if(sock == NULL || sock->sk == NULL)
	{
		jprobe_return();
	}
	
	if(sock->sk->sk_protocol == IPPROTO_TCP)
	{
#if WHITELISTING
		if(is_whitelisted(current))
		{
			jprobe_return();
		}
#endif

		printk("netlog: %s[%d] TCP %s:%d <-> %s:%d (uid=%d)\n", current->comm, current->pid, 
				get_local_ip(sock), ntohs(inet_sk(sock->sk)->sport),
				get_remote_ip(sock), ntohs(inet_sk(sock->sk)->dport), 
				CURRENT_UID);
	}
#if PROBE_UDP
	if(sock->sk->sk_protocol == IPPROTO_UDP)
	{
#if WHITELISTING
		if(is_whitelisted(current))
		{
			jprobe_return();
		}
#endif

		printk("netlog: %s[%d] UDP %s:%d <-> %s:%d (uid=%d)\n", current->comm, current->pid, 
				get_local_ip(sock), ntohs(inet_sk(sock->sk)->sport),
				get_remote_ip(sock), ntohs(inet_sk(sock->sk)->dport), 
				CURRENT_UID);
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
		char *ip;
#if WHITELISTING
		if(is_whitelisted(current))
		{
			jprobe_return();
		}
#endif

		ip = get_ip(addr);
			
		if(any_ip_address(ip))
		{				
			printk("netlog: %s[%d] UDP bind (any IP address):%d (uid=%d)\n", 
				current->comm, current->pid, ntohs(((struct sockaddr_in *)addr)->sin_port),
				CURRENT_UID);
		}
		else
		{
			printk("netlog: %s[%d] UDP bind %s:%d (uid=%d)\n", current->comm,
				current->pid, ip, ntohs(((struct sockaddr_in6 *)addr)->sin6_port),	
				CURRENT_UID);
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
	.entry 			= (kprobe_opcode_t *) my_inet_stream_connect,
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
//TODO add kernel version macro in order to probe sys_accept4 at newer kernel versions
static struct kretprobe accept_kretprobe = {
        .handler                = post_accept,
        .maxactive              = MAX_ACTIVE,
        .kp = {
        	.symbol_name = "sys_accept"
        	},
};

#if PROBE_CONNECTION_CLOSE
static struct jprobe shutdown_jprobe = {	
	.entry 			= (kprobe_opcode_t *) my_inet_shutdown,
	.kp = {
		.symbol_name 	= "inet_shutdown",
	},
};
#endif

#if PROBE_UDP
static struct jprobe bind_jprobe = {	
	.entry 			= (kprobe_opcode_t *) my_sys_bind,
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
	int register_status, i;

	register_status = register_jprobe(&connect_jprobe);

	if(register_status < 0)
	{
		return CONNECT_PROBE_FAILED;
	}

	register_status = register_kretprobe(&connect_kretprobe);
        
    if(register_status < 0)
    {
    	return CONNECT_PROBE_FAILED;
    }

	register_status = register_kretprobe(&accept_kretprobe);
        
    if(register_status < 0)
    {
    	return ACCEPT_PROBE_FAILED;
    }

#if PROBE_CONNECTION_CLOSE
	register_status = register_jprobe(&shutdown_jprobe);

	if(register_status < 0)
	{
		return SHUTDOWN_PROBE_FAILED;
	}
#endif
	
#if PROBE_UDP
	register_status = register_jprobe(&bind_jprobe);

	if(register_status < 0)
	{
		return BIND_PROBE_FAILED;
	}
#endif	

	printk("netlog: planted\n");

#if WHITELISTING
	/*Deal with the whitelisting*/

	for(i = 0; i < NO_WHITELISTS; i++)
	{
		int whitelist_status;

		whitelist_status = whitelist(procs_to_whitelist[i]);

		if(whitelist_status < 0)
		{
			printk("netlog: failed to whitelist %s\n", procs_to_whitelist[i]);
		}
		else
		{
			printk("netlog: whitelisted %s\n", procs_to_whitelist[i]);
		}
	}
#endif
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
