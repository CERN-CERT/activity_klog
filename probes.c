#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/net.h>
#include <net/ip.h>
#include <linux/socket.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include "iputils.h"
#include "whitelist.h"
#include "logger.h"
#include "netlog.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	#define CURRENT_UID current->uid
#else
	#define CURRENT_UID current_uid()
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 25)
	#define SPORT sport
#else
	#define SPORT inet_sport
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 25)
	#define DPORT dport
#else
	#define DPORT inet_dport
#endif

#define MODULE_NAME "netlog: "

/* The next two probes are for the connect system call. We need to associate the process that 
 * requested the connection with the socket file descriptor that the kernel returned.
 * The socket file descriptor is available only after the system call returns. 
 * Though we need to be able to get the pointer to the socket struct that was given as a parameter
 * to connect and log its contents. We cannot have a process requesting two connects in the same time,
 * because when a system call is called, the process is suspended untill its end of execution.
 */

static struct socket *match_socket[PID_MAX_LIMIT] = {NULL};

static int netlog_inet_stream_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{	
	match_socket[current->pid] = sock;

	jprobe_return();
	return 0;
}

static int post_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int log_status;
	struct socket *sock;

	sock = match_socket[current->pid];
	
	if(sock == NULL || sock->sk == NULL)
	{
		goto exit;
	}

	if((sock->sk->sk_family != AF_INET && sock->sk->sk_family != AF_INET6) || sock->sk->sk_protocol != IPPROTO_TCP)
	{
		goto exit;
	}
	
	#if WHITELISTING

	if(is_whitelisted(current))
	{
		goto exit;
	}

	#endif

	log_status = log_message("%s[%d] TCP %s:%d -> %s:%d (uid=%d)\n", current->comm, current->pid, 
						get_local_ip(sock), ntohs(inet_sk(sock->sk)->SPORT),
						get_remote_ip(sock), ntohs(inet_sk(sock->sk)->DPORT), 
						CURRENT_UID);

	if(LOG_FAILED(log_status))
	{
		printk(KERN_ERR MODULE_NAME "Failed to log message\n");		
	}

exit:
	match_socket[current->pid] = NULL;
	return 0;
}

/* post_accept probe is called right after the accept system call returns.
 * In the return register is placed the socket file descriptor. So with the
 * user of regs_register_status we can get the socket file descriptor and log
 * the data that we want for the socket.
 */

static int post_accept(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct socket *sock;
	int err = 0, log_status;

	sock = sockfd_lookup(regs_return_value(regs), &err);

	if(sock == NULL ||sock->sk == NULL || err < 0)
	{
		goto exit;
	}

	if((sock->sk->sk_family != AF_INET && sock->sk->sk_family != AF_INET6) || sock->sk->sk_protocol != IPPROTO_TCP)
	{
		goto exit;
	}

	#if WHITELISTING

	if(is_whitelisted(current))
	{
		goto exit;
	}

	#endif

	log_status = log_message("%s[%d] TCP %s:%d <- %s:%d (uid=%d)\n", current->comm, current->pid, 
						get_local_ip(sock), ntohs(inet_sk(sock->sk)->SPORT),
						get_remote_ip(sock), ntohs(inet_sk(sock->sk)->DPORT), 
						CURRENT_UID);

	if(LOG_FAILED(log_status))
	{
		printk(KERN_ERR MODULE_NAME "Failed to log message\n");		
	}

exit:
	if(sock != NULL)
	{
		sockfd_put(sock);
	}

	return 0;
}

#if PROBE_CONNECTION_CLOSE

static void netlog_tcp_close(struct sock *sk)
{
	int log_status;

	if(sk == NULL || ntohs(inet_sk(sk)->DPORT) == 0)
	{
		goto exit;
	}

	if((sk->sk_family != AF_INET && sk->sk_family != AF_INET6) || sk->sk_protocol != IPPROTO_TCP)
	{
		goto exit;
	}

	#if WHITELISTING

	if(is_whitelisted(current))
	{
		goto exit;
	}

	#endif

	log_status = log_message("%s[%d] TCP %s:%d <-> %s:%d (uid=%d)\n", current->comm, current->pid, 
						get_local_ip_sk(sk), ntohs(inet_sk(sk)->SPORT),
						get_remote_ip_sk(sk), ntohs(inet_sk(sk)->DPORT), 
						CURRENT_UID);

	if(LOG_FAILED(log_status))
	{
		printk(KERN_ERR MODULE_NAME "Failed to log message\n");		
	}

exit:
	jprobe_return();
}

#endif

#if PROBE_UDP && PROBE_CONNECTION_CLOSE

static void netlog_udp_close(struct sock *sk, long timeout)
{
	int log_status;

	if(sk == NULL || ntohs(inet_sk(sk)->DPORT) == 0)
	{
		goto exit;
	}

	if((sk->sk_family != AF_INET && sk->sk_family != AF_INET6) || sk->sk_protocol != IPPROTO_UDP)
	{
		goto exit;
	}

	#if WHITELISTING

	if(is_whitelisted(current))
	{
		goto exit;
	}

	#endif

	log_status = log_message("%s[%d] UDP %s:%d <-> %s:%d (uid=%d)\n", current->comm, current->pid, 
						get_local_ip_sk(sk), ntohs(inet_sk(sk)->SPORT),
						get_remote_ip_sk(sk), ntohs(inet_sk(sk)->DPORT), 
						CURRENT_UID);			

	if(LOG_FAILED(log_status))
	{
		printk(KERN_ERR MODULE_NAME "Failed to log message\n");
	}

exit:
	jprobe_return();
}

#endif

#if PROBE_UDP

/* UDP protocol is connectionless protocol, so we probe the bind system call */

static int netlog_sys_bind(int sockfd, const struct sockaddr *addr, int addrlen)
{
	char *ip;
	struct socket * sock;
	int log_status, err = 0;

	sock = sockfd_lookup(sockfd, &err);

	if(sock == NULL || sock->sk == NULL || err < 0)
	{
		goto exit;
	}

	if((sock->sk->sk_family != AF_INET && sock->sk->sk_family != AF_INET6) || sock->sk->sk_protocol != IPPROTO_UDP)
	{
		goto exit;
	}

	#if WHITELISTING

	if(is_whitelisted(current))
	{
		goto exit;
	}

	#endif

	ip = get_ip(addr);

	if(any_ip_address(ip))
	{
		log_status = log_message("%s[%d] UDP bind (any IP address):%d (uid=%d)\n", current->comm, 
					current->pid, ntohs(((struct sockaddr_in *)addr)->sin_port), CURRENT_UID);
	}
	else
	{
		log_status = log_message("%s[%d] UDP bind %s:%d (uid=%d)\n", current->comm,
					current->pid, ip, ntohs(((struct sockaddr_in6 *)addr)->sin6_port), CURRENT_UID);
	}

	if(LOG_FAILED(log_status))
	{
		printk(KERN_ERR MODULE_NAME "Failed to log message\n");	
	}

exit:
	if(sock != NULL)
	{
		sockfd_put(sock);
	}

	jprobe_return();
	return 0;
}

#endif

int handler_fault(struct kprobe *p, struct pt_regs *regs, int trap)
{
	/*In case of an interrupt that will cause the process to quit,
	 * check if the preeemp_count is greater than 0 and decrease it
	 */

	return 0;
}


/*************************************/
/*         probe definitions        */
/*************************************/

static struct jprobe connect_jprobe = 
{	
	.entry = (kprobe_opcode_t *) netlog_inet_stream_connect,
	.kp = 
	{
		.symbol_name = "inet_stream_connect",
		.fault_handler = handler_fault,
	},
};

static struct kretprobe connect_kretprobe = 
{
        .handler = post_connect,
        .maxactive = 0,
        .kp = 
        {
        	.symbol_name = "inet_stream_connect",
		.fault_handler = handler_fault,
        },
};

static struct kretprobe accept_kretprobe = 
{
	.handler = post_accept,
	.maxactive = 0,
        .kp = 
        {
		#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
        	.symbol_name = "sys_accept",
        	#else
        	.symbol_name = "sys_accept4",
		#endif
		.fault_handler = handler_fault,
        },
};

#if PROBE_CONNECTION_CLOSE

extern struct proto tcp_prot;

static struct jprobe tcp_close_jprobe = 
{	
	.entry = (kprobe_opcode_t *) netlog_tcp_close,
	.kp = 
	{
		.fault_handler = handler_fault,
	}
};

#endif

#if PROBE_UDP && PROBE_CONNECTION_CLOSE

extern struct proto udp_prot;

static struct jprobe udp_close_jprobe = 
{	
	.entry = (kprobe_opcode_t *) netlog_udp_close,
	.kp = 
	{
		.fault_handler = handler_fault,
	}
};

#endif

#if PROBE_UDP

static struct jprobe bind_jprobe = 
{	
	.entry = (kprobe_opcode_t *) netlog_sys_bind,
	.kp = 
	{
		.symbol_name = "sys_bind",
		.fault_handler = handler_fault,
	},
};

#endif



/************************************/
/*             INIT MODULE          */
/************************************/

int __init plant_probes(void)
{
	int register_status, i;

	if(LOG_FAILED(init_logger(MODULE_NAME)))
	{
		printk(KERN_ERR MODULE_NAME "Failed to init logging facility\n");
		return LOG_FAILURE;
	}
	else
	{
		printk(KERN_INFO MODULE_NAME "Initialized logging facility\n");
	}

	register_status = register_jprobe(&connect_jprobe);

	if(register_status < 0)
	{
		printk(KERN_ERR MODULE_NAME "Failed to plant pre connect probe\n");
		return CONNECT_PROBE_FAILED;
	}

	register_status = register_kretprobe(&connect_kretprobe);

	if(register_status < 0)
	{
		printk(KERN_ERR MODULE_NAME "Failed to plant post connect probe\n");
		return CONNECT_PROBE_FAILED;
	}

	register_status = register_kretprobe(&accept_kretprobe);

	if(register_status < 0)
	{
		printk(KERN_ERR MODULE_NAME "Failed to plant accept probe\n");
		return ACCEPT_PROBE_FAILED;
	}

	#if PROBE_CONNECTION_CLOSE

	tcp_close_jprobe.kp.addr = (kprobe_opcode_t *) tcp_prot.close;
	register_status = register_jprobe(&tcp_close_jprobe);

	if(register_status < 0)
	{
		printk(KERN_ERR MODULE_NAME "Failed to plant tcp_close probe\n");
		return CLOSE_PROBE_FAILED;
	}

	#endif
	
	#if PROBE_UDP && PROBE_CONNECTION_CLOSE

	udp_close_jprobe.kp.addr = (kprobe_opcode_t *) udp_prot.close;
	register_status = register_jprobe(&udp_close_jprobe);

	if(register_status < 0)
	{
		printk(KERN_ERR MODULE_NAME "Failed to plant udp_close probe\n");
		return CLOSE_PROBE_FAILED;
	}

	#endif	

	#if PROBE_UDP

	register_status = register_jprobe(&bind_jprobe);

	if(register_status < 0)
	{
		printk(KERN_ERR MODULE_NAME "Failed to plant bind probe\n");
		return BIND_PROBE_FAILED;
	}

	#endif

	printk(KERN_INFO MODULE_NAME "Planted\n");

	#if WHITELISTING

	/*Deal with the whitelisting*/

	for(i = 0; i < NO_WHITELISTS; ++i)
	{
		int whitelist_status;

		whitelist_status = whitelist(procs_to_whitelist[i]);

		if(WHITELIST_FAILED(whitelist_status))
		{
			printk(KERN_ERR MODULE_NAME "Failed to whitelist %s\n", procs_to_whitelist[i]);
		}
		else
		{
			printk(KERN_INFO MODULE_NAME "Whitelisted %s\n", procs_to_whitelist[i]);
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

	unregister_jprobe(&tcp_close_jprobe);

	#endif

	#if PROBE_UDP && PROBE_CONNECTION_CLOSE

	unregister_jprobe(&udp_close_jprobe);	

	#endif

	#if PROBE_UDP

  	unregister_jprobe(&bind_jprobe);

	#endif

	destroy_logger();

	printk(KERN_INFO MODULE_NAME "Unplanted\n");
}

