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
#include "inet_utils.h"
#include "whitelist.h"
#include "netlog.h"
#include "connection.h"
#include "proc_config.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	#define get_current_uid() current->uid
#else
	#define get_current_uid() current_uid()
#endif

#define MODULE_NAME "netlog"

/**********************************/
/*      MODULE PARAMETERS         */
/**********************************/

int absolute_path_mode = 0;

module_param(absolute_path_mode, int, 0);
MODULE_PARM_DESC(absolute_path_mode, " Boolean parameter for absolute path mode. When enabled, \n"
				"\t\tit will log the execution path instead of the process name");


#if WHITELISTING

static int whitelist_length = 0;
static char *connections_to_whitelist[MAX_WHITELIST_SIZE] = {'\0'};

module_param_array(connections_to_whitelist, charp, &whitelist_length, 0000);
MODULE_PARM_DESC(connections_to_whitelist, " An array of strings that contains the connections that " MODULE_NAME " will ignore.\n"
					    "\t\tThe format of the string must be '/absolute/executable/path ip_address-port'");

#endif

/**********************************/
/*           PROBES               */
/**********************************/

/* The next two probes are for the connect system call. We need to associate the process that 
 * requested the connection with the socket file descriptor that the kernel returned.
 * The socket file descriptor is available only after the system call returns. 
 * Though we need to be able to get the pointer to the socket struct that was given as a parameter
 * to connect and log its contents. We cannot have a process requesting two connects in the same time,
 * because when a system call is called, the process is suspended until its end of execution.
 */

static struct socket *match_socket[PID_MAX_LIMIT] = {NULL};

static int netlog_inet_stream_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{	
	if(unlikely(current == NULL))
	{
		goto out;
	}

	match_socket[current->pid] = sock;
out:
	jprobe_return();
	return 0;
}

static int post_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct socket *sock;
	int destination_port;
	char *destination_ip;

	sock = match_socket[current->pid];

	if(unlikely(!is_tcp(sock)) || unlikely(!is_inet(sock)))
	{
		goto out;
	}

	if(unlikely(current == NULL))
	{
		goto out;
	}	

	destination_ip = get_destination_ip(sock);
	destination_port = get_destination_port(sock);

	#if WHITELISTING

	if(is_whitelisted(current, destination_ip, destination_port))
	{
		goto out;
	}

	#endif

	if(!absolute_path_mode)
	{
		printk(KERN_INFO MODULE_NAME ": %s[%d] TCP %s:%d -> %s:%d (uid=%d)\n", current->comm, current->pid, 
									get_source_ip(sock), get_source_port(sock),
									destination_ip, destination_port, 
									get_current_uid());
	}
	else
	{
		char buffer[MAX_ABSOLUTE_EXEC_PATH + 1], *path;
		path = exe_from_mm(current->mm, buffer, sizeof(buffer));

		printk(KERN_INFO MODULE_NAME ": %s[%d] TCP %s:%d -> %s:%d (uid=%d)\n", path, current->pid,
									get_source_ip(sock), get_source_port(sock),
									destination_ip, destination_port, 
									get_current_uid());
	}

out:
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
	char *destination_ip;
	int err, destination_port;

	sock = sockfd_lookup(regs_return_value(regs), &err);

	if(unlikely(!is_tcp(sock)) || unlikely(!is_inet(sock)))
	{
		goto out;
	}

	if(unlikely(current == NULL))
	{
		goto out;
	}

	destination_ip = get_destination_ip(sock);
	destination_port = get_destination_port(sock);

	#if WHITELISTING

	if(is_whitelisted(current, destination_ip, destination_port))
	{
		goto out;
	}

	#endif


	if(!absolute_path_mode)
	{
		printk(KERN_INFO MODULE_NAME ": %s[%d] TCP %s:%d <- %s:%d (uid=%d)\n", current->comm, current->pid, 
									get_source_ip(sock), get_source_port(sock),
									destination_ip, destination_port, 
									get_current_uid()); 
	}
	else
	{
		char buffer[MAX_ABSOLUTE_EXEC_PATH + 1], *path;
		path = exe_from_mm(current->mm, buffer, sizeof(buffer));

		printk(KERN_INFO MODULE_NAME ": %s[%d] TCP %s:%d <- %s:%d (uid=%d)\n", path, current->pid, 
									get_source_ip(sock), get_source_port(sock),
									destination_ip, destination_port, 
									get_current_uid()); 
	}

out:
	if(likely(sock != NULL))
	{
		sockfd_put(sock);
	}

	return 0;
}

#if PROBE_CONNECTION_CLOSE

asmlinkage static long netlog_sys_close(unsigned int fd)
{
	struct socket *sock;
	char *destination_ip;
	int err, destination_port;

	sock = sockfd_lookup(fd, &err);

	if(likely(!is_inet(sock)) || unlikely(current == NULL))
	{
		goto out;
	}

	destination_ip = get_destination_ip(sock);
	destination_port = get_destination_port(sock);

	#if WHITELISTING

	if(is_whitelisted(current, destination_ip, destination_port))
	{
		goto out;
	}

	#endif

	if(is_tcp(sock) && likely(get_destination_port(sock) != 0))
	{	
	
		if(!absolute_path_mode)
		{
			printk(KERN_INFO MODULE_NAME ": %s[%d] TCP %s:%d <-> %s:%d (uid=%d)\n", current->comm, current->pid, 
										get_source_ip(sock), get_source_port(sock),
										destination_ip, destination_port, 
										get_current_uid());
		}
		else
		{
			char buffer[MAX_ABSOLUTE_EXEC_PATH + 1], *path;
			path = exe_from_mm(current->mm, buffer, sizeof(buffer));
		
			printk(KERN_INFO MODULE_NAME ": %s[%d] TCP %s:%d <-> %s:%d (uid=%d)\n", path, current->pid, 
									get_source_ip(sock), get_source_port(sock),
									destination_ip, destination_port, 
									get_current_uid());
		}
	}

	#if PROBE_UDP

	else if(is_udp(sock) && is_inet(sock))
	{
		if(!absolute_path_mode)
		{
			printk(KERN_INFO MODULE_NAME ": %s[%d] UDP %s:%d <-> %s:%d (uid=%d)\n", current->comm, current->pid, 
										get_source_ip(sock), get_source_port(sock),
										destination_ip, destination_port, 
										get_current_uid());
		}
		else
		{
			char buffer[MAX_ABSOLUTE_EXEC_PATH + 1], *path;
			path = exe_from_mm(current->mm, buffer, sizeof(buffer));
		
			printk(KERN_INFO MODULE_NAME ": %s[%d] UDP %s:%d <-> %s:%d (uid=%d)\n", 
										path, current->pid, 
										get_source_ip(sock), get_source_port(sock),
										destination_ip, destination_port, 
										get_current_uid());
		}
	}

	#endif

out:
	if(likely(sock != NULL))
	{
		sockfd_put(sock);
	}

	jprobe_return();
	return 0;
}

#endif

#if PROBE_UDP

/* UDP protocol is connectionless protocol, so we probe the bind system call */

asmlinkage static int netlog_sys_bind(int sockfd, const struct sockaddr *addr, int addrlen)
{
	int err;
	char *ip;
	struct socket *sock;

	sock = sockfd_lookup(sockfd, &err);

	if(!is_inet(sock) || !is_udp(sock))
	{
		goto out;
	}

	if(unlikely(current == NULL))
	{
		goto out;
	}

	ip = get_ip(addr);

	#if WHITELISTING

	if(is_whitelisted(current, ip, NO_PORT))
	{
		goto out;
	}

	#endif

	if(any_ip_address(ip))
	{
		if(!absolute_path_mode)
		{
			printk(KERN_INFO MODULE_NAME ": %s[%d] UDP bind (any IP address):%d (uid=%d)\n", 
										current->comm, current->pid,
										ntohs(((struct sockaddr_in *)addr)->sin_port), 
										get_current_uid());
		}
		else
		{
			char buffer[MAX_ABSOLUTE_EXEC_PATH + 1], *path;
			path = exe_from_mm(current->mm, buffer, sizeof(buffer));

			printk(KERN_INFO MODULE_NAME ": %s[%d] UDP bind (any IP address):%d (uid=%d)\n", 
											path, current->pid,
										 	ntohs(((struct sockaddr_in *)addr)->sin_port), 
										 	get_current_uid());		
		}
	}
	else
	{
		if(!absolute_path_mode)
		{
			printk(KERN_INFO MODULE_NAME ": %s[%d] UDP bind %s:%d (uid=%d)\n", current->comm, current->pid, ip, 
											ntohs(((struct sockaddr_in6 *)addr)->sin6_port), 
											get_current_uid());
		}
		else
		{
			char buffer[MAX_ABSOLUTE_EXEC_PATH + 1], *path;
			path = exe_from_mm(current->mm, buffer, sizeof(buffer));
		
			printk(KERN_INFO MODULE_NAME ": %s[%d] UDP bind %s:%d (uid=%d)\n", path, current->pid, ip,
											ntohs(((struct sockaddr_in6 *)addr)->sin6_port), 
											get_current_uid());		
		}
	}

out:
	if(likely(sock != NULL))
	{
		sockfd_put(sock);
	}

	jprobe_return();
	return 0;
}

#endif

int signal_that_will_cause_exit(int trap_number)
{
	switch(trap_number)
	{
		case SIGABRT:
		case SIGSEGV:
		case SIGQUIT:
		//TODO Other signals that we need to handle?
			return 1;
			break;
		default:
			return 0;
			break;
	}
}

int handler_fault(struct kprobe *p, struct pt_regs *regs, int trap_number)
{
	if(signal_that_will_cause_exit(trap_number))
	{
		printk(KERN_ERR MODULE_NAME ": fault handler: Detected fault %d from inside probes.", trap_number);
	}

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
        .maxactive = 16 * NR_CPUS,
        .kp = 
        {
        	.symbol_name = "inet_stream_connect",
		.fault_handler = handler_fault,
        },
};

static struct kretprobe accept_kretprobe = 
{
	.handler = post_accept,
	.maxactive = 16 * NR_CPUS,
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

static struct jprobe tcp_close_jprobe = 
{	
	.entry = (kprobe_opcode_t *) netlog_sys_close,
	.kp = 
	{
		.symbol_name = "sys_close",
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

void unplant_all(void)
{
  	unregister_jprobe(&connect_jprobe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted connect pre handler probe\n");
	
	unregister_kretprobe(&connect_kretprobe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted connect post handler probe\n");

	unregister_kretprobe(&accept_kretprobe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted accept post handler probe\n");

	#if PROBE_CONNECTION_CLOSE

	unregister_jprobe(&tcp_close_jprobe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted close pre handler probe\n");

	#endif

	#if PROBE_UDP

  	unregister_jprobe(&bind_jprobe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted bind pre handler probe\n");

	#endif
}

int plant_all(void)
{
	int err;

	err = register_jprobe(&connect_jprobe);

	if(err < 0)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Failed to plant connect pre handler\n");
		unplant_all();
		
		return -CONNECT_PROBE_FAILED;
	}

	printk(KERN_INFO MODULE_NAME ":\t[+] Planted connect pre handler\n");

	err = register_kretprobe(&connect_kretprobe);

	if(err < 0)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Failed to plant connect post handler\n");
		unplant_all();
		
		return -CONNECT_PROBE_FAILED;
	}

	printk(KERN_INFO MODULE_NAME ":\t[+] Planted connect post handler\n");

	err = register_kretprobe(&accept_kretprobe);

	if(err < 0)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Failed to plant accept post handler\n");
		unplant_all();
		
		return -ACCEPT_PROBE_FAILED;
	}

	printk(KERN_INFO MODULE_NAME ":\t[+] Planted accept post handler\n");

	#if PROBE_CONNECTION_CLOSE

	err = register_jprobe(&tcp_close_jprobe);

	if(err < 0)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Failed to plant close pre handler\n");
		unplant_all();
		
		return -CLOSE_PROBE_FAILED;
	}

	printk(KERN_INFO MODULE_NAME ":\t[+] Planted close pre handler\n");

	#endif
	
	#if PROBE_UDP

	err = register_jprobe(&bind_jprobe);

	if(err < 0)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Failed to plant bind pre handler\n");
		unplant_all();
		
		return -BIND_PROBE_FAILED;
	}

	printk(KERN_INFO MODULE_NAME ":\t[+] Planted bind pre handler\n");

	#endif

	return 0;
}

#if WHITELISTING

void do_whitelist(void)
{
	int i, err;

	/*Deal with the whitelisting*/

	if(whitelist_length > MAX_WHITELIST_SIZE)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Cannot whitelist more than %d connections. The %d last parameters paths will be ignored. \
					Please change MAX_WHITELIST_SIZE definition in netlog.h and recompile, or contact \
					CERN-CERT <cert@cern.ch>\n", MAX_WHITELIST_SIZE, whitelist_length - MAX_WHITELIST_SIZE);
					
		whitelist_length = MAX_WHITELIST_SIZE;
	}

	/*Will not check if the paths are valid, because in case that they are, they will be ignored*/

	for(i = 0; i < whitelist_length; ++i)
	{
		err = whitelist(connections_to_whitelist[i]);

		if(err < 0)
		{
			printk(KERN_ERR MODULE_NAME ":\t[-] Failed to whitelist %s\n", connections_to_whitelist[i]);
		}
		else
		{
			printk(KERN_INFO MODULE_NAME ":\t[+] Whitelisted %s\n", connections_to_whitelist[i]);
		}
	}
}

#endif

/************************************/
/*             INIT MODULE          */
/************************************/

int __init plant_probes(void)
{
	int err;

	printk(KERN_INFO MODULE_NAME ": Light monitoring tool for inet connections by CERN Security Team\n");

	err = plant_all();

	if(err < 0)
	{
		return err;
	}

	#if WHITELISTING

	err = create_proc_config();

	if(err < 0)
	{
		printk(KERN_INFO MODULE_NAME ":\t[-] Creation of proc file for configuring connection whitelisting failed\n");
	}
	else
	{
		printk(KERN_INFO MODULE_NAME ":\t[+] Created %s proc file for configuring connection whitelisting\n", PROC_CONFIG_NAME);
	}

	do_whitelist();

	#endif

	if(absolute_path_mode)
	{
		printk(KERN_INFO MODULE_NAME ":\t[+] Absolute path mode is enabled. The logs will contain the absolute execution path\n");
	}
	else
	{
		printk(KERN_INFO MODULE_NAME ":\t[-] Absolute path mode is disabled. The logs will contain the process name\n");
	}

	printk(KERN_INFO MODULE_NAME ":\t[+] Deployed\n");

	return 0;
}

/************************************/
/*             EXIT MODULE          */
/************************************/

void __exit unplant_probes(void)
{
	unplant_all();

	#if WHITELISTING

	destroy_whitelist();
	destroy_proc_config();

	#endif
}
