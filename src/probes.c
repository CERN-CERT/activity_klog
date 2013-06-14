#include <linux/file.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/ipv6.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <net/ip.h>
#include "whitelist.h"
#include "netlog.h"
#include "log.h"
#include "probes.h"
#include "retro-compat.h"
#include "internal.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	#define get_current_uid() current->uid
	#define call_d_path(file, buffer, length) d_path(file->f_dentry, file->f_vfsmnt, buffer, length);
#else
	#define get_current_uid() current_uid()
	#define call_d_path(file, buffer, length) d_path(&file->f_path, buffer, length);
#endif

/********************************/
/*            Tools             */
/********************************/

static char *path_from_mm(struct mm_struct *mm, char *buffer, int length)
{
        char *p = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
        struct vm_area_struct *vma;

        if(unlikely(mm == NULL))
        {
                return NULL;
        }

        vma = mm->mmap;

        while(vma)
        {
                if((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
                {
                        break;
                }

                vma = vma->vm_next;
        }

        if(vma && vma->vm_file)
        {
                p = call_d_path(vma->vm_file, buffer, length);

                if(IS_ERR(p))
                {
                        p = NULL;
                }
        }
#else
        if (unlikely(mm == NULL))
                return NULL;

        down_read(&mm->mmap_sem);

        if (unlikely(mm->exe_file == NULL)) {
		p = NULL;
	} else {
                p = call_d_path(mm->exe_file, buffer, length);
                if(IS_ERR(p))
                        p = NULL;
        }

        up_read(&mm->mmap_sem);
#endif
        return p;
}

static char *get_path(char *buffer, size_t len)
{
        if(!absolute_path_mode)
		return current->comm;
	else
		return path_from_mm(current->mm, buffer, len);
}

static void log_if_not_whitelisted(struct socket *sock, u8 protocol, u8 action)
{
	/* sock & sock->sk need to be non null */

	char buffer[MAX_ABSOLUTE_EXEC_PATH + 1], *path;
	unsigned short family;
	const void *dst_ip;
	const void *src_ip;
	int dst_port;
	int src_port;

	path = get_path(buffer, MAX_ABSOLUTE_EXEC_PATH);
	buffer[MAX_ABSOLUTE_EXEC_PATH] = '\0';
	if(unlikely(path == NULL))
		return;

	/* Get everything */
	family = sock->sk->sk_family;
	dst_port = ntohs(inet_sk(sock->sk)->DPORT);
	src_port = ntohs(inet_sk(sock->sk)->SPORT);
	switch(family)
	{
		case AF_INET:
			dst_ip = &inet_sk(sock->sk)->DADDR;
			src_ip = &inet_sk(sock->sk)->SADDR;
			break;
		case AF_INET6:
			dst_ip = &inet6_sk(sock->sk)->daddr;
			src_ip = &inet6_sk(sock->sk)->saddr;
			break;
		default:
			dst_ip = NULL;
			src_ip = NULL;
			break;
	}

#if WHITELISTING
	/* Are we whitelisted ? */
	if(is_whitelisted(path, family, dst_ip, dst_port))
		return;
#endif

        store_record(current->pid, get_current_uid(), path, action, protocol,
	             family, src_ip, src_port, dst_ip, dst_port);
}

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

static int stream_pre_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{
	if (likely(current != NULL))
		match_socket[current->pid] = sock;

	jprobe_return();
	return 0;
}

static int stream_post_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct socket *sock;

	sock = match_socket[current->pid];

	if (likely(current != NULL) &&
	    likely(sock != NULL) &&
	    likely(sock->sk != NULL) &&
	    likely(sock->sk->sk_family == AF_INET ||
	           sock->sk->sk_family == AF_INET6) &&
	    likely(sock->sk->sk_protocol == IPPROTO_TCP))
		log_if_not_whitelisted(sock, PROTO_TCP, ACTION_CONNECT);

	match_socket[current->pid] = NULL;
	return 0;
}

#if PROBE_UDP
static int dgram_pre_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{
	if (likely(current != NULL))
		match_socket[current->pid] = sock;

	jprobe_return();
	return 0;
}

static int dgram_post_connect(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct socket *sock;

	sock = match_socket[current->pid];

	if (likely(current != NULL) &&
	    likely(sock != NULL) &&
	    likely(sock->sk != NULL) &&
	    likely(sock->sk->sk_family == AF_INET ||
	           sock->sk->sk_family == AF_INET6) &&
	    likely(sock->sk->sk_protocol == IPPROTO_UDP))
		log_if_not_whitelisted(sock, PROTO_UDP, ACTION_CONNECT);

	match_socket[current->pid] = NULL;
	return 0;
}
#endif /* PROBE_UDP */

/* post_accept probe is called right after the accept system call returns.
 * In the return register is placed the socket file descriptor. So with the
 * user of regs_register_status we can get the socket file descriptor and log
 * the data that we want for the socket.
 */

static int post_accept(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct socket *sock;
	int err;

	sock = sockfd_lookup(regs_return_value(regs), &err);

	if (likely(sock != NULL)) {
		if (likely(sock->sk != NULL) &&
		    likely(sock->sk->sk_family == AF_INET ||
		           sock->sk->sk_family == AF_INET6) &&
		    likely(sock->sk->sk_protocol == IPPROTO_TCP))
			log_if_not_whitelisted(sock, PROTO_TCP, ACTION_ACCEPT);
		sockfd_put(sock);
	}
	return 0;
}

#if PROBE_CONNECTION_CLOSE
asmlinkage static long netlog_sys_close(unsigned int fd)
{
	struct socket *sock;
	int err;

	sock = sockfd_lookup(fd, &err);

	if (unlikely(current == NULL) ||
	    unlikely(sock == NULL) ||
	    unlikely(sock->sk == NULL) ||
	    likely(sock->sk->sk_family != AF_INET &&
	           sock->sk->sk_family != AF_INET6))
		goto out;

	if (sock->sk->sk_protocol == IPPROTO_TCP &&
	    likely(inet_sk(sock->sk)->DPORT != 0))
		log_if_not_whitelisted(sock, PROTO_TCP, ACTION_CLOSE);
#if PROBE_UDP
	else if (sock->type == SOCK_DGRAM &&
	         sock->sk->sk_protocol == IPPROTO_UDP &&
	         inet_sk(sock->sk)->SPORT != 0)
		log_if_not_whitelisted(sock, PROTO_UDP, ACTION_CLOSE);
#endif

out:
	if(likely(sock != NULL))
		sockfd_put(sock);

	jprobe_return();
	return 0;
}

#endif /* PROBE_CONNECTION_CLOSE */

#if PROBE_UDP
static struct socket *match_bind[PID_MAX_LIMIT] = {NULL};

static int post_bind(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct socket *sock;
	sock = match_bind[current->pid];

	if (likely(sock != NULL)) {
		if (likely(sock->sk != NULL) &&
		    likely(sock->sk->sk_family == AF_INET ||
		           sock->sk->sk_family == AF_INET6) &&
		    likely(sock->sk->sk_protocol == IPPROTO_UDP))
			log_if_not_whitelisted(sock, PROTO_UDP, ACTION_BIND);
		sockfd_put(sock);
	}

	match_bind[current->pid] = NULL;
	return 0;
}

/* UDP protocol is connectionless protocol, so we probe the bind system call */
asmlinkage static int pre_bind(int sockfd, const struct sockaddr *addr, int addrlen)
{
	int err;
	struct socket *sock;

	if (unlikely(current == NULL))
		return 0;

	sock = sockfd_lookup(sockfd, &err);

	if (likely(sock != NULL))
		match_bind[current->pid] = sock;

	jprobe_return();
	return 0;
}
#endif /* PROBE_UDP */

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

static struct jprobe stream_connect_jprobe =
{
	.entry = (kprobe_opcode_t *) stream_pre_connect,
	.kp =
	{
		.symbol_name = "inet_stream_connect",
		.fault_handler = handler_fault,
	},
};

static struct kretprobe stream_connect_kretprobe =
{
        .handler = stream_post_connect,
        .maxactive = 16 * NR_CPUS,
        .kp =
        {
        	.symbol_name = "inet_stream_connect",
		.fault_handler = handler_fault,
        },
};

#if PROBE_UDP
static struct jprobe dgram_connect_jprobe =
{
	.entry = (kprobe_opcode_t *) dgram_pre_connect,
	.kp =
	{
		.symbol_name = "inet_dgram_connect",
		.fault_handler = handler_fault,
	},
};

static struct kretprobe dgram_connect_kretprobe =
{
        .handler = dgram_post_connect,
        .maxactive = 16 * NR_CPUS,
        .kp =
        {
        	.symbol_name = "inet_dgram_connect",
		.fault_handler = handler_fault,
        },
};
#endif /* PROBE_UDP */

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

static struct jprobe close_jprobe =
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

static struct kretprobe bind_kretprobe =
{
	.handler = post_bind,
	.maxactive = 16 * NR_CPUS,
        .kp =
        {
		.symbol_name = "sys_bind",
		.fault_handler = handler_fault,
        },
};

static struct jprobe bind_jprobe =
{
	.entry = (kprobe_opcode_t *) pre_bind,
	.kp =
	{
		.symbol_name = "sys_bind",
		.fault_handler = handler_fault,
	},
};

#endif

void unplant_all(void)
{
  	unregister_jprobe(&stream_connect_jprobe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted stream connect pre handler probe\n");

	unregister_kretprobe(&stream_connect_kretprobe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted stream connect post handler probe\n");

#if PROBE_UDP
  	unregister_jprobe(&dgram_connect_jprobe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted dgram connect pre handler probe\n");

	unregister_kretprobe(&dgram_connect_kretprobe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted dgram connect post handler probe\n");
#endif

	unregister_kretprobe(&accept_kretprobe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted accept post handler probe\n");

	#if PROBE_CONNECTION_CLOSE

	unregister_jprobe(&close_jprobe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted close pre handler probe\n");

	#endif

	#if PROBE_UDP

	unregister_kretprobe(&bind_kretprobe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted bind post handler probe\n");

  	unregister_jprobe(&bind_jprobe);
	printk(KERN_INFO MODULE_NAME ":\t[+] Unplanted bind pre handler probe\n");

	#endif
}

int plant_all(void)
{
	int err;

	err = register_jprobe(&stream_connect_jprobe);

	if(err < 0)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Failed to plant stream connect pre handler\n");
		unplant_all();

		return -CONNECT_PROBE_FAILED;
	}

	printk(KERN_INFO MODULE_NAME ":\t[+] Planted stream connect pre handler\n");

	err = register_kretprobe(&stream_connect_kretprobe);

	if(err < 0)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Failed to plant stream connect post handler\n");
		unplant_all();

		return -CONNECT_PROBE_FAILED;
	}

	printk(KERN_INFO MODULE_NAME ":\t[+] Planted stream connect post handler\n");

#if PROBE_UDP
	err = register_jprobe(&dgram_connect_jprobe);

	if(err < 0)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Failed to plant dgram connect pre handler\n");
		unplant_all();

		return -CONNECT_PROBE_FAILED;
	}

	printk(KERN_INFO MODULE_NAME ":\t[+] Planted dgram connect pre handler\n");

	err = register_kretprobe(&dgram_connect_kretprobe);

	if(err < 0)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Failed to plant dgram connect post handler\n");
		unplant_all();

		return -CONNECT_PROBE_FAILED;
	}

	printk(KERN_INFO MODULE_NAME ":\t[+] Planted dgramconnect post handler\n");
#endif /* PROBE_UDP */

	err = register_kretprobe(&accept_kretprobe);

	if(err < 0)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Failed to plant accept post handler\n");
		unplant_all();

		return -ACCEPT_PROBE_FAILED;
	}

	printk(KERN_INFO MODULE_NAME ":\t[+] Planted accept post handler\n");

	#if PROBE_CONNECTION_CLOSE

	err = register_jprobe(&close_jprobe);

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

	err = register_kretprobe(&bind_kretprobe);

	if(err < 0)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Failed to plant bind post handler\n");
		unplant_all();

		return -BIND_PROBE_FAILED;
	}

	printk(KERN_INFO MODULE_NAME ":\t[+] Planted bind post handler\n");

	#endif

	return 0;
}
