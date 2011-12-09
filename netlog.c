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
#include <linux/unistd.h>

char *get_remote_ip(int);
char *get_local_ip(int);
char *inet_ntoa(struct in_addr in);

static int post_accept(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int err;
	struct inet_sock *inet;
	struct socket *sock = sockfd_lookup(regs_return_value(regs), &err);
		
	if(sock == NULL || sock->sk == NULL)
		return 0;
	
	if(sock->sk->sk_protocol != IPPROTO_TCP)
	{
		return 0;
	}

	inet = inet_sk(sock->sk);
	
	if(inet == NULL)
		return 0;
	
	printk("netlog: %s[%d] TCP accept %s:%d <- %s:%d (uid=%d)\n", current->comm, current->pid, 
				get_local_ip(inet->inet_saddr), ntohs(inet->inet_sport),
				get_remote_ip(inet->inet_daddr), ntohs(inet->inet_dport), 
				sock_i_uid(sock->sk));
	

        return 0;
}

static struct kretprobe accept_kretprobe = {
        .handler                = post_accept,
        .maxactive              = 100,
        .kp = {
        	.symbol_name = "sys_accept"
        	},
};



int init_module(void)
{
	int ret;
	
	ret = register_kretprobe(&accept_kretprobe);
        
        if(ret < 0) 
        {
                return -1;
        }

	ret = register_jprobe(&inet_stream_connect_jprobe);

	if(ret < 0)
	{
		return -1;
	}
	
	printk("netlog: planted\n");        

	return 0;
}

void cleanup_module(void)
{
	unregister_kretprobe(&accept_kretprobe);
	unregister_jprobe(&inet_stream_connect_jprobe);
	
	printk("netlog: unplanted\n");
}

MODULE_LICENSE("GPL");

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

char *get_local_ip(int in)
{
	static char b[18];
	register char*p;
	
	p = (char *)&in;
#define	UC(b)	(((int)b)&0xff)
	(void)snprintf(b, sizeof(b),
	    "%u.%u.%u.%u", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));
	return (b);		
}

char *get_remote_ip(int in)
{
	static char b[18];
	register char*p;
	
	p = (char *)&in;
#define	UC(b)	(((int)b)&0xff)
	(void)snprintf(b, sizeof(b),
	    "%u.%u.%u.%u", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));
	return (b);		
}

