#include <linux/socket.h>
#include <linux/un.h>
#include <linux/file.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/net.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/utsname.h>
#include <linux/param.h>
#include <linux/version.h>
#include <net/sock.h>
#include "logger.h"

#define MAX_TAG_SIZE 64
#define BUFFER_LEN MAX_TAG_SIZE + MAX_MESSAGE_SIZE + 1

DEFINE_PER_CPU(struct sockaddr_un, log_file);
DEFINE_PER_CPU(struct socket *, log_socket = NULL);

DEFINE_PER_CPU(char [MAX_TAG_SIZE + 1], tag = {'\0'});

void _init_logger(void *name)
{
	char *module_name = (char *)name;
	char *my_tag = get_cpu_var(tag);
	struct sockaddr_un *my_log_file = &get_cpu_var(log_file);
	struct socket *my_log_socket = get_cpu_var(log_socket);

	if(my_log_socket == NULL)
	{
		if(sock_create_kern(PF_UNIX, SOCK_DGRAM, 0, &my_log_socket) != 0)
		{
			goto out_fail;
		}		

		/*Initialize socket address to LOG_PATH*/
	
		memset((void *) my_log_file, 0, sizeof(struct sockaddr_un));
		my_log_file->sun_family = PF_UNIX;
		strncpy(my_log_file->sun_path, LOG_PATH, sizeof(my_log_file->sun_path));

		/*Keep module's name to print it in logs*/

		snprintf(my_tag, MAX_TAG_SIZE, "kernel: %s", module_name);
	}

	put_cpu_var(log_file);
	put_cpu_var(log_socket);
	put_cpu_var(tag);
	
//	return (void *)LOG_OK;
out_fail:

	my_log_socket = NULL;
	
	put_cpu_var(log_file);
	put_cpu_var(log_socket);
	put_cpu_var(tag);

//	return (void *) LOG_FAIL;
}

void init_logger(const char *module_name)
{	
	on_each_cpu(_init_logger, (void *) module_name, 0);
}

int log_message(const char *format, ...)
{
	int err;
	struct iovec iov;
	struct msghdr msg;
	mm_segment_t oldfs;
	va_list arguments;
	unsigned int message_length;
	char buffer[BUFFER_LEN] = {'\0'};

	char *my_tag = get_cpu_var(tag);
	struct sockaddr_un *my_log_file = &get_cpu_var(log_file);
	struct socket *my_log_socket = get_cpu_var(log_socket);

	if(my_log_socket == NULL || format == NULL)
	{
		goto out_fail;
	}

	/*Add "kernel: <module name>" at the start of the buffer*/

	message_length = snprintf(buffer, MAX_TAG_SIZE, "%s", my_tag);

	if(message_length < 0)
	{
		goto out_fail;
	}

	va_start(arguments, format);
	message_length += vsnprintf(buffer + message_length, MAX_MESSAGE_SIZE, format, arguments);
	va_end(arguments);

	buffer[message_length++] = '\0';
	
	/*Prepare message header and send the buffer*/

	msg.msg_name = (struct sockaddr *) my_log_file;
	msg.msg_namelen = sizeof(struct sockaddr_un);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_NOSIGNAL;

	iov.iov_base = (char *) buffer;
	iov.iov_len = (__kernel_size_t) message_length;

	oldfs = get_fs(); 
	set_fs(KERNEL_DS);

	err = sock_sendmsg(my_log_socket, &msg, message_length);

	if(err < 0)
	{
		printk("%d\n", err);
		goto out_fail;
	}
	
	set_fs(oldfs);

	put_cpu_var(log_socket);
	put_cpu_var(tag);
	put_cpu_var(log_file);

	return LOG_OK;
out_fail:
	printk(KERN_ERR "%sFailed to log message\n", my_tag);

	put_cpu_var(log_socket);
	put_cpu_var(tag);
	put_cpu_var(log_file);

	return LOG_FAIL;
}

void destroy_logger(void)
{
	char *my_tag = get_cpu_var(tag);
	struct socket *my_log_socket = get_cpu_var(log_socket);

	if(my_log_socket != NULL)
	{
		sock_release(my_log_socket);
		my_log_socket = NULL;
		
		printk(KERN_INFO "%sLogging facility destroyed\n", my_tag);		
	}

	put_cpu_var(tag);
	put_cpu_var(log_socket);	
}


