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
#include <linux/limits.h>
#include "logger.h"

#define MAX_TAG_SIZE 30
#define BUFFER_LEN MAX_TAG_SIZE + MAX_MESSAGE_SIZE

static struct sockaddr_un log_sockaddr;
static struct socket *log_socket = NULL;

char tag[MAX_TAG_SIZE + 1] = {'\0'};

int init_logger(const char *module_name)
{
	if(log_socket != NULL)
	{
		goto out;
	}

	if(module_name == NULL)
	{
		goto out_fail;
	}

	if(sock_create_kern(PF_UNIX, SOCK_DGRAM, 0, &log_socket) < 0)
	{
		goto out_fail;
	}		

	/*Initialize socket address to LOG_PATH*/

	memset((void *) &log_sockaddr, 0, sizeof(log_sockaddr));
	log_sockaddr.sun_family = PF_UNIX;
	strncpy(log_sockaddr.sun_path, LOG_PATH, sizeof(log_sockaddr.sun_path));

	/*Keep module's name to print it in logs*/

	snprintf(tag, MAX_TAG_SIZE, "<6>kernel: %s", module_name);
	
	printk("%sLogging facility initialized\n", tag);
out:
	return LOG_OK;
out_fail:
	log_socket = NULL;
	return LOG_FAIL;
}

int log_message(const char *format, ...)
{
	int err;
	struct iovec iov;
	struct msghdr header;
	mm_segment_t oldfs;
	va_list arguments;
	unsigned int message_length;
//	static char buffer[BUFFER_LEN + 1] = {'\0'};
	char buffer[BUFFER_LEN + 1] = {'\0'};

	if(unlikely(log_socket == NULL) || unlikely(format == NULL))
	{
		goto out_fail;
	}

	/*Add tag at the start of the buffer*/

	message_length = snprintf(buffer, MAX_TAG_SIZE, "%s", tag);

	if(unlikely(message_length <= 0))
	{
		goto out_fail;
	}

	/*Append buffer with the log message*/

	va_start(arguments, format);
	err = vsnprintf(buffer + message_length, MAX_MESSAGE_SIZE, format, arguments);
	va_end(arguments);

	if(err < 0)
	{
		printk(KERN_ERR "%slogger: Message truncated\n", tag);
		goto out_fail;
	}

	message_length += err;
	buffer[message_length++] = '\0';

	/*Prepare message header and send the buffer*/

	header.msg_name = (struct sockaddr *) &log_sockaddr;
	header.msg_namelen = sizeof(log_sockaddr);
	header.msg_iov = &iov;
	header.msg_iovlen = 1;
	header.msg_control = NULL;
	header.msg_controllen = 0;
	header.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;

	iov.iov_base = (char *) buffer;
	iov.iov_len = (__kernel_size_t) message_length;

	oldfs = get_fs(); 
	set_fs(KERNEL_DS);

	err = sock_sendmsg(log_socket, &header, message_length);

	set_fs(oldfs);

	if(unlikely(err < 0))
	{
		goto out_fail;
	}
	
//	memset(buffer, '\0', BUFFER_LEN);

	return LOG_OK;
out_fail:
	printk(KERN_ERR "Failed to log message: %s", buffer);
//	memset(buffer, '\0', BUFFER_LEN);

	return LOG_FAIL;
}

void destroy_logger(void)
{
	if(log_socket == NULL)
	{
		return;
	}

	sock_release(log_socket);
	log_socket = NULL;
	
	printk("%sLogging facility destroyed\n", tag);		
}


