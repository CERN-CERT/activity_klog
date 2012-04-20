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
#include <linux/preempt.h>
#include "logger.h"

#define MAX_TAG_SIZE 64

struct sockaddr_un log_file;
struct socket *log_socket = NULL;
char tag[MAX_TAG_SIZE + 1] = {'\0'};
char buffer[MAX_MESSAGE_SIZE + 1] = {'\0'};

int init_logger(const char *module_name)
{
	if(log_socket == NULL)
	{
		if(sock_create(PF_UNIX, SOCK_DGRAM, 0, &log_socket) != 0)
		{
			log_socket = NULL;
			return LOG_FAIL;
		}		

		/*Initialize socket address to LOG_PATH*/
	
		memset((void *) &log_file, 0, sizeof(log_file));
		log_file.sun_family = PF_UNIX;
		strncpy(log_file.sun_path, LOG_PATH, sizeof(log_file.sun_path) - 1);

		/*Keep module's name to print it in logs*/

		snprintf(tag, MAX_TAG_SIZE, "kernel: %s", module_name);
	}
	
	return LOG_OK;
}

int log_message(const char *format, ...)
{
	int err;
	struct iovec iov;
	struct msghdr msg;
	mm_segment_t oldfs;
	va_list arguments;
	unsigned int message_length;

	if(log_socket == NULL || format == NULL)
	{
		goto out_fail;
	}

	message_length = 0;
	
	/*Add "kernel: <module name>" at the start of the buffer*/

	message_length += snprintf(buffer, MAX_TAG_SIZE, "%s", tag);

	va_start(arguments, format);
	message_length += vsnprintf(buffer + message_length, MAX_MESSAGE_SIZE - message_length, format, arguments);
	va_end(arguments);

	buffer[message_length++] = '\0';

	/*Prepare message header and send the buffer*/

	msg.msg_name = (struct sockaddr *) &log_file;
	msg.msg_namelen = sizeof(struct sockaddr_un) - 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_NOSIGNAL;

	iov.iov_base = (char *) buffer;
	iov.iov_len = (__kernel_size_t) message_length;

	oldfs = get_fs(); 
	set_fs(KERNEL_DS);

	err = sock_sendmsg(log_socket, &msg, strnlen(buffer, MAX_MESSAGE_SIZE));

	set_fs(oldfs);

	if(err < 0)
	{
		goto out_fail;
	}

	buffer[0] = '\0';

	return LOG_OK;
out_fail:
	return LOG_FAIL;
}

void destroy_logger(void)
{
	if(log_socket != NULL)
	{
		sock_release(log_socket);
		log_socket = NULL;
	}
}

