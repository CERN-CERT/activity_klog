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

#define MAX_MODULE_NAME 64

struct sockaddr_un log_file;
struct socket *log_socket = NULL;
char from_module[MAX_MODULE_NAME] = {'\0'};
char buffer[MAX_MESSAGE_SIZE] = {'\0'};

int init_logger(const char *module_name)
{
	if(log_socket == NULL)
	{
		
		if(sock_create_kern(PF_UNIX, SOCK_DGRAM, 0, &log_socket) < 0)
		{
			log_socket = NULL;
			return LOG_FAIL;
		}		

		/*Initialize socket address to*/
	
		memset((void *) &log_file, 0, sizeof(log_file));
		log_file.sun_family = PF_UNIX;
		strncpy(log_file.sun_path, LOG_PATH, UNIX_PATH_MAX);

		/*Keep module's name to print it in logs*/

		strncpy(from_module, module_name, MAX_MODULE_NAME);
	}
	
	return LOG_OK;
}

int log_message(const char *format, ...)
{
	struct iovec iov;
	struct msghdr msg;
	mm_segment_t oldfs;
	va_list arguments;
	unsigned int message_start;
	
	if(log_socket == NULL || format == NULL)
	{
		return LOG_FAIL;
	}
	
	message_start = 0;

	/*Add "kernel: <module name>" at the start of the buffer*/

	message_start += snprintf(buffer, MAX_MODULE_NAME, "kernel: %s", from_module);
	
	va_start(arguments, format);
	vsnprintf(buffer + message_start, MAX_MESSAGE_SIZE - message_start, format, arguments);
	va_end(arguments);

	/*Prepare message header and send the buffer*/

	msg.msg_name = (struct sockaddr *) &log_file;
	msg.msg_namelen = sizeof(struct sockaddr_un);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_NOSIGNAL;

	iov.iov_base = (char *) buffer;
	iov.iov_len = (__kernel_size_t) strlen(buffer) + 1;

	oldfs = get_fs(); 
	set_fs(KERNEL_DS);

	sock_sendmsg(log_socket, &msg, (size_t) strlen(buffer) + 1);

	set_fs(oldfs);
	memset(buffer, '\0', sizeof(buffer));

	return LOG_OK;
}

void destroy_logger(void)
{
	if(log_socket != NULL)
	{
		sock_release(log_socket);
		log_socket = NULL;
	}
}

