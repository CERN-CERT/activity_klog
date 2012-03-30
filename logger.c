#include "logger.h"

#define MAX_MODULE_NAME 32

static struct socket *log_socket = NULL;
static char buffer[MAX_MESSAGE_SIZE] = {'\0'};
static char from_module[MAX_MODULE_NAME] = {'\0'};

int init_logger(const char *module_name)
{
	if(log_socket == NULL)
	{
		struct sockaddr_un sockaddr_un;
		
		if(sock_create(AF_UNIX, SOCK_STREAM, 0, &log_socket) < 0)
		{
			log_socket = NULL;
			return LOG_FAIL;
		}		

		memset((void *) &sockaddr_un, 0, sizeof(sockaddr_un));
		sockaddr_un.sun_family = AF_UNIX;
		strncpy(sockaddr_un.sun_path, LOG_PATH, strlen(LOG_PATH));
		
		if(log_socket->ops->connect(log_socket, (struct sockaddr *) &sockaddr_un, sizeof(sockaddr_un), 0) < 0)
		{
			log_socket = NULL;
			return LOG_FAIL;
		}
	}

	return LOG_OK;
}

int log(char *message)
{
	struct iovec iov;
	struct msghdr msg;
	mm_segment_t oldfs;
	struct rtc_time tm;
	struct timespec curtime;
	struct new_utsname *uts_name;
	unsigned int message_lenght, message_start;
	
	if(log_socket == NULL || message == NULL)
	{
		return LOG_FAIL;
	}
	
	message_start = 0;
	message_lenght = strlen(message) + 1;

	/*Format buffer (time, nodename and log facility's utilizing module name)*/

	/*Format time*/

	curtime = CURRENT_TIME;
	rtc_time_to_tm(curtime.tv_sec, &tm);
	message_start += snprintf(buffer, sizeof(buffer), "%d-%02d-%dT%d:%d:%d.%d+00:00 ",
			      1900 + tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour,
			      tm.tm_min, tm.tm_sec, (unsigned int) curtime.tv_nsec / 1000);

	/*Format node name*/
	
	message_start += snprintf(buffer + message_start, MAXHOSTNAMELEN, "%s", uts_name->nodename);
	message_start += snprintf(buffer + message_start, MAX_MODULE_NAME + 10, " kernel: %s ", from_module);

	strncpy(buffer + message_start, message, sizeof(buffer));
	
	/*Send buffer*/

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_NOSIGNAL;	

	iov.iov_base = (char*) buffer;
	iov.iov_len =  (__kernel_size_t) message_lenght;

	oldfs = get_fs(); set_fs(KERNEL_DS);

	sock_sendmsg(log_socket, &msg, (size_t) message_lenght);

	set_fs(oldfs);
	memset(buffer, '\0', sizeof(buffer));
	
	return LOG_OK;
}

//REVIEW shutdown or other call in order to release the socket?
void destroy_logger(void)
{
	if(log_socket != NULL)
	{
		log_socket->ops->shutdown(log_socket, SHUT_WR);
	}
}

