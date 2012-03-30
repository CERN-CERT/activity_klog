#include "logger.h"

#define MAX_MODULE_NAME 32

struct socket *log_socket = NULL;
char buffer[MAX_MESSAGE_SIZE] = {'\0'};
char from_module[MAX_MODULE_NAME] = {'\0'};

int init_logger(const char *module_name)
{
	if(log_socket == NULL)
	{
		struct sockaddr_un log_file;
		
		if(sock_create_kern(PF_UNIX, SOCK_DGRAM, 0, &log_socket) < 0)
		{
			log_socket = NULL;
			return LOG_FAIL;
		}		

		memset((void *) &log_file, 0, sizeof(log_file));
		log_file.sun_family = PF_UNIX;
		strncpy(log_file.sun_path, LOG_PATH, UNIX_PATH_MAX);

		if(log_socket->ops->connect(log_socket, (struct sockaddr *) &log_file, sizeof(struct sockaddr_un) - 1, 0) < 0)
		{
			log_socket = NULL;
			return LOG_FAIL;
		}
		
		strncpy(from_module, module_name, MAX_MODULE_NAME);
	}
	
	return LOG_OK;
}

int log(const char *message)
{
	struct iovec iov;
	struct msghdr msg;
	mm_segment_t oldfs;
	struct rtc_time tm;
	struct timespec curtime;
	struct new_utsname *uts_name;
	unsigned int message_start;
	
	if(log_socket == NULL || message == NULL)
	{
		return LOG_FAIL;
	}
	
	message_start = 0;

	/*Format buffer (time, node name and log facility's utilizing module name)*/

	/*Format time*/
	curtime = CURRENT_TIME;
	rtc_time_to_tm(curtime.tv_sec, &tm);

	message_start += snprintf(buffer, sizeof(buffer), "%d-%02d-%dT%d:%d:%d.%d+00:00 ",
			      1900 + tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour,
			      tm.tm_min, tm.tm_sec, (unsigned int) curtime.tv_nsec / 1000);

	/*Format node name*/
	
	uts_name = utsname();
	
	message_start += snprintf(buffer + message_start, MAXHOSTNAMELEN, "%s", uts_name->nodename);
	message_start += snprintf(buffer + message_start, MAX_MODULE_NAME + 10, " kernel: %s", from_module);


	snprintf(buffer + message_start, strlen(message) + 1, "%s", message);

	/*Send buffer*/

	msg.msg_name = 0;
	msg.msg_namelen = 0;
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

//REVIEW shutdown or other call in order to release the socket?
void destroy_logger(void)
{
	if(log_socket != NULL)
	{
		log_socket->ops->shutdown(log_socket, SHUT_WR);
	}
}

