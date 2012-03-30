#include "logger.h"

static struct socket *log_socket = NULL;
static char buffer[MAX_MESSAGE_SIZE] = {'\0'};

int init_logger(void)
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
	unsigned int message_lenght;
	
	if(log_socket == NULL || message == NULL)
	{
		return LOG_FAIL;
	}
	
	message_lenght = strlen(message) + 1;
	strncpy(buffer, message, sizeof(buffer));

	//TODO format buffer

	/*Prepare and send buffer*/

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

