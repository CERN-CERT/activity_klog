#include "logger.h"

#define NONE -1
#define BUFFER_SIZE 1024

static struct socket *log_socket = NULL;
static char buffer[BUFFER_SIZE] = {'\0'};

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
	if(log_socket == NULL || message == NULL)
	{
		return LOG_FAIL;
	}
	
	strncpy(buffer, message, sizeof(buffer));

	//TODO format buffer and send the message

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

