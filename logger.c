#include "logger.h"

#define NONE -1
#define MAX_BUFFER_SIZE 1024

static int logfd = NONE;
static char buffer[MAX_MESSAGE_LENGHT] = {'\0'};

int init_logger()
{
	if(logfd < 0)
	{
		int return_value;
		struct sockaddr_un sockaddr_unix;
		
		logfd = socket(AF_UNIX, SOCK_STREAM, 0);
		
		if(logfd < 0)
		{
			return LOG_FAIL;
		}
		
		memset(sockaddr_unix, 0, sizeof(sockaddr_unix));
		sockaddr_unix.sun_family = AF_UNIX;
		strncpy(sockaddr_unix.sun_path, LOG_PATH, strlen(LOG_PATH));
		
		return_value = connect(logfd, (struct sockaddr *) &sockaddr_unix, SUN_LEN(&sockaddr_unix));
		
		if(return_value < 0)
		{
			logfd = NONE;
			return LOG_FAIL;
		}
		
		
	}
}

int log(char *message)
{
	if(logfd < 0 || message == NULL)
	{
		return LOG_FAIL;
	}
	
	strncpy(buffer, message, sizeof(buffer));
	
	//TODO Format buffer to syslog format 

	send(logfd, buffer, strlen(buffer));
	memset(buffer, '\0', sizeof(buffer));
}

void destroy_logger()
{
	if(logfd >= 0)
	{
		close(sockfd);
	}
}

