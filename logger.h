#ifndef __LOGGER__
#define __LOGGER__

#include <linux/socket.h>
#include <linux/un.h>
#include <linux/file.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/net.h>

#define LOG_FAILED(A) A < 0
#define MAX_MESSAGE_SIZE 512

#define LOG_OK 1
#define LOG_FAIL -1

#define LOG_PATH "/dev/log"

/*Initiliaze logger facility */

int init_logger(void);

/*Log a message*/

int log(char *message);

/*Destroy logger facility*/

void destroy_logger(void);

#endif
