#ifndef __LOGGER__
#define __LOGGER__

#define LOG_FAIL(A) A < 0

#define LOG_OK 1
#define LOG_FAIL -1

#define LOG_PATH "/dev/log"

/*Initiliaze logger facility */

int init_logger();

/*Log a message*/

int log(char *message);

/*Destroy logger facility*/

void destroy_logger();

#endif
