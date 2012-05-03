#ifndef __LOGGER__
#define __LOGGER__

/* API of logging facility. 
 *
 * Use instead of printk when ou want to log sensitive data.
 */

#define MAX_MESSAGE_SIZE 150

#define LOG_OK 1
#define LOG_FAIL -1

#define LOG_PATH "/dev/log"

/*Initiliaze logger facility */

int init_logger(const char *module_name);

/*Log a message*/

int log_message(const char *format, ...);

/*Destroy logger facility*/

void destroy_logger(void);

#endif
