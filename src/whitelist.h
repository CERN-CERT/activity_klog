#ifndef __NETLOG_WHITELIST__
#define __NETLOG_WHITELIST__

#include <linux/sched.h>

#define WHITELIST_FAIL -1

#define WHITELISTED 1
#define NOT_WHITELISTED 0

/*The maximum lenght of the whitelisted paths. Any path
 *with lenght greater than this, cannot be whitelisted.
 */

#define MAX_ABSOLUTE_EXEC_PATH 950

/*The number of maximum whitelisted processes*/

#define MAX_WHITELIST_SIZE 150

int whitelist(const char *connection_string);

int is_whitelisted(const struct task_struct *task, const char *ip, const int port);

void destroy_whitelist(void);

char *exe_from_mm(struct mm_struct *mm, char *buf, int len);

#endif /* __NETLOG_WHITELIST__ */
