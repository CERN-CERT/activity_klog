#ifndef __WHITELIST__
#define __WHITELIST__

#define WHITELIST_FAIL -1

#define WHITELISTED 1
#define NOT_WHITELISTED 0

/*The maximum lenght of the whitelisted paths. Any path
 *with lenght greater than this, cannot be whitelisted.
 */

#define MAX_ABSOLUTE_EXEC_PATH 1000

/*The number of maximum whitelisted processes*/

#define MAX_WHITELIST_SIZE 128

struct task_struct;

int whitelist(const char *connection_string);

int is_whitelisted(const struct task_struct *task, const char *ip, const int port);

void destroy_whitelist(void);

#endif

