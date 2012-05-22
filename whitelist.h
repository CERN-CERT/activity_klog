#ifndef __WHITELIST__
#define __WHITELIST__

#define WHITELIST_FAIL -1

#define WHITELISTED 1
#define NOT_WHITELISTED 0

/*The maximum lenght of the whitelisted paths. Any path
 *with lenght greater than this, cannot be whitelisted.
 */

#define MAX_ABSOLUTE_EXEC_PATH 1019

/*The number of maximum whitelisted processes*/

#define MAX_WHITELIST_SIZE 32

struct task_struct;

int whitelist(const char *process_name);

int is_whitelisted(const struct task_struct *task);

#endif

