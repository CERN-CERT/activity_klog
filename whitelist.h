#ifndef __WHITELIST__
#define __WHITELIST__

/*This API must be not be used within critical section.
 *krpobes handlers are not in critical section. if you want
 *to use it within a critical section, you have to add the
 *semaphore handling for the path handling in is_whitelisted function.
 */

#define LIST_FULL 0
#define WHITELISTED 1
#define NOT_WHITELISTED 0

/*The maximum lenght of the whitelisted paths. Any path
 *with lenght greater than this, cannot be whitelisted.
 */

#define MAX_ABSOLUTE_EXEC_PATH 64

/*The number of maximum whitelisted processes*/

#define MAX_WHITELIST_SIZE 16

struct task_struct;

int whitelist(const char *process_name);

int is_whitelisted(const struct task_struct *task);

#endif
