#ifndef __WHITELIST__
#define __WHITELIST__

#define MAX_LIST_SIZE 20

#define LIST_FULL -1
#define WHITELISTED 1
#define NOT_WHITELISTED -1

int whitelist(char *process_name);

int is_whitelisted(char *process_name);

#endif
