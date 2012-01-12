#ifndef __WHITELIST__
#define __WHITELIST__

#define MAX_LIST_SIZE 16

#define LIST_FULL 0
#define WHITELISTED 1
#define NOT_WHITELISTED 0

int whitelist(const char *process_name);

int is_whitelisted(const char *process_name);

#endif
