#include "whitelist.h"
#include <linux/sched.h>

int size = 0;
char white_list[MAX_LIST_SIZE][TASK_COMM_LEN];

int whitelist(const char *process_name)
{
	if(size == MAX_LIST_SIZE)
	{
		/*List is full, cannot whitelist more processes*/

		return LIST_FULL;
	}

	if(strnlen(process_name, TASK_COMM_LEN) == 0)
	{
		/*No reason to whitelist an ampty process name...*/

		return NOT_WHITELISTED;
	}

	strncpy(white_list[size], process_name, TASK_COMM_LEN);
	size++;

	return WHITELISTED;
}

int is_whitelisted(const char *process_name)
{
	int i;

	for(i = 0; i < size; i++)
	{
		if(!strncmp(white_list[i], process_name, TASK_COMM_LEN))
		{
			/*Process found in the whitelist*/

			return WHITELISTED;
		}
	}

	return NOT_WHITELISTED;
}
