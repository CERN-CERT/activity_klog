#include "whitelist.h"
#include <linux/sched.h>
#include <net/ip.h>

int size = 0;
char white_list[MAX_WHITELIST_SIZE][MAX_ABSOLUTE_EXEC_PATH];

int whitelist(const char *process_name)
{
	if(size == MAX_WHITELIST_SIZE)
	{
		/*List is full, cannot whitelist more processes*/

		return LIST_FULL;
	}

	if(strnlen(process_name, MAX_ABSOLUTE_EXEC_PATH) == 0)
	{
		/*No reason to whitelist an empty process name...*/

		return NOT_WHITELISTED;
	}

	memset(white_list[size], '\0', MAX_ABSOLUTE_EXEC_PATH);
	strncpy(white_list[size], process_name, MAX_ABSOLUTE_EXEC_PATH);
	size++;

	return WHITELISTED;
}

int is_whitelisted(const struct task_struct *task)
{
	int i;
	char *temp, *pathname;
	
	if(task == NULL || task->mm == NULL || task->mm->exe_file == NULL)
	{
		return NOT_WHITELISTED;
	}

	/*Retrieve the absolute execution path of the process*/

	temp = (char *)__get_free_page(GFP_TEMPORARY);

	if (!temp) 
	{
	    return NOT_WHITELISTED;
	}

	pathname = d_path(&(task->mm->exe_file->f_path), temp, PAGE_SIZE);

	if (IS_ERR(pathname)) 
	{
    		free_page((unsigned long)temp);
    		return NOT_WHITELISTED;
	}

	/*Check if exists in the whitelist*/
	
	for(i = 0; i < size; ++i)
	{
		if(strncmp(white_list[i], pathname, MAX_ABSOLUTE_EXEC_PATH) == 0)
		{
			/*Process found in the whitelist*/
			
			free_page((unsigned long)temp);
			return WHITELISTED;
		}
	}

	free_page((unsigned long)temp);
	return NOT_WHITELISTED;
}
















