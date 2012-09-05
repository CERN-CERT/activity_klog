#include <linux/sched.h>
#include <net/ip.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/err.h>
#include <linux/spinlock.h>
#include "whitelist.h"
#include "connection.h"
#include "proc_config.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
	#define call_d_path(file, buffer, length) d_path(file->f_dentry, file->f_vfsmnt, buffer, length);
#else
	#define call_d_path(file, buffer, length) d_path(&file->f_path, buffer, length);
#endif

int size = 0;
struct connection *white_list[MAX_WHITELIST_SIZE];

unsigned long flags;
DEFINE_SPINLOCK(access_whitelist_spinlock);

int whitelist(const char *connection_string)
{
	int i;
	struct connection *connection_to_whitelist;

	spin_lock_irqsave(&access_whitelist_spinlock, flags);

	if(size == MAX_WHITELIST_SIZE)
	{
		/*List is full, cannot whitelist more processes*/

		goto out_fail;
	}

	connection_to_whitelist = initialize_connection_from_string(connection_string);
	
	if(connection_to_whitelist == NULL)
	{
		goto out_fail;
	}

	/*Check if it's already whitelisted*/
	
	for(i = 0; i < size; ++i)
	{
		if(connections_are_equal(connection_to_whitelist, white_list[i]))
		{
			/*Already whitelisted*/
			
			goto out_fail;
		}
	}

	white_list[size] = connection_to_whitelist;	
	++size;

	/* Update the proc configuration buffer */

	add_connection_string_to_proc_config(connection_string);

	spin_unlock_irqrestore(&access_whitelist_spinlock, flags);

	return WHITELISTED;
out_fail:
	spin_unlock_irqrestore(&access_whitelist_spinlock, flags);

	return WHITELIST_FAIL;
}

int is_whitelisted(const struct task_struct *task, const char *ip, const int port)
{
	int i;
	unsigned int path_length;
	char *path, buffer[MAX_ABSOLUTE_EXEC_PATH + 1] = {'\0'};

	if(unlikely(task == NULL) || unlikely(task->mm == NULL))
	{
		goto not_whitelisted;
	}

	/*Retrieve the absolute execution path of the process*/

	path = exe_from_mm(task->mm, buffer, MAX_ABSOLUTE_EXEC_PATH);

	if(unlikely(path == NULL))
	{
		goto not_whitelisted;
	}

	path_length = strnlen(path, MAX_ABSOLUTE_EXEC_PATH);

	if(unlikely(path_length == 0) || unlikely(path_length == MAX_ABSOLUTE_EXEC_PATH))
	{
		/*Empty or paths greater than our limit are not whitelisted*/

		goto not_whitelisted;
	}

	/*Check if the execution path and the ip and port are whitelisted*/

	spin_lock_irqsave(&access_whitelist_spinlock, flags);
	
	for(i = 0; i < size; ++i)
	{
		if(connection_matches_attributes(white_list[i], path, ip, port))
		{
			/*Connection found in the whitelist*/
			
			goto whitelisted;
		}
	}

	spin_unlock_irqrestore(&access_whitelist_spinlock, flags);

not_whitelisted:
	return NOT_WHITELISTED;
whitelisted:
	spin_unlock_irqrestore(&access_whitelist_spinlock, flags);

	return WHITELISTED;
}

void destroy_whitelist(void)
{
	int i;
	
	spin_lock_irqsave(&access_whitelist_spinlock, flags);
	
	for(i = 0; i < size; ++i)
	{
		destroy_connection(white_list[i]);
	}
	
	size = 0;
	
	spin_unlock_irqrestore(&access_whitelist_spinlock, flags);
}

char *exe_from_mm(const struct mm_struct *mm, char *buffer, int length)
{
	char *p = NULL;
	struct vm_area_struct *vma;

	if(unlikely(mm == NULL))
	{
		return NULL;
	}

	vma = mm->mmap;

	while(vma)
	{
		if((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
		{
			break;
		}
			
		vma = vma->vm_next;
	}

	if(vma && vma->vm_file)
	{
		p = call_d_path(vma->vm_file, buffer, length);
		
		if(IS_ERR(p))
		{
			p = NULL;
		}
	}

	return p;
}

