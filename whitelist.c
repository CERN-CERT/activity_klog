#include "whitelist.h"
#include <linux/sched.h>
#include <net/ip.h>
#include <linux/mm.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
#define call_d_path(file, buf, len) d_path(file->f_dentry, file->f_vfsmnt, buf, len);
#else
#define call_d_path(file, buf, len) d_path(&file->f_path, buf, len);
#endif

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

char *exe_from_mm(const struct mm_struct *mm, char *buf, int len);

int is_whitelisted(const struct task_struct *task)
{
	int i;
	char *path, buffer[MAX_ABSOLUTE_EXEC_PATH];

	if(task == NULL || task->mm == NULL)
	{
		return NOT_WHITELISTED;
	}

	/*Retrieve the absolute execution path of the process*/

	path = exe_from_mm(task->mm, buffer, MAX_ABSOLUTE_EXEC_PATH);

	if(path == NULL)
	{
		return NOT_WHITELISTED;
	}

	/*Check if exists in the whitelist*/
	
	for(i = 0; i < size; ++i)
	{
		if(strncmp(white_list[i], path, MAX_ABSOLUTE_EXEC_PATH) == 0)
		{
			/*Process found in the whitelist*/
			
			return WHITELISTED;
		}
	}

	return NOT_WHITELISTED;
}

char *exe_from_mm(const struct mm_struct *mm, char *buf, int len)
{
	struct vm_area_struct *vma;
	char *p = NULL;

	vma = mm->mmap;

	while (vma)
	{
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
			break;
		vma = vma->vm_next;
	}

	if (vma && vma->vm_file)
	{
		p = call_d_path(vma->vm_file, buf, len);
	}

	return p;
}













