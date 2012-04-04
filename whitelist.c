#include "whitelist.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
#define call_d_path(file, buffer, length) d_path(file->f_dentry, file->f_vfsmnt, buffer, length);
#else
#define call_d_path(file, buffer, length) d_path(&file->f_path, buffer, length);
#endif

int size = 0;
char white_list[MAX_WHITELIST_SIZE][MAX_ABSOLUTE_EXEC_PATH];

int whitelist(const char *process_name)
{
	unsigned int name_length;

	if(size == MAX_WHITELIST_SIZE)
	{
		/*List is full, cannot whitelist more processes*/

		return WHITELIST_FAIL;
	}

	name_length = strnlen(process_name, MAX_ABSOLUTE_EXEC_PATH);

	if(name_length == 0 || name_length == MAX_ABSOLUTE_EXEC_PATH)
	{
		/*Fail to whitelist empty input or input greater than our limit*/

		return WHITELIST_FAIL;
	}

	memset(white_list[size], '\0', MAX_ABSOLUTE_EXEC_PATH);
	strncpy(white_list[size], process_name, MAX_ABSOLUTE_EXEC_PATH);
	++size;

	return WHITELISTED;
}

char *exe_from_mm(const struct mm_struct *mm, char *buf, int len);

int is_whitelisted(const struct task_struct *task)
{
	int i;
	unsigned int path_length;
	char *path, buffer[MAX_ABSOLUTE_EXEC_PATH] = {'\0'};

	if(task == NULL || task->mm == NULL)
	{
		return WHITELIST_FAIL;
	}

	/*Retrieve the absolute execution path of the process*/

	path = exe_from_mm(task->mm, buffer, MAX_ABSOLUTE_EXEC_PATH);

	if(path == NULL)
	{
		return NOT_WHITELISTED;
	}

	path_length = strnlen(path, MAX_ABSOLUTE_EXEC_PATH);

	if(path_length == 0 || path_length == MAX_ABSOLUTE_EXEC_PATH)
	{
		/*Empty or paths greater than our limit are not whitelisted*/

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

char *exe_from_mm(const struct mm_struct *mm, char *buffer, int length)
{
	char *p = NULL;
	struct vm_area_struct *vma;

	if(mm == NULL)
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

	if (vma && vma->vm_file)
	{
		p = call_d_path(vma->vm_file, buffer, length);
		
		if(IS_ERR(p))
		{
			return NULL;
		}
	}

	return p;
}

