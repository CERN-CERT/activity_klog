#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include "whitelist.h"
#include "connection.h"
#include "proc_config.h"

static unsigned long procfs_buffer_size = 0;
static char procfs_buffer[PROCFS_MAX_SIZE];
static struct proc_dir_entry *netlog_config_proc_file = NULL;

void add_connection_string_to_proc_config(char *connection_string)
{
	if(connection_string == NULL)
		return;
		
	procfs_buffer_size += snprintf(procfs_buffer + procfs_buffer_size, PROCFS_MAX_SIZE - procfs_buffer_size, 
											"%s\n", connection_string);
}

int procfile_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
	int ret;
	
	if (offset > 0) 
	{
		ret  = 0;
	}
	else 
	{
		memcpy(buffer, procfs_buffer, procfs_buffer_size);
		ret = procfs_buffer_size;
	}

	return ret;
}

int procfile_write(struct file *file, const char *buffer, unsigned long count, void *data)
{
	procfs_buffer_size = count;
	if(procfs_buffer_size > PROCFS_MAX_SIZE) 
	{
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}
	
	if(copy_from_user(procfs_buffer, buffer, procfs_buffer_size))
	{
		return -EFAULT;
	}
	
	return procfs_buffer_size;
}

int create_proc_config(void)
{
	netlog_config_proc_file = create_proc_entry(PROC_CONFIG_NAME, 0644, NULL);
	
	if(netlog_config_proc_file == NULL) 
	{
		remove_proc_entry(PROC_CONFIG_NAME, NULL);
		return -CREATE_PROC_FAILED;
	}

	netlog_config_proc_file->read_proc  = procfile_read;
	netlog_config_proc_file->write_proc = procfile_write;
	netlog_config_proc_file->mode = S_IFREG | S_IRUGO;
	netlog_config_proc_file->uid = 0;
	netlog_config_proc_file->gid = 0;
	
	return 0;
}

void destroy_proc_config(void)
{
	if(netlog_config_proc_file != NULL)
	{
		remove_proc_entry(PROC_CONFIG_NAME, NULL);	
		netlog_config_proc_file = NULL;
	}
}

