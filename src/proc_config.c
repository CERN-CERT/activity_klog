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

void add_connection_string_to_proc_config(const char *connection_string)
{
	if(connection_string == NULL)
	{
		return;
	}
		
	procfs_buffer_size += snprintf(procfs_buffer + procfs_buffer_size, PROCFS_MAX_SIZE - procfs_buffer_size, 
											"%s,", connection_string);
}

void initialize_procfs_buffer(void)
{
	memset(procfs_buffer, '\0', PROCFS_MAX_SIZE);
	procfs_buffer_size = 0;
}

void update_whitelist(void)
{
	int i, connection_string_length;
	static char temp_procfs_buffer[PROCFS_MAX_SIZE];
	char new_connection_string[MAX_NEW_CONNECTION_SIZE], *start;

	/* Copy the prc fs buffer into a temporary, because it will
	 * be updated from the void whitelist(struct connection *connection).
	 * 
	 * By this way, the buffer will be consistent with the whitelist, because
	 * some connections might not be in the right format.
	 */

	memcpy(temp_procfs_buffer, procfs_buffer, PROCFS_MAX_SIZE);
	initialize_procfs_buffer();

	destroy_whitelist();

	printk(KERN_INFO PROC_CONFIG_NAME ":\t[+] Cleared whitelist\n");	

	/* Whitelist one by one the connections that our buffer has */

	start = temp_procfs_buffer;
	connection_string_length = 0;

	for(i = 0; ; ++i)
	{
		/* Each connection is separated by a comma in the buffer,
		 * or by a \0 if there is no comma after the last connection string.
		 * Locate them and add them to the whitelist.
		 */

		if(temp_procfs_buffer[i] == ',' || temp_procfs_buffer[i] == '\0')
		{
			int err;

			connection_string_length++;
			memcpy(new_connection_string, start, connection_string_length);
			new_connection_string[connection_string_length - 1] = '\0';

			/* Whitelist the new connection */

			err = whitelist(new_connection_string);

			if(err < 0)
			{
				printk(KERN_ERR PROC_CONFIG_NAME ":\t[-] Failed to whitelist %s\n", new_connection_string);
			}
			else
			{
				printk(KERN_INFO PROC_CONFIG_NAME ":\t[+] Whitelisted %s\n", new_connection_string);
			}

			if(temp_procfs_buffer[i] == '\0')
			{
				/* End of parsing */

				break;
			}
			else
			{
				/* Skip separating character */

				start += connection_string_length;
				connection_string_length = 0;
			}
		}
		else
		{
			connection_string_length++;		
		}
	}

	memset(temp_procfs_buffer, '\0', PROCFS_MAX_SIZE);
}

int procfile_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
	int written;

	if(offset > 0)
	{
		written = 0;
	}
	else if(buffer_length < procfs_buffer_size)
	{
		printk(KERN_ERR PROC_CONFIG_NAME ": Not large enought buffer to copy the procfs buffer\n");
		written = 0;
	}
	else 
	{
		/* Trim the last comma, if exists */

		if(procfs_buffer[procfs_buffer_size - 1] == ',')
		{		
			procfs_buffer_size--;
			procfs_buffer[procfs_buffer_size] = '\0';
		}

		written = snprintf(buffer, buffer_length, "%s\n", procfs_buffer);
	}

	return written;
}

int procfile_write(struct file *file, const char *buffer, unsigned long count, void *data)
{
	procfs_buffer_size = count;

	if(procfs_buffer_size >= PROCFS_MAX_SIZE) 
	{
		printk(KERN_ERR PROC_CONFIG_NAME ": There is no enought space in the procfs buffer, changes will be ignored\n");

		return -ENOSPC;
	}

	if(copy_from_user(procfs_buffer, buffer, procfs_buffer_size))
	{
		return -EFAULT;
	}

	procfs_buffer[procfs_buffer_size - 1] = '\0';

	update_whitelist();

	return count;
}

int create_proc_config(void)
{
	netlog_config_proc_file = create_proc_entry(PROC_CONFIG_NAME, 0600, NULL);

	if(netlog_config_proc_file == NULL) 
	{
		remove_proc_entry(PROC_CONFIG_NAME, NULL);

		return -CREATE_PROC_FAILED;
	}

	netlog_config_proc_file->read_proc  = procfile_read;
	netlog_config_proc_file->write_proc = procfile_write;
	netlog_config_proc_file->mode = S_IFREG | S_IRUSR | S_IWUSR;
	netlog_config_proc_file->uid = 0;
	netlog_config_proc_file->gid = 0;

	initialize_procfs_buffer();
	
	return 0;
}

void destroy_proc_config(void)
{
	if(netlog_config_proc_file != NULL)
	{
		remove_proc_entry(PROC_CONFIG_NAME, NULL);	
		netlog_config_proc_file = NULL;
		
		initialize_procfs_buffer();
	}
}

