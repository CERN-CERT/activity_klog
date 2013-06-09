#include <linux/module.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
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

ssize_t procfile_read(struct file *fd, char __user *buffer, size_t buffer_length, loff_t *offset)
{
	int written;

	if(*offset >= procfs_buffer_size - 1)
	{
		return 0;
	}
	else
	{
		/* Trim the last comma, if exists */

		if(procfs_buffer[procfs_buffer_size - 1] == ',')
		{
			procfs_buffer_size--;
			procfs_buffer[procfs_buffer_size] = '\0';
		}

		written = snprintf(buffer, buffer_length, "%s", procfs_buffer + *offset);
		*offset += buffer_length - 1;
		return written;
	}
}

ssize_t procfile_write(struct file *fd, const char __user *buffer, size_t count, loff_t *offset)
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

static const struct file_operations netlog_proc_dir_operations = {
	.owner			= THIS_MODULE,
	.read			= procfile_read,
	.write			= procfile_write,
};

int create_proc_config(void)
{
	// TODO: use proc_create_data and store procfs_buffer inside
	netlog_config_proc_file = proc_create(PROC_CONFIG_NAME, S_IFREG | S_IRUSR | S_IWUSR, NULL, &netlog_proc_dir_operations);
	if(netlog_config_proc_file == NULL)
	{
		return -CREATE_PROC_FAILED;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
	netlog_config_proc_file->uid = 0;
	netlog_config_proc_file->gid = 0;
#else
	proc_set_user(netlog_config_proc_file, 0, 0);
#endif
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

