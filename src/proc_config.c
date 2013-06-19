#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <asm/uaccess.h>
#include "whitelist.h"
#include "proc_config.h"
#include "netlog.h"

#define BUFFER_STEP 4096
#define BUFFER_MAX  4096000

struct user_data {
	char state;
	char *buf;
	size_t pos;
	size_t size;
};

#define STATE_READ 0
#define STATE_WRITE 1

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
  #define REMOVE_PROC(name, parent, pointer) remove_proc_entry(name, parent);
#else
  #define REMOVE_PROC(name, parent, pointer) proc_remove(pointer);
#endif

static struct proc_dir_entry *netlog_dir = NULL;
static struct proc_dir_entry *netlog_whitelist_file = NULL;

#ifdef WHITELISTING
ssize_t netlog_whitelist_write(struct file *file, const char __user *buf, size_t count, loff_t *offset)
{
	struct user_data* data = file->private_data;
	size_t current_size;
	char *current_buf;

	if (unlikely(data == NULL) ||
	    unlikely(data->buf == NULL))
		return -EBADF;

	current_size = data->size;
	while (count > data->size - data->pos - 1) {
		data->size += 4096;
	}
	if (current_size != data->size) {
		if (data->size > BUFFER_MAX)
			return -ENOMEM;
		current_buf = data->buf;
		data->buf = krealloc(data->buf, data->size, GFP_KERNEL);
		if (data->buf == NULL) {
			data->buf = current_buf;
			data->size = current_size;
			return -ENOMEM;
		}
	}

	if (unlikely(copy_from_user(data->buf, buf, count)))
		return -EFAULT;
	data->pos += count;
	return count;
}

static ssize_t netlog_whitelist_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
	struct user_data* data = file->private_data;
	size_t to_be_copied;

	if (unlikely(data == NULL) ||
	    unlikely(data->buf == NULL))
		return -EBADF;

	if (data->pos >= data->size)
		return 0;

	to_be_copied = min(count, data->size - data->pos);
	if (unlikely(copy_to_user(buf, data->buf, to_be_copied)))
		return -EFAULT;
	data->pos += to_be_copied;
	return to_be_copied;
}


static int netlog_whitelist_open(struct inode *inode, struct file *file)
{
	struct user_data *data;
	int err = 0;

	data = kmalloc(sizeof(struct user_data), GFP_KERNEL);
	if (unlikely(data == NULL))
		return -ENOMEM;
	data->buf = kmalloc(BUFFER_STEP ,GFP_KERNEL);
	if (unlikely(data->buf == NULL)) {
		kfree(data);
		return -ENOMEM;
	}
	data->size = BUFFER_STEP;
	data->pos = 0;

	switch(file->f_flags & O_ACCMODE) {
		case O_RDONLY:
			data->state = STATE_READ;
			data->size = dump_whitelist(&data->buf, BUFFER_STEP);
			break;
		case O_WRONLY:
			data->state = STATE_WRITE;
			break;
		default:
			err = -EINVAL;
			break;
	}
	file->private_data = data;
	if (err != 0) {
		kfree(data->buf);
		kfree(data);
	}
	return err;
}


static int netlog_whitelist_release(struct inode *inode, struct file *file)
{
        struct user_data *data = file->private_data;
	int ret = 0;

	if (unlikely(data == NULL) || unlikely(data->buf == NULL))
		return 0;

	switch(data->state) {
		case STATE_READ:
			break;
		case STATE_WRITE:
			data->buf[data->pos] = '\0';
			destroy_whitelist();
			set_whitelist_from_string(data->buf);
			break;
	}
	kfree(data);
	return ret;
}

const struct file_operations netlog_whitelist_ops = {
	.owner = THIS_MODULE,
	.open = netlog_whitelist_open,
	.read  = netlog_whitelist_read,
	.write = netlog_whitelist_write,
	.release = netlog_whitelist_release,
};
#endif /* WHITELISTING */

int create_proc(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 20, 0)
	netlog_dir = proc_mkdir(PROC_DIR_NAME, NULL);
#else
	netlog_dir = proc_mkdir_mode(PROC_DIR_NAME, S_IFDIR | S_IRUSR | S_IXUSR, NULL);
#endif
	if(netlog_dir == NULL)
		return -ENOMEM;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 20, 0)
	netlog_dir->mode = S_IFDIR | S_IRUSR | S_IXUSR;
#endif

#if WHITELISTING
	netlog_whitelist_file = proc_create(PROC_WHITELIST_NAME, S_IFREG | S_IRUSR | S_IWUSR, netlog_dir, &netlog_whitelist_ops);
	if(netlog_whitelist_file == NULL)
		goto clean;
  #if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
	netlog_whitelist_file->uid = 0;
	netlog_whitelist_file->gid = 0;
  #else
	proc_set_user(netlog_whitelist_file, 0, 0);
  #endif
#endif /* WHITELISTING */

	return 0;
clean:
	destroy_proc();
	return -ENOMEM;
}

void destroy_proc(void)
{
	if(netlog_dir != NULL) {
#if WHITELISTING
		if(netlog_whitelist_file != NULL)
			REMOVE_PROC(PROC_WHITELIST_NAME, netlog_dir, netlog_whitelist_file)
#endif /* WHITELISTING */
		REMOVE_PROC(PROC_DIR_NAME, NULL, netlog_dir)
	}
}

