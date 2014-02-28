#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include "whitelist.h"
#include "proc_config.h"
#include "probes.h"
#include "netlog.h"
#include "internal.h"

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
  #define MKDIR_PROC_MODE(name, parent, pointer, _mode)	\
do {							\
	pointer = proc_mkdir(name, parent);		\
	if (pointer != NULL)				\
		pointer->mode = _mode;			\
} while (0)
  #define REMOVE_PROC(name, parent, pointer) remove_proc_entry(name, parent);
#else
  #define MKDIR_PROC_MODE(name, parent, pointer, mode)	\
	pointer = proc_mkdir_mode(name, mode, parent);
  #define REMOVE_PROC(name, parent, pointer) proc_remove(pointer);
#endif

static struct proc_dir_entry *netlog_dir;
static struct proc_dir_entry *netlog_whitelist_file;
static struct proc_dir_entry *netlog_probes_dir;
static struct proc_dir_entry *netlog_probes[PROBES_NUMBER];

static struct probe_proc {
	const char *name;
	u32 mask;
} probe_list[] = {
	{ "tcp_connect", 1 << PROBE_TCP_CONNECT },
	{ "tcp_accept",  1 << PROBE_TCP_ACCEPT},
	{ "tcp_close",   1 << PROBE_TCP_CLOSE},
	{ "udp_connect", 1 << PROBE_UDP_CONNECT},
	{ "udp_bind",    1 << PROBE_UDP_BIND},
	{ "udp_close",   1 << PROBE_UDP_CLOSE},
};


/*****************/
/*   Whitelist   */
/*****************/

#ifdef WHITELISTING
static ssize_t netlog_whitelist_write(struct file *file, const char __user *buf, size_t count, loff_t *offset)
{
	struct user_data *data = file->private_data;
	size_t new_size;
	char *new_buf;

	if (unlikely(data == NULL) ||
	    unlikely(data->buf == NULL) ||
	    unlikely(data->state != STATE_WRITE))
		return -EBADF;

	new_size = data->size;
	while (new_size < count + data->pos + 1) {
		if (new_size > BUFFER_MAX - 4096)
			return -ENOMEM;
		new_size += 4096;
	}
	if (new_size != data->size) {
		if (new_size > BUFFER_MAX)
			return -ENOMEM;
		new_buf = krealloc(data->buf, new_size, GFP_KERNEL);
		if (new_buf == NULL)
			return -ENOMEM;
		data->buf = new_buf;
		data->size = new_size;
	}

	if (unlikely(copy_from_user(data->buf, buf, count)))
		return -EFAULT;
	data->pos += count;
	return count;
}

static ssize_t netlog_whitelist_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
	struct user_data *data = file->private_data;
	ssize_t ret;

	if (unlikely(data == NULL) ||
	    unlikely(data->buf == NULL) ||
	    unlikely(data->state != STATE_READ))
		return -EBADF;

	file->private_data = data->buf;
	ret = seq_read(file, buf, count, offset);
	file->private_data = data;
	return ret;
}

static loff_t netlog_whitelist_lseek(struct file *file, loff_t offset, int origin)
{
	struct user_data *data = file->private_data;
	loff_t ret;

	if (unlikely(data == NULL) ||
	    unlikely(data->buf == NULL) ||
	    unlikely(data->state != STATE_READ))
		return -EBADF;

	file->private_data = data->buf;
	ret = seq_lseek(file, offset, origin);
	file->private_data = data;
	return ret;
}

static int netlog_whitelist_open(struct inode *inode, struct file *file)
{
	struct user_data *data;
	int err = 0;

	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (unlikely(data == NULL))
		return -ENOMEM;
	data->pos = 0;

	switch (file->f_flags & O_ACCMODE) {
	case O_RDONLY:
		data->state = STATE_READ;
		err = seq_open(file, &whitelist_file);
		data->buf = file->private_data;
		data->size = 0;
		break;
	case O_WRONLY:
		data->state = STATE_WRITE;
		data->buf = kmalloc(BUFFER_STEP, GFP_KERNEL);
		if (unlikely(data->buf == NULL)) {
			kfree(data);
			return -ENOMEM;
		}
		data->size = BUFFER_STEP;
		break;
	default:
		err = -EINVAL;
		break;
	}
	file->private_data = data;
	if (err != 0)
		kfree(data);
	return err;
}

static int netlog_whitelist_release(struct inode *inode, struct file *file)
{
	struct user_data *data = file->private_data;
	int ret = 0;

	if (unlikely(data == NULL) ||
	    unlikely(data->buf == NULL))
		return 0;

	switch (data->state) {
	case STATE_READ:
		file->private_data = data->buf;
		seq_release(inode, file);
		break;
	case STATE_WRITE:
		data->buf[data->pos] = '\0';
		set_whitelist_from_string(data->buf);
		kfree(data->buf);
		break;
	}
	kfree(data);
	return ret;
}

static const struct file_operations netlog_whitelist_ops = {
	.owner = THIS_MODULE,
	.open = netlog_whitelist_open,
	.read  = netlog_whitelist_read,
	.llseek = netlog_whitelist_lseek,
	.write = netlog_whitelist_write,
	.release = netlog_whitelist_release,
};
#endif /* WHITELISTING */

/*****************/
/*     Probes    */
/*****************/

static ssize_t netlog_probe_write(struct file *file, const char __user *buf, size_t count, loff_t *offset)
{
	const struct probe_proc *data = file->private_data;
	char buffer[2];

	if (unlikely(data == NULL))
		return -EBADF;

	if (count > 2 || *offset > 0)
		return -EBADE;

	if (unlikely(copy_from_user(buffer,  buf, count)))
		return -EFAULT;

	if (count == 2 &&
	    buffer[1] != '\n')
		return -EBADE;

	switch (buffer[0]) {
	case '0':
		unplant_probe(data->mask);
		break;
	case '1':
		plant_probe(data->mask);
		break;
	default:
		return -EBADE;
	}

	(*offset) += count;
	return count;
}

static ssize_t netlog_probe_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
	const struct probe_proc *data = file->private_data;
	char buffer[3];

	if (unlikely(data == NULL))
		return -EBADF;

	if (*offset == 2)
		return 0;

	if (count < 2 || *offset > 0)
		return -EBADE;

	if (snprintf(buffer, 3, "%i\n", probe_status(data->mask)) != 2)
		return -EFAULT;

	if (unlikely(copy_to_user(buf, buffer, 2)))
		return -EFAULT;

	(*offset) += 2;
	return 2;
}

static int netlog_probe_open(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
	file->private_data = PDE(inode)->data;
#else
	file->private_data = PDE_DATA(inode);
#endif
	return 0;
}

static int netlog_probe_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations netlog_probe_ops = {
	.owner = THIS_MODULE,
	.open = netlog_probe_open,
	.read  = netlog_probe_read,
	.write = netlog_probe_write,
	.release = netlog_probe_release,
};


/********************/
/*    Main fun      */
/********************/

int create_proc(void)
{
	int i;

	MKDIR_PROC_MODE(PROC_DIR_NAME, NULL, netlog_dir, S_IFDIR | S_IRUSR | S_IXUSR);
	if (netlog_dir == NULL) {
		pr_err("\t[-] Unable to create /proc/"PROC_DIR_NAME"/\n");
		return -ENOMEM;
	}

	for (i = 0; i < PROBES_NUMBER; ++i)
		netlog_probes[i] = NULL;

	MKDIR_PROC_MODE(PROC_PROBES_NAME, netlog_dir, netlog_probes_dir, S_IFDIR | S_IRUSR | S_IXUSR);
	if (netlog_probes_dir == NULL) {
		pr_err("\t[-] Unable to create /proc/"PROC_DIR_NAME"/"PROC_PROBES_NAME"/\n");
		goto clean;
	}

	for (i = 0; i < PROBES_NUMBER; ++i) {
		netlog_probes[i] = proc_create_data(probe_list[i].name,  S_IFREG | S_IRUSR | S_IWUSR, netlog_probes_dir, &netlog_probe_ops, (void *)&probe_list[i]);
		if (netlog_probes[i] == NULL) {
			pr_err("\t[-] Unable to create /proc/"PROC_DIR_NAME"/"PROC_PROBES_NAME"/%s\n", probe_list[i].name);
			goto clean;
		}
	}

#if WHITELISTING
	netlog_whitelist_file = proc_create(PROC_WHITELIST_NAME, S_IFREG | S_IRUSR | S_IWUSR, netlog_dir, &netlog_whitelist_ops);
	if (netlog_whitelist_file == NULL) {
		pr_err("\t[-] Unable to create /proc/"PROC_DIR_NAME"/"PROC_WHITELIST_NAME"\n");
		goto clean;
	}
  #if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
	netlog_whitelist_file->uid = 0;
	netlog_whitelist_file->gid = 0;
  #else
	proc_set_user(netlog_whitelist_file, KUIDT_INIT(0), KGIDT_INIT(0));
  #endif
#endif /* WHITELISTING */

	pr_info("\t[+] Created /proc/"PROC_DIR_NAME"/ for control\n");
	return 0;
clean:
	destroy_proc();
	return -ENOMEM;
}

void destroy_proc(void)
{
	int i;

	if (netlog_dir != NULL) {
		pr_info("\t[+] Destroying /proc/"PROC_DIR_NAME"/\n");
		for (i = 0; i < PROBES_NUMBER; ++i)
			if (netlog_probes[i] != NULL)
				REMOVE_PROC(probe_list[i].name, netlog_probes_dir, netlog_probes[i])
		if (netlog_probes_dir != NULL)
			REMOVE_PROC(PROC_PROBES_NAME, netlog_dir, netlog_probes_dir)
#if WHITELISTING
		if (netlog_whitelist_file != NULL)
			REMOVE_PROC(PROC_WHITELIST_NAME, netlog_dir, netlog_whitelist_file)
#endif /* WHITELISTING */
		REMOVE_PROC(PROC_DIR_NAME, NULL, netlog_dir)
	}
}
