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
		REMOVE_PROC(PROC_DIR_NAME, NULL, netlog_dir)
	}
}
