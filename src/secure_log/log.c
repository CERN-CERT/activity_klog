#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/version.h>
#include "log.h"
#include "sparse_compat.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Brillault <vincent.brillault@cern.ch>");
MODULE_DESCRIPTION("Create a new logging device, /dev/"MODULE_NAME);
MODULE_VERSION("0.2");

static int simple_format;
module_param(simple_format, int, 0664);
MODULE_PARM_DESC(simple_format, "Use a simpler out format than syslog RFC, only valid for new open call on the device");


/*
 * This kernel module is heavily inspired from linux/kernel/printk.c
 * Here is the original copyright notice on that file:
 ******
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 * Modified to make sys_syslog() more flexible: added commands to
 * return the last 4k of kernel messages, regardless of whether
 * they've been read or not.  Added option to suppress kernel printk's
 * to the console.  Added hook for sending the console messages
 * elsewhere, in preparation for a serial line console (someday).
 * Ted Ts'o, 2/11/93.
 * Modified for sysctl support, 1/8/97, Chris Horn.
 * Fixed SMP synchronization, 08/08/99, Manfred Spraul
 *     manfred@colorfullife.com
 * Rewrote bits to get rid of console_lock
 *      01Mar01 Andrew Morton
 ******
 */

/* Log structures of records stored the buffer */
struct sec_log {
	size_t len /** Total size of the record, including the strings at the end */;
	u64 nsec   /** Timestamp of the activity */;
	pid_t pid  /** PID responsible for the activity */;
	pid_t sid  /** SID of the PID responsible for the activity */;
	pid_t ppid /** PID of the parent of the PID responsible for the activity */;
	uid_t uid  /** UID responsible for the activity */;
	uid_t euid /** EUID responsible for the activity */;
	uid_t gid  /** GID responsible for the activity */;
	uid_t egid /** EGID responsible for the activity */;
	char tty[64] /** TTY, if existant, used by the program responsible for the activity, '\0' otherwise */;
	enum secure_log_type type /** Type of this record (for cast)*/;
};

struct netlog_log {
	struct sec_log header    /** Mandatory header */;
	size_t path_len          /** Length of the path of the executable responsible for the activity, including the tailing '\0'. The string is accessible via get_netlog_path */;
	enum secure_log_protocol protocol /** Network protocol used (currently supported: UDP & TCP */;
	enum secure_log_action action /** Type of call used (currently supported: bind, connect, accept, close */;
	unsigned short family    /** Familly of the socket used (currently supported: AF_INET, AF_INET6 */;
	int src_port             /** Source port (local) */;
	int dst_port             /** Destination port (distant) */;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
		u8 raw[16];
	} src                    /** Source address (local) */;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
		u8 raw[16];
	} dst                    /** Destination address (distant) */;
};

struct execlog_log {
	struct sec_log header /** Mandatory header */;
	size_t path_len       /** Length of the path of the executable, including the tailing '\0'. The string is accessible via get_netlog_path */;
	size_t argv_len       /** Length of the arguments given to the executable including the tailing '\0'. The string is accessible via get_netlog_argv. MUST be set after the 'path_len' */;
};

/* The bigger structure is definitely the netlog_log one */
#define LOG_ALIGN __alignof__(struct netlog_log)

/* Buffer */
static char log_buf[LOG_BUF_LEN];

/* index and sequence number of the first record stored in the buffer */
static u64 log_first_seq;
static u32 log_first_idx;

/* index and sequence number of the next record to store in the buffer */
static u64 log_next_seq;
static u32 log_next_idx;

/* Buffer protection */
static DEFINE_SPINLOCK(log_lock);

/* Poll queue */
static DECLARE_WAIT_QUEUE_HEAD(log_wait);

static char first_read = 1;

/* Device identifiers */
static struct device *dev;
static dev_t secure_dev;
static struct cdev secure_c_dev;
static struct class *secure_class;

/* Get the path of a log */
static char *
get_netlog_path(struct netlog_log *log)
__must_hold(log_lock)
{
	return ((char *)log) + sizeof(struct netlog_log);
}

static char *
get_execlog_path(struct execlog_log *log)
__must_hold(log_lock)
{
	return ((char *)log) + sizeof(struct execlog_log);
}

static char *
get_execlog_argv(struct execlog_log *log)
__must_hold(log_lock)
{
	return ((char *)log) + sizeof(struct execlog_log) + log->path_len;
}

static u32
next_record(u32 idx)
__must_hold(log_lock)
{
	size_t *len;

	len = &((struct sec_log *)(log_buf + idx))->len;
	if (*len == 0) {
		/* We need to wrap around */
		return 0;
	}
	return idx + *len;
}

/* Small tool */
static void
copy_ip(void *dst, const void *src, unsigned short family)
{
	switch (family) {
	case AF_INET:
		memcpy(dst, src, sizeof(struct in_addr));
		break;
	case AF_INET6:
		memcpy(dst, src, sizeof(struct in6_addr));
		break;
	default:
		break;
	}
}

static const char null_tty[] = "NULL tty";

static inline void
init_log_header(struct sec_log *record, enum secure_log_type type)
{
	record->nsec = local_clock();
	current_uid_gid(&record->uid, &record->gid);
	current_euid_egid(&record->euid, &record->egid);
	record->pid  = current->pid;
	if (likely(current->real_parent != NULL))
		record->ppid = current->real_parent->pid;
	else
		record->ppid = 0;
	record->sid  = task_session_vnr(current);
	tty_name(current->signal->tty, record->tty);
	if (memcmp(record->tty, null_tty, sizeof(null_tty) - 1) == 0)
		record->tty[4] = '\0';
	record->type = type;
}


static inline void
find_new_record_place(size_t size)
__must_hold(log_lock)
{
	size += (-size) & (LOG_ALIGN - 1);

	while (log_first_seq < log_next_seq) {
		size_t free;

		if (log_next_idx > log_first_idx)
			free = max(LOG_BUF_LEN - log_next_idx, log_first_idx);
		else
			free = log_first_idx - log_next_idx;

		if (free > size + sizeof(size_t))
			break;

		/* Drop old messages until we have enough contiuous space */
		log_first_idx = next_record(log_first_idx);
		log_first_seq++;
	}

	if (unlikely(log_next_idx + size + sizeof(size_t) >= LOG_BUF_LEN)) {
		/*
		 * As free > size + sizeof(size_t), this mean that we had
		 * free = max(log_buf_len - log_next_idx, log_first_idx)
		 * But as we are too close to the end, it means that the max
		 * is log_first_idx, thus we must wrap around.
		 * Add an empty size_t to indicate the wrap around
		 */
		*((size_t *)(log_buf + log_next_idx)) = 0;
		log_next_idx = 0;
	}
}


void
store_netlog_record(const char *path, enum secure_log_action action,
		    enum secure_log_protocol protocol, unsigned short family,
		    const void *src_ip, int src_port,
		    const void *dst_ip, int dst_port)
{
	struct netlog_log *record;
	size_t path_len, record_size;
	unsigned long flags;

	path_len = strlen(path) + 1;
	if (unlikely(path_len > (LOG_BUF_LEN >> 4) ||
		     path_len > INT_MAX)) {
		dev_warn(dev, "troncating path (size %zu > %i)\n",
			 path_len, min((LOG_BUF_LEN >> 4), INT_MAX));
		path_len = min((LOG_BUF_LEN >> 4), INT_MAX);
	}
	record_size = sizeof(struct netlog_log) + path_len;

	spin_lock_irqsave(&log_lock, flags);

	find_new_record_place(record_size);
	record = (struct netlog_log *)(log_buf + log_next_idx);
	/* Store basic information */
	init_log_header(&(record->header), LOG_NETWORK_INTERACTION);
	record->header.len = record_size;
	record->path_len = path_len;

	/* Store advanced information */
	record->action = action;
	record->protocol = protocol;
	record->family = family;
	if (src_ip == NULL)
		memset(record->src.raw, 0, 16);
	else
		copy_ip(record->src.raw, src_ip, family);
	if (dst_ip == NULL)
		memset(record->dst.raw, 0, 16);
	else
		copy_ip(record->dst.raw, dst_ip, family);
	record->src_port = src_port;
	record->dst_port = dst_port;
	memcpy(get_netlog_path(record), path, path_len);

	/* Update the next position */
	log_next_idx += record_size;
	log_next_seq++;

	spin_unlock_irqrestore(&log_lock, flags);

	/* Wake-up reading threads */
	wake_up_interruptible(&log_wait);
}
EXPORT_SYMBOL(store_netlog_record);


void
store_execlog_record(const char *path,
		     const char *argv, size_t argv_size)
{
	struct execlog_log *record;
	size_t path_len, record_size;
	unsigned long flags;

	path_len = strlen(path) + 1;
	if (unlikely(path_len > (LOG_BUF_LEN >> 5) ||
		     path_len > INT_MAX)) {
		dev_warn(dev, "Troncating path (size %zu > %i)\n",
			 path_len, min((LOG_BUF_LEN >> 5), INT_MAX));
		path_len = min((LOG_BUF_LEN >> 5), INT_MAX);
	}
	if (unlikely(argv_size > (LOG_BUF_LEN >> 5) ||
		     argv_size > INT_MAX)) {
		dev_warn(dev, "Troncating argv (size %zu > %i)\n",
			 argv_size, min((LOG_BUF_LEN >> 5), INT_MAX));
		argv_size = min((LOG_BUF_LEN >> 5), INT_MAX);
	}
	record_size = sizeof(struct execlog_log) + path_len + argv_size;

	spin_lock_irqsave(&log_lock, flags);

	find_new_record_place(record_size);
	record = (struct execlog_log *)(log_buf + log_next_idx);
	/* Store basic information */
	init_log_header(&(record->header), LOG_EXECUTION);
	record->header.len = record_size;

	/* Store advanced information */
	record->path_len = path_len;
	memcpy(get_execlog_path(record), path, path_len);
	record->argv_len = argv_size;
	memcpy(get_execlog_argv(record), argv, argv_size);

	/* Update the next position */
	log_next_idx += record_size;
	log_next_seq++;

	spin_unlock_irqrestore(&log_lock, flags);

	/* Wake-up reading threads */
	wake_up_interruptible(&log_wait);
}
EXPORT_SYMBOL(store_execlog_record);


struct user_data {
	u64 log_curr_seq;
	u32 log_curr_idx;
	u8  simple_format;
	struct mutex lock /** Lock when reading (only one read a at time) */;
	char buf[USER_BUFFER_SIZE];
};


static loff_t
secure_log_llseek(struct file *file, loff_t offset, int whence)
{
	struct user_data *data = file->private_data;
	unsigned long flags;

	if (unlikely(data == NULL))
		return -EBADF;

	/* Support rsyslog file reader: accept but ignore custom seeks */
	if (unlikely(offset != 0))
		return 0;

	/* Set the 'offset' to the desired value */
	spin_lock_irqsave(&log_lock, flags);
	switch (whence) {
	case SEEK_SET:
		data->log_curr_seq = log_first_seq;
		data->log_curr_idx = log_first_idx;
		break;
	case SEEK_CUR:
		break;
	case SEEK_END:
		data->log_curr_seq = log_next_seq;
		data->log_curr_idx = log_next_idx;
		break;
	default:
		spin_unlock_irqrestore(&log_lock, flags);
		return -EINVAL;
	}
	spin_unlock_irqrestore(&log_lock, flags);

	return 0;
}


static inline const char *
netlog_protocol(struct netlog_log *log)
__must_hold(log_lock)
{
	switch (log->protocol) {
	case PROTO_TCP:
		return "TCP";
	case PROTO_UDP:
		return "UDP";
	default:
		return "UNK";
	}
}

#define UPDATE_POINTERS(change, remaining, len) \
do {						\
	if (change >= remaining) {		\
		/* Output truncated */		\
		return -1;			\
	}					\
	len += change;				\
	remaining -= change;                    \
} while (0)


static ssize_t
netlog_print(struct netlog_log *record, char *data, size_t len)
__must_hold(log_lock)
{
	size_t remaining = USER_BUFFER_SIZE - len;
	int change;

	change = snprintf(data + len, remaining, "%.*s %s ",
			  (int)record->path_len, get_netlog_path(record),
			  netlog_protocol(record));
	UPDATE_POINTERS(change, remaining, len);
	switch (record->family) {
	case AF_INET:
		change = snprintf(data + len, remaining, "%pI4:%d",
				  &record->src.ip4, record->src_port);
		break;
	case AF_INET6:
		change = snprintf(data + len, remaining, "[%pI6c]:%d",
				  &record->src.ip6, record->src_port);
		break;
	default:
		change = snprintf(data + len, remaining, "Unknown");
		break;
	}
	UPDATE_POINTERS(change, remaining, len);
	switch (record->action) {
	case ACTION_CONNECT:
		change = snprintf(data + len, remaining, " -> ");
		break;
	case ACTION_ACCEPT:
		change = snprintf(data + len, remaining, " <- ");
		break;
	case ACTION_CLOSE:
		change = snprintf(data + len, remaining, " <!> ");
		break;
	case ACTION_BIND:
		change = snprintf(data + len, remaining, " BIND ");
		goto out;
	default:
		change = snprintf(data + len, remaining, " UNK ");
		goto out;
	}
	UPDATE_POINTERS(change, remaining, len);
	switch (record->family) {
	case AF_INET:
		change = snprintf(data + len, remaining, "%pI4:%d",
				&record->dst.ip4, record->dst_port);
		break;
	case AF_INET6:
		change = snprintf(data + len, remaining, "[%pI6c]:%d",
				&record->dst.ip6, record->dst_port);
		break;
	default:
		change = snprintf(data + len, remaining, "Unknown");
		break;
	}
out:
	UPDATE_POINTERS(change, remaining, len);
	return len;
}


static ssize_t
execlog_print(struct execlog_log *record, char *data, size_t len)
__must_hold(log_lock)
{
	size_t remaining = USER_BUFFER_SIZE - len;
	int change;

	change = snprintf(data + len, remaining, "%.*s %.*s",
			  (int) record->path_len, get_execlog_path(record),
			  (int) record->argv_len, get_execlog_argv(record));
	UPDATE_POINTERS(change, remaining, len);
	return len;
}

static inline char *
get_module_name(enum secure_log_type type)
{
	switch (type) {
	case LOG_NETWORK_INTERACTION:
		return "netlog";
	case LOG_EXECUTION:
		return "execlog";
	default:
		return "unknown";
	}
}

static inline size_t
secure_log_read_fill_record(char *buf, size_t len, struct sec_log *record)
__must_hold(log_lock)
{
	ssize_t ret;

	/* Fill the common header */
	len += sprintf(buf + len,
		       "p:%d s:%d pp:%d u/g:%d/%d eu/g:%d/%d t:%s ",
		       record->pid, record->sid, record->ppid,
		       record->uid, record->gid,
		       record->euid, record->egid,
		       record->tty);

	/* Print the content */
	switch (record->type) {
	case LOG_NETWORK_INTERACTION:
		ret = netlog_print((struct netlog_log *)record, buf, len);
		break;
	case LOG_EXECUTION:
		ret = execlog_print((struct execlog_log *)record, buf, len);
		break;
	default:
		ret = len + sprintf(buf + len, "Unknown entry");
	}
	if (ret < 0) {
		sprintf(buf + (USER_BUFFER_SIZE - 7), "TRUNC");
		len = USER_BUFFER_SIZE - 2;
	} else {
		len = ret;
	}
	len += sprintf(buf + len, "\n");

	return len;
}

static ssize_t
secure_log_read(struct file *file, char __user *buf, size_t count,
		loff_t *offset)
{
	struct user_data *data = file->private_data;
	struct sec_log *record;
	u64 ts;
	unsigned long rem_nsec;
	unsigned long flags;
	size_t len;
	ssize_t err, ret;

	if (unlikely(data == NULL))
		return -EBADF;

	/* Is the user already reading ? */
	err = mutex_lock_interruptible(&data->lock);
	if (err)
		return err;

	spin_lock_irqsave(&log_lock, flags);
	/* Wait until we have something to read */
	while (data->log_curr_seq == log_next_seq) {
		/* Too bad, this call cannot be non-blocking */
		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			spin_unlock_irqrestore(&log_lock, flags);
			goto out;
		}

		/* We need to wait, unlock */
		spin_unlock_irqrestore(&log_lock, flags);
		ret = wait_event_interruptible(log_wait,
				data->log_curr_seq != log_next_seq);
		if (ret)
			goto out;
		spin_lock_irqsave(&log_lock, flags);
	}

	/* Perhaps we waited for too long and some data is lost */
	if (unlikely(data->log_curr_seq < log_first_seq)) {
		/* Rest the position and alert the user */
		data->log_curr_seq = log_first_seq;
		data->log_curr_idx = log_first_idx;
		spin_unlock_irqrestore(&log_lock, flags);
		ret = -EPIPE;
		goto out;
	}

	/* Get the current record */
	record = (struct sec_log *)(log_buf + data->log_curr_idx);

	ts = record->nsec;
	rem_nsec = do_div(ts, 1000000000);
	if (data->simple_format == 0) {
		/* Fill the syslog header */
		len = sprintf(data->buf, "<%u>1 - - %s - - - [%5lu.%06lu]: ",
			      (LOG_FACILITY << 3) | LOG_LEVEL,
			      get_module_name(record->type),
			      (unsigned long)ts, rem_nsec / 1000);
	} else {
		/* Use a simpler header */
		len = sprintf(data->buf, "%s [%5lu.%06lu]: ",
			      get_module_name(record->type),
			      (unsigned long)ts, rem_nsec / 1000);
	}

	len = secure_log_read_fill_record(data->buf, len, record);

	/* Prepare for next iteration */
	data->log_curr_idx = next_record(data->log_curr_idx);
	++data->log_curr_seq;

	/* Unlock */
	spin_unlock_irqrestore(&log_lock, flags);

	/* The user buffer is too small, abort */
	if (unlikely(len > count)) {
		ret = -EINVAL;
		goto out;
	}

	/* Copy the data into userspace */
	if (unlikely(copy_to_user(buf, data->buf, len))) {
		/* Copy failed */
		ret = -EFAULT;
		goto out;
	}
	ret = len;
out:
	mutex_unlock(&data->lock);
	return ret;
}

static unsigned int
secure_log_poll(struct file *file, poll_table *wait)
{
	struct user_data *data = file->private_data;
	unsigned long flags;
	int ret = 0;

	if (unlikely(data == NULL))
		return POLLERR|POLLNVAL;

	/* Update the poll state */
	poll_wait(file, &log_wait, wait);

	/* Check if there is anything to read */
	spin_lock_irqsave(&log_lock, flags);
	if (data->log_curr_seq < log_next_seq) {
		/* Return error when data has vanished underneath us */
		if (data->log_curr_seq < log_first_seq)
			ret = POLLIN|POLLRDNORM|POLLERR|POLLPRI;
		else
			ret = POLLIN|POLLRDNORM;
	}
	spin_unlock_irqrestore(&log_lock, flags);

	return ret;
}

static int
secure_log_open(struct inode *inode, struct file *file)
{
	struct user_data *data;
	unsigned long flags;

	/* Allocate private data */
	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (unlikely(data == NULL))
		return -ENOMEM;

	/* Initialize read mutex */
	mutex_init(&data->lock);

	/* Set the format */
	kparam_block_sysfs_write(simple_format);
	data->simple_format = simple_format;
	kparam_unblock_sysfs_write(simple_format);

	/* Get current state */
	spin_lock_irqsave(&log_lock, flags);
	if (first_read) {
		data->log_curr_seq = log_first_seq;
		data->log_curr_idx = log_first_idx;
		first_read = 0;
	} else {
		data->log_curr_seq = log_next_seq;
		data->log_curr_idx = log_next_idx;
	}
	spin_unlock_irqrestore(&log_lock, flags);


	/* Store private data */
	file->private_data = data;

	return 0;
}

static int
secure_log_release(struct inode *inode, struct file *file)
{
	struct user_data *data = file->private_data;

	if (data == NULL)
		return 0;

	mutex_destroy(&data->lock);
	kfree(data);

	return 0;
}


static const struct file_operations secure_log_fops = {
	.owner = THIS_MODULE,
	.open = secure_log_open,
	.read = secure_log_read,
	.llseek = secure_log_llseek,
	.poll = secure_log_poll,
	.release = secure_log_release,
};


static int __init
init_secure_dev(void)
{
	int err;

	secure_class = class_create(THIS_MODULE, MODULE_NAME);
	if (IS_ERR(secure_class))
		return PTR_ERR(secure_class);

	err =  alloc_chrdev_region(&secure_dev, 0, 1, MODULE_NAME);
	if (err < 0)
		goto clean_class;

	cdev_init(&secure_c_dev, &secure_log_fops);
	err = cdev_add(&secure_c_dev, secure_dev, 1);
	if (err < 0)
		goto clean_chrdev_region;

	dev = device_create(secure_class, NULL, secure_dev, NULL, MODULE_NAME);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto clean_cdev;
	}

	dev_info(dev, "\t[+]Created /dev/"MODULE_NAME" for logs\n");
	return 0;

clean_cdev:
	cdev_del(&secure_c_dev);
clean_chrdev_region:
	unregister_chrdev_region(secure_dev, 1);
clean_class:
	class_destroy(secure_class);
	return err;
}

module_init(init_secure_dev);

static void __exit
destroy_secure_dev(void)
{
	dev_info(dev, "\t[+]Removing /dev/"MODULE_NAME"\n");
	device_destroy(secure_class, secure_dev);
	cdev_del(&secure_c_dev);
	unregister_chrdev_region(secure_dev, 1);
	class_destroy(secure_class);
	return;
}

module_exit(destroy_secure_dev);
