#include <linux/fs.h>
#include <linux/ipv6.h>
#include "inet_utils.h"
#include "netlog.h"

/* Log structure of records stored the buffer */
struct netlog_log {
	size_t len;
	size_t path_len;
	u64 nsec;
	pid_t pid;
	uid_t uid;
	u8 action;
	u8 protocol;
	unsigned short family;
	int src_port;
	int dst_port;
	union {
		struct in_addr ip;
		struct in6_addr ip6;
		u8 raw[16];
	} dst;
	union {
		struct in_addr ip;
		struct in6_addr ip6;
		u8 raw[16];
	} src;
};
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
DEFINE_SPINLOCK(log_lock);

/* Poll queue */
DECLARE_WAIT_QUEUE_HEAD(log_wait);

/* Get the path of a log */
static char *log_path(struct netlog_log *log)
{
	return ((char*)log) + sizeof(struct netlog_log);
}

static u32 next_record(u32 idx)
{
	size_t *len;

	len = (size_t*)(log_buf + idx);
	if (*len == 0)
	{
		/* We need to wrap around */
		return 0;
	}
	return idx + *len;
}

void
store_record(pid_t pid, uid_t uid, const char* path, u8 action,
             u8 protocol, unsigned short family,
             const void *src_ip, int src_port, const void *dst_ip, int dst_port) {
	struct netlog_log *record;
	size_t path_len, record_size;
	unsigned long flags;

	path_len = strlen(path);
	record_size = sizeof(struct netlog_log) + path_len + 1;
	record_size += (-record_size) & (LOG_ALIGN - 1);

	spin_lock_irqsave(&log_lock, flags);

	while (log_first_seq < log_next_seq) {
		size_t free;

        	if (log_next_idx > log_first_idx)
			free = max(LOG_BUF_LEN - log_next_idx, log_first_idx);
		else
			free = log_first_idx - log_next_idx;

		if (free > record_size + sizeof(size_t))
			break;

		/* Drop old messages until we have enough contiuous space */
		log_first_idx = next_record(log_first_idx);
		log_first_seq++;
	}

	if (log_next_idx + record_size + sizeof(size_t) >= LOG_BUF_LEN) {
		/*
		 * As free > size + sizeof(size_t), this mean that we had
		 * free = max(log_buf_len - log_next_idx, log_first_idx)
		 * But as we are too close to the end, it means that the max
		 * is log_first_idx, thus we must wrap around.
		 * Add an empty size_t to indicate the wrap around
		 */
		*((size_t*)(log_buf + log_next_idx)) = 0;
		log_next_idx = 0;
	}

	record = (struct netlog_log*)(log_buf + log_next_idx);
	/* Store the data in the recored */
	record->len = record_size;
	record->path_len = path_len;
	record->nsec = local_clock();
	record->pid = pid;
	record->uid = uid;
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

	/* Update the next position */
        log_next_idx += record_size;
        log_next_seq++;

	spin_unlock_irqrestore(&log_lock, flags);

	/* Wake-up reading threads */
	wake_up_interruptible(&log_wait);
}

static loff_t netlog_log_llseek(struct file *file, loff_t offset, int whence)
{
	return 0;
}

static ssize_t netlog_log_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
	return 0;
}

static unsigned int netlog_log_poll(struct file *file, poll_table *wait)
{
	return 0;
}

static int netlog_log_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int netlog_log_release(struct inode *inode, struct file *file)
{
	return 0;
}


const struct file_operations netlog_log_fops = {
	.owner = THIS_MODULE,
	.open = netlog_log_open,
	.read = netlog_log_read,
	.llseek = netlog_log_llseek,
	.poll = netlog_log_poll,
	.release = netlog_log_release,
};
