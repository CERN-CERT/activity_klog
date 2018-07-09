#ifndef __TOOL_CURRENT_DATA__
#define __TOOL_CURRENT_DATA__

#include <linux/tty.h>
#include <linux/version.h>

/* Structure containing all the details about the current process */
struct current_details {
	u64 nsec   /** Timestamp (now) */;
	pid_t pid  /** PID of 'current' */;
	pid_t sid  /** SID of the PID of 'current' */;
	pid_t ppid /** PID of the parent of the PID of 'current' */;
	uid_t uid  /** UID of 'current' */;
	uid_t euid /** EUID of 'current' */;
	uid_t gid  /** GID of 'current' */;
	uid_t egid /** EGID of 'current' */;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	const char *tty; /** TTY, if existant, used by 'current', '\0' otherwise */;
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0) */
	char tty[64] /** TTY, if existant, used by 'current', '\0' otherwise */;
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(4, 2, 0) */
};

#define CURRENT_DETAILS_FORMAT "p:%d s:%d pp:%d u:%d g:%d eu:%d eg:%d t:%s"
#define CURRENT_DETAILS_ARGS(details) details.pid, details.sid, details.ppid, \
				      details.uid, details.gid, \
				      details.euid, details.egid, \
				      details.tty

static const char null_tty[] = "NULL tty";
static const char null_tty_short[] = "NULL";

static inline void
fill_current_details(struct current_details *details)
{
	struct task_struct * parent;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	kuid_t kuid;
	kgid_t kgid;

	current_uid_gid(&kuid, &kgid);
	details->uid = kuid.val;
	details->gid = kgid.val;
	current_euid_egid(&kuid, &kgid);
	details->euid = kuid.val;
	details->egid = kgid.val;
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0) */
	current_uid_gid(&details->uid, &details->gid);
	current_euid_egid(&details->euid, &details->egid);
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(3, 5, 0) */
	details->nsec = local_clock();
	details->pid = current->pid;
	rcu_read_lock();
	parent = rcu_dereference(current->real_parent);
	if (likely(parent != NULL))
		details->ppid = parent->pid;
	else
		details->ppid = 0;
	rcu_read_unlock();
	details->sid = task_session_vnr(current);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	details->tty = tty_name(current->signal->tty);
	if (strcmp(details->tty, null_tty) == 0)
		details->tty = null_tty_short;
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0) */
	tty_name(current->signal->tty, details->tty);
	if (memcmp(details->tty, null_tty, sizeof(null_tty) - 1) == 0)
		details->tty[4] = '\0';
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(4, 2, 0) */
}

#endif /* __TOOL_CURRENT_DATA__ */
