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
	char tty[64] /** TTY, if existant, used by 'current', '\0' otherwise */;
};

#define CURRENT_DETAILS_FORMAT "p:%d s:%d pp:%d u/g:%d/%d eu/g:%d/%d t:%s"
#define CURRENT_DETAILS_ARGS(details) details.pid, details.sid, details.ppid, \
				      details.uid, details.gid, \
				      details.euid, details.egid, \
				      details.tty

static const char null_tty[] = "NULL tty";

static inline void
fill_current_details(struct current_details *details)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	kuid_t kuid;
	kgid_t kgid;

	current_uid_gid(&kuid, &kgid);
	details->uid = from_kuid(&init_user_ns, kuid);
	details->gid = from_kgid(&init_user_ns, kgid);
	current_euid_egid(&kuid, &kgid);
	details->euid = from_kuid(&init_user_ns, kuid);
	details->egid = from_kgid(&init_user_ns, kgid);
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0) */
	current_uid_gid(&details->uid, &details->gid);
	current_euid_egid(&details->euid, &details->egid);
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(3, 5, 0) */
	details->nsec = local_clock();
	details->pid = current->pid;
	if (likely(current->real_parent != NULL))
		details->ppid = current->real_parent->pid;
	else
		details->ppid = 0;
	details->sid = task_session_vnr(current);
	tty_name(current->signal->tty, details->tty);
	if (memcmp(details->tty, null_tty, sizeof(null_tty) - 1) == 0)
		details->tty[4] = '\0';
}

#endif /* __TOOL_CURRENT_DATA__ */
