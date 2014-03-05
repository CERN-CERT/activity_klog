#ifndef __NETLOG_PROBES__
#define __NETLOG_PROBES__

#define PROBES_NUMBER 6

#define PROBE_TCP_CONNECT 0
#define PROBE_TCP_ACCEPT  1
#define PROBE_TCP_CLOSE   2
#define PROBE_UDP_CONNECT 3
#define PROBE_UDP_BIND    4
#define PROBE_UDP_CLOSE   5

struct probes {
	const char *name;
	u32 mask;
};

extern struct probes probe_list[];

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
int all_probes_param_set(const char *buf, struct kernel_param *kp);
int all_probes_param_get(char *buffer, struct kernel_param *kp);
int one_probe_param_set(const char *buf, struct kernel_param *kp);
int one_probe_param_get(char *buffer, struct kernel_param *kp);
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
extern const struct kernel_param_ops all_probes_param;
extern const struct kernel_param_ops one_probe_param;
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(2, 6, 36) */

int probes_init(void);
void unplant_all(void);

#endif /* __NETLOG_PROBES__ */
