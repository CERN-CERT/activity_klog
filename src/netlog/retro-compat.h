/* This file is included for retro-compatibility purposes */

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 25)
	#define SADDR saddr
	#define DADDR daddr
	#define SPORT sport
	#define DPORT dport
#else
	#define SADDR inet_saddr
	#define DADDR inet_daddr
	#define SPORT inet_sport
	#define DPORT inet_dport
#endif
