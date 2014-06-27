#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include "print_netlog.h"

static const char * netlog_protocol_desc[] = {
	"UNK",
	"TCP",
	"UDP",
	NULL,
};

static const char * netlog_action_desc[] = {
	" UNK ",
	" -> ",
	" <- ",
	" <!> ",
	" BIND ",
	NULL
};

/**
 * Write IP to buffer (We'll move to %pISpc when available on stable kernel...
 */
static inline ssize_t
print_ip(char *buffer, size_t len, int family, const void *ip, int port)
{
	switch (family) {
	case AF_INET:
		return snprintf(buffer, len, "%pI4:%d", ip, port);
	case AF_INET6:
		return snprintf(buffer, len, "[%pI6c]:%d", ip, port);
	default:
		return snprintf(buffer, len, "Unknown");
	}
}

/**
 * Write netlog log to buffer
 */
ssize_t
print_netlog(char *buffer, size_t len,
	     enum netlog_protocol prot, int family,
	     enum netlog_action action,
	     const void *src_ip, int src_port,
	     const void *dst_ip, int dst_port)
{
	int change;
	size_t orig_len = len;

	if (prot >= sizeof(netlog_protocol_desc))
		prot = PROTO_UNK;
	change = snprintf(buffer, len, "%s ",
			  netlog_protocol_desc[prot]);
	if (change >= len)
		return -1;
	len -= change;
	buffer += change;

	change = print_ip(buffer, len, family, src_ip, src_port);
	if (change >= len)
		return -1;
	len -= change;
	buffer += change;

	if (action >= sizeof(netlog_action_desc))
		action = ACTION_UNK;
	change = snprintf(buffer, len, "%s", netlog_action_desc[action]);
	if (change >= len)
		return -1;
	len -= change;
	buffer += change;

	if (action < ACTION_CONNECT)
		return orig_len - len;

	change = print_ip(buffer, len, family, dst_ip, dst_port);
	if (change >= len)
		return -1;
	len -= change;
	buffer += change;

	return orig_len - len;
}
