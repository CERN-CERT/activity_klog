#ifndef __NETLOG__
#define __NETLOG__

/* Probes enabled by default (all) */
#define DEFAULT_PROBES 0xFFFFFFFF

/* In absolute_path_mode mode, probes need to resolve those absolute path.
 * For memory reason, those path lentgh must be bounded.
 */
#define MAX_ABSOLUTE_EXEC_PATH 950


/* Set to non-zero value in order to compile the whitelisting code*/

#define WHITELISTING 1

/* Maximum number of whitelisted element in module parameter */
#define MAX_WHITELIST_SIZE 100

/* Error codes */

#define CONNECT_PROBE_FAILED 1
#define ACCEPT_PROBE_FAILED 2
#define CLOSE_PROBE_FAILED 3
#define BIND_PROBE_FAILED 4

/* Separator for the whitelisting */
#define FIELD_SEPARATOR '|'

/* Old linux makefiles seem broken */
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
#define MODULE_NAME "netlog"
#endif

#endif /* __NETLOG__ */
