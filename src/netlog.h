#ifndef __NETLOG__
#define __NETLOG__

/* Change to non zero value (i.e. 1) if you wish to probe
 * the binding of UDP sockets.
 */

#define PROBE_UDP 0

/* Change to zero value (0) if you wish to not probe
 * the close system call for the sockets.
 */

#define PROBE_CONNECTION_CLOSE 1

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

/* Size of the buffer containing the logs */
#define LOG_BUF_LEN (1 << 20)

/* Log facility and level for our devicde */
#define LOG_FACILITY 0
#define LOG_LEVEL    6

/* Device name (in /dev/log) */
#define NELOG_DEVICE_NAME MODULE_NAME

/* Separator for the whitelisting */
#define FIELD_SEPARATOR '|'

/* Old linux makefiles seem broken */
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
#define MODULE_NAME "netlog"
#endif

#endif /* __NETLOG__ */
