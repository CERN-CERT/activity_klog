#ifndef __NETLOG__
#define __NETLOG__

/* Probes enabled by default (all) */
#define DEFAULT_PROBES 0xFFFFFFFF

/* Probes need to resolve those absolute path.
 * For memory reason, those path lentgh must be bounded.
 */
#define MAX_EXEC_PATH 950

/* Maximum number of whitelisted element in module parameter */
#define MAX_WHITELIST_SIZE 100

/* Error codes */

#define CONNECT_PROBE_FAILED 1
#define ACCEPT_PROBE_FAILED 2
#define CLOSE_PROBE_FAILED 3
#define BIND_PROBE_FAILED 4

/* Separator for the whitelisting */
#define FIELD_SEPARATOR '|'

#endif /* __NETLOG__ */
