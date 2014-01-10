#ifndef __NETLOG_INTERNAL__
#define __NETLOG_INTERNAL___

#define NO_PORT -1

/* Printing function */
#undef pr_fmt
#define pr_fmt(fmt) MODULE_NAME ": " fmt

#endif /* __NETLOG_INTERNAL__ */
