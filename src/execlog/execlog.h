#ifndef __EXECLOG_MODULE__
#define __EXECLOG_MODULE__

/* Printing function */
#undef pr_fmt
#define pr_fmt(fmt) MODULE_NAME ": " fmt

#endif /* __EXECLOG_MODULE__ */
