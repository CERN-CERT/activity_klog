#ifndef __EXECLOG_MODULE__
#define __EXECLOG_MODULE__

/* Printing function */
#undef pr_fmt
#define pr_fmt(fmt) MODULE_NAME ": " fmt

/* Max and min values for truncating the argv */
/* Max needs to be smaller than LONG_MAX */
/* Min needs to be bigger than 2 */

#define ARGV_MAX_SIZE 39936
#define ARGV_MIN_SIZE 100

#endif /* __EXECLOG_MODULE__ */
