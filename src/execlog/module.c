#include <linux/module.h>
#include <linux/binfmts.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/version.h>
#include "execlog.h"
#include "probes.h"
#include "whitelist.h"

/************************************/
/*             INIT MODULE          */
/************************************/

static int __init execlog_init(void)
{
	int err;

	pr_info("Light monitoring tool for execve by CERN Security Team\n");

	err = probes_plant();
	if (err < 0) {
		destroy_whitelist();
		return err;
	}
	pr_info("[+] "MODULE_NAME" version "MOD_VER" deployed\n");
	return 0;
}

/************************************/
/*             EXIT MODULE          */
/************************************/

static void __exit execlog_exit(void)
{
	probes_unplant();
	destroy_whitelist();
}


/**********************************/
/*      MODULE PARAMETERS         */
/**********************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
module_param_call(whitelist, &whitelist_param_set, &whitelist_param_get, NULL, 0600);
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
module_param_cb(whitelist, &whitelist_param, NULL, 0600);
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(2, 6, 36) */
MODULE_PARM_DESC(whitelist, " A coma separated list of strings that contains"
		 " the executions that " MODULE_NAME " will ignore.\n"
		 " The format of the string must be '${executable}|${argv_start}'."
		 " The |${argv_start} part is optional.");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
module_param_call(whitelist_include_root, &whitelist_root_param_set, &whitelist_root_param_get, NULL, 0600);
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
module_param_cb(whitelist_include_root, &whitelist_root_param, NULL, 0600);
#endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(2, 6, 36) */
MODULE_PARM_DESC(whitelist_include_root, "A boolean indicating if root actions"
		 " should be whitelisted like actions from other users or not.");

/************************************/
/*             MODULE DEF           */
/************************************/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Brillault <vincent.brillault@cern.ch>");
MODULE_DESCRIPTION("execlog logs information about every 'execve' syscall.");
MODULE_VERSION(MOD_VER);

module_init(execlog_init)
module_exit(execlog_exit)
