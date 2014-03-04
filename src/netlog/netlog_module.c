#include <linux/module.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include "whitelist.h"
#include "proc_config.h"
#include "probes.h"
#include "internal.h"
#include "netlog.h"

/****************************************************************/
/* Kernel module information (submitted at the end of the file) */
/****************************************************************/

#define MOD_AUTHORS "Panos Sakkos <panos.sakkos@cern.ch>," \
		    "Vincent Brillault <vincent.brillault@cern.ch";
#define MOD_DESC "netlog logs information about every internet connection\n" \
		 "\t\tfrom and to the machine that is installed. This information\n" \
		 "\t\tis source/destination ips and ports, process name and pid,\n" \
		 "\t\tuid and the protocol (TCP/UDP)."
#define MOD_LICENSE "GPL"

/**********************************/
/*      MODULE PARAMETERS         */
/**********************************/

static int probes = DEFAULT_PROBES;

module_param(probes, int, 0);
MODULE_PARM_DESC(probes, " Integer paramter describing which prbes should be loaded\n");

#if WHITELISTING
# if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
module_param_call(whitelist, &whitelist_param_set, &whitelist_param_get, NULL, 0600);
# else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36) */
module_param_cb(whitelist, &whitelist_param, NULL, 0600);
# endif /* LINUX_VERSION_CODE ? KERNEL_VERSION(2, 6, 36) */
MODULE_PARM_DESC(whitelist, " A coma separated list of strings that contains"
		 " the connections that " MODULE_NAME " will ignore.\n"
		 " The format of the string must be '${executable}|i<${ip}>|<${port}>'."
		 " The ip and port parts are optional.");
#endif

/************************************/
/*             INIT MODULE          */
/************************************/

static int __init netlog_init(void)
{
	int err;

	pr_info("Light monitoring tool for inet connections by CERN Security Team\n");

	err = plant_probe(probes);
	if (err < 0) {
		pr_info("\t[-] Unable to plant all probes\n");
		unplant_all();
		return err;
	}

	err = create_proc();
	if (err < 0) {
		pr_info("\t[-] Creation of proc files failed\n");
		unplant_all();
		return err;
	} else {
		pr_info("\t[+] Created proc files for configuration\n");
	}

	pr_info("\t[+] Deployed\n");
	return 0;
}

/************************************/
/*             EXIT MODULE          */
/************************************/

static void __exit netlog_exit(void)
{
	destroy_proc();
	unplant_all();

#if WHITELISTING
	destroy_whitelist();
#endif
}


/*********************************************/
/* Register module functions and information */
/*********************************************/

module_init(netlog_init);
module_exit(netlog_exit);

MODULE_LICENSE(MOD_LICENSE);
MODULE_AUTHOR(MOD_AUTHORS);
MODULE_DESCRIPTION(MOD_DESC);
