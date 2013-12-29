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

/*******************************/
/* Kernel Versionning handling */
/*******************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	#define get_current_uid() current->uid
#else
	#define get_current_uid() current_uid()
#endif

/****************************************************************/
/* Kernel module information (submitted at the end of the file) */
/****************************************************************/

#define MOD_AUTHORS "Panos Sakkos <panos.sakkos@cern.ch>, Vincent Brillault <vincent.brillault@cern.ch";
#define MOD_DESC "netlog logs information about every internet connection\n" \
                 "\t\tfrom and to the machine that is installed. This information\n" \
                 "\t\tis source/destination ips and ports, process name and pid,\n" \
                 "\t\tuid and the protocol (TCP/UDP)."
#define MOD_LICENSE "GPL"

/**********************************/
/*      MODULE PARAMETERS         */
/**********************************/

int absolute_path_mode = 1;

module_param(absolute_path_mode, int, 0);
MODULE_PARM_DESC(absolute_path_mode, " Boolean parameter for absolute path mode. If disabled,\n"
                                     "\t\tboth whiltelisting and log will only contain the process name\n"
                                     "\t\tinstead of the complete path\n");

static int probes = DEFAULT_PROBES;

module_param(probes, int, 0);
MODULE_PARM_DESC(probes, " Integer paramter describing which prbes should be loaded\n");

#if WHITELISTING

static int whitelist_length = 0;
static char *connections_to_whitelist[MAX_WHITELIST_SIZE] = {NULL};

module_param_array(connections_to_whitelist, charp, &whitelist_length, 0000);
MODULE_PARM_DESC(connections_to_whitelist, " An array of strings that contains the connections that " MODULE_NAME " will ignore.\n"
					    "\t\tThe format of the string must be '/absolute/executable/path ip_address-port'");
#endif

/************************************/
/*             INIT MODULE          */
/************************************/

static int __init netlog_init(void)
{
	int err;

	printk(KERN_INFO MODULE_NAME ": Light monitoring tool for inet connections by CERN Security Team\n");

	err = plant_probe(probes);
	if(err < 0)
		return err;

	err = create_proc();

	if(err < 0)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Creation of proc files failed\n");
		unplant_all();
		return err;
	}
	else
	{
		printk(KERN_INFO MODULE_NAME ":\t[+] Created proc files for configuration\n");
	}

#if WHITELISTING
	set_whitelist_from_array(connections_to_whitelist, whitelist_length);
#endif

	if(absolute_path_mode)
	{
		printk(KERN_INFO MODULE_NAME ":\t[+] Absolute path mode is enabled. The logs will contain the absolute execution path\n");
	}
	else
	{
		printk(KERN_INFO MODULE_NAME ":\t[-] Absolute path mode is disabled. The logs will contain the process name\n");
	}

	printk(KERN_INFO MODULE_NAME ":\t[+] Deployed\n");

	return 0;
}

/************************************/
/*             EXIT MODULE          */
/************************************/

static void __exit netlog_exit(void)
{
	unplant_all();
	#if WHITELISTING

	destroy_proc();
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