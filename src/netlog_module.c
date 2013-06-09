#include <linux/module.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include "inet_utils.h"
#include "whitelist.h"
#include "netlog.h"
#include "connection.h"
#include "proc_config.h"
#include "probes.h"

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

int absolute_path_mode = 0;

module_param(absolute_path_mode, int, 0);
MODULE_PARM_DESC(absolute_path_mode, " Boolean parameter for absolute path mode. When enabled, \n"
				"\t\tit will log the execution path instead of the process name");

#if WHITELISTING

static int whitelist_length = 0;
static char *connections_to_whitelist[MAX_WHITELIST_SIZE] = {'\0'};

module_param_array(connections_to_whitelist, charp, &whitelist_length, 0000);
MODULE_PARM_DESC(connections_to_whitelist, " An array of strings that contains the connections that " MODULE_NAME " will ignore.\n"
					    "\t\tThe format of the string must be '/absolute/executable/path ip_address-port'");
#endif

#if WHITELISTING

static void do_whitelist(void)
{
	int i, err;

	/*Deal with the whitelisting*/

	if(whitelist_length > MAX_WHITELIST_SIZE)
	{
		printk(KERN_ERR MODULE_NAME ":\t[-] Cannot whitelist more than %d connections. The %d last parameters paths will be ignored. \
					Please change MAX_WHITELIST_SIZE definition in netlog.h and recompile, or contact \
					CERN-CERT <cert@cern.ch>\n", MAX_WHITELIST_SIZE, whitelist_length - MAX_WHITELIST_SIZE);

		whitelist_length = MAX_WHITELIST_SIZE;
	}

	/*Will not check if the paths are valid, because in case that they are, they will be ignored*/

	for(i = 0; i < whitelist_length; ++i)
	{
		err = whitelist(connections_to_whitelist[i]);

		if(err < 0)
		{
			printk(KERN_ERR MODULE_NAME ":\t[-] Failed to whitelist %s\n", connections_to_whitelist[i]);
		}
		else
		{
			printk(KERN_INFO MODULE_NAME ":\t[+] Whitelisted %s\n", connections_to_whitelist[i]);
		}
	}
}

#endif

/************************************/
/*             INIT MODULE          */
/************************************/

static int __init netlog_init(void)
{
	int err;

	printk(KERN_INFO MODULE_NAME ": Light monitoring tool for inet connections by CERN Security Team\n");

	err = plant_all();

	if(err < 0)
	{
		return err;
	}

	#if WHITELISTING

	err = create_proc_config();

	if(err < 0)
	{
		printk(KERN_INFO MODULE_NAME ":\t[-] Creation of proc file for configuring connection whitelisting failed\n");
	}
	else
	{
		printk(KERN_INFO MODULE_NAME ":\t[+] Created %s proc file for configuring connection whitelisting\n", PROC_CONFIG_NAME);
	}

	do_whitelist();

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

	destroy_whitelist();
	destroy_proc_config();

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
