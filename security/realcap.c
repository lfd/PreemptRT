/*
 * Realtime Capabilities Linux Security Module
 *
 *  Copyright (C) 2003 Torben Hohn
 *  Copyright (C) 2003, 2004 Jack O'Quin
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/security.h>

#define RT_LSM "Realtime LSM "		/* syslog module name prefix */
#define RT_ERR "Realtime: "		/* syslog error message prefix */

/* module parameters
 *
 *  These values could change at any time due to some process writing
 *  a new value in /sys/module/realtime/parameters.  This is OK,
 *  because each is referenced only once in each function call.
 *  Nothing depends on parameters having the same value every time.
 */

/* if TRUE, any process is realtime */
static int rt_any;
module_param_named(any, rt_any, int, 0644);
MODULE_PARM_DESC(any, " grant realtime privileges to any process.");

/* realtime group id, or NO_GROUP */
static int rt_gid = -1;
module_param_named(gid, rt_gid, int, 0644);
MODULE_PARM_DESC(gid, " the group ID with access to realtime privileges.");

/* enable mlock() privileges */
static int rt_mlock = 1;
module_param_named(mlock, rt_mlock, int, 0644);
MODULE_PARM_DESC(mlock, " enable memory locking privileges.");

/* helper function for testing group membership */
static inline int gid_ok(int gid)
{
	if (gid == -1)
		return 0;

	if (gid == current->gid)
		return 1;

	return in_egroup_p(gid);
}

static void realtime_bprm_apply_creds(struct linux_binprm *bprm, int unsafe)
{
	cap_bprm_apply_creds(bprm, unsafe);

	/*  If a non-zero `any' parameter was specified, we grant
	 *  realtime privileges to every process.  If the `gid'
	 *  parameter was specified and it matches the group id of the
	 *  executable, of the current process or any supplementary
	 *  groups, we grant realtime capabilites.
	 */

	if (rt_any || gid_ok(rt_gid)) {
		cap_raise(current->cap_effective, CAP_SYS_NICE);
		if (rt_mlock) {
			cap_raise(current->cap_effective, CAP_IPC_LOCK);
			cap_raise(current->cap_effective, CAP_SYS_RESOURCE);
		}
	}
}

static struct security_operations capability_ops = {
	.ptrace =			cap_ptrace,
	.capget =			cap_capget,
	.capset_check =			cap_capset_check,
	.capset_set =			cap_capset_set,
	.capable =			cap_capable,
	.netlink_send =			cap_netlink_send,
	.netlink_recv =			cap_netlink_recv,
	.bprm_apply_creds =		realtime_bprm_apply_creds,
	.bprm_set_security =		cap_bprm_set_security,
	.bprm_secureexec =		cap_bprm_secureexec,
	.task_post_setuid =		cap_task_post_setuid,
	.task_reparent_to_init =	cap_task_reparent_to_init,
	.syslog =                       cap_syslog,
	.vm_enough_memory =             cap_vm_enough_memory,
};

#define MY_NAME __stringify(KBUILD_MODNAME)

static int secondary;	/* flag to keep track of how we were registered */

static int __init realtime_init(void)
{
	/* register ourselves with the security framework */
	if (register_security(&capability_ops)) {

		/* try registering with primary module */
		if (mod_reg_security(MY_NAME, &capability_ops)) {
			printk(KERN_INFO RT_ERR "Failure registering "
			       "capabilities with primary security module.\n");
			printk(KERN_INFO RT_ERR "Is kernel configured "
			       "with CONFIG_SECURITY_CAPABILITIES=m?\n");
			return -EINVAL;
		}
		secondary = 1;
	}

	if (rt_any)
		printk(KERN_INFO RT_LSM
		       "initialized (all groups, mlock=%d)\n", rt_mlock);
	else if (rt_gid == -1)
		printk(KERN_INFO RT_LSM
		       "initialized (no groups, mlock=%d)\n", rt_mlock);
	else
		printk(KERN_INFO RT_LSM
		       "initialized (group %d, mlock=%d)\n", rt_gid, rt_mlock);

	return 0;
}

static void __exit realtime_exit(void)
{
	/* remove ourselves from the security framework */
	if (secondary) {
		if (mod_unreg_security(MY_NAME, &capability_ops))
			printk(KERN_INFO RT_ERR "Failure unregistering "
				"capabilities with primary module.\n");

	} else if (unregister_security(&capability_ops)) {
		printk(KERN_INFO RT_ERR
		       "Failure unregistering capabilities with the kernel\n");
	}
	printk(KERN_INFO "Realtime Capability LSM exiting\n");
}

late_initcall(realtime_init);
module_exit(realtime_exit);

MODULE_DESCRIPTION("Realtime Capabilities Security Module");
MODULE_LICENSE("GPL");
