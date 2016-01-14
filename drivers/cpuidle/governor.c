/*
 * governor.c - governor support
 *
 * (C) 2006-2007 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *               Shaohua Li <shaohua.li@intel.com>
 *               Adam Belay <abelay@novell.com>
 *
 * This code is licenced under the GPL.
 */

#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/cpuidle.h>

#include "cpuidle.h"

LIST_HEAD(cpuidle_governors);
struct cpuidle_governor *cpuidle_curr_governor;


/**
 * cpuidle_attach_governor - attaches a governor to a CPU
 * @dev: the target CPU
 *
 * Must be called with cpuidle_lock aquired.
 */
int cpuidle_attach_governor(struct cpuidle_device *dev)
{
	int ret = 0;

	if(dev->status & CPUIDLE_STATUS_GOVERNOR_ATTACHED)
		return -EIO;

	if (!try_module_get(cpuidle_curr_governor->owner))
		return -EINVAL;

	if (cpuidle_curr_governor->init)
		ret = cpuidle_curr_governor->init(dev);
	if (ret) {
		module_put(cpuidle_curr_governor->owner);
		printk(KERN_ERR "cpuidle: governor %s failed to attach to cpu %d\n",
			cpuidle_curr_governor->name, dev->cpu);
	} else {
		if (dev->status & CPUIDLE_STATUS_DRIVER_ATTACHED)
			cpuidle_rescan_device(dev);
		smp_wmb();
		dev->status |= CPUIDLE_STATUS_GOVERNOR_ATTACHED;
	}

	return ret;
}

/**
 * cpuidle_detach_govenor - detaches a governor from a CPU
 * @dev: the target CPU
 *
 * Must be called with cpuidle_lock aquired.
 */
void cpuidle_detach_governor(struct cpuidle_device *dev)
{
	if (dev->status & CPUIDLE_STATUS_GOVERNOR_ATTACHED) {
		dev->status &= ~CPUIDLE_STATUS_GOVERNOR_ATTACHED;
		if (cpuidle_curr_governor->exit)
			cpuidle_curr_governor->exit(dev);
		module_put(cpuidle_curr_governor->owner);
	}
}

/**
 * __cpuidle_find_governor - finds a governor of the specified name
 * @str: the name
 *
 * Must be called with cpuidle_lock aquired.
 */
struct cpuidle_governor * __cpuidle_find_governor(const char *str)
{
	struct cpuidle_governor *gov;

	list_for_each_entry(gov, &cpuidle_governors, governor_list)
		if (!strnicmp(str, gov->name, CPUIDLE_NAME_LEN))
			return gov;

	return NULL;
}

/**
 * cpuidle_switch_governor - changes the governor
 * @gov: the new target governor
 *
 * NOTE: "gov" can be NULL to specify disabled
 * Must be called with cpuidle_lock aquired.
 */
int cpuidle_switch_governor(struct cpuidle_governor *gov)
{
	struct cpuidle_device *dev;

	if (gov == cpuidle_curr_governor)
		return -EINVAL;

	cpuidle_uninstall_idle_handler();

	if (cpuidle_curr_governor)
		list_for_each_entry(dev, &cpuidle_detected_devices, device_list)
			cpuidle_detach_governor(dev);

	cpuidle_curr_governor = gov;

	if (gov) {
		list_for_each_entry(dev, &cpuidle_detected_devices, device_list)
			cpuidle_attach_governor(dev);
		if (cpuidle_curr_driver)
			cpuidle_install_idle_handler();
		printk(KERN_INFO "cpuidle: using governor %s\n", gov->name);
	}

	return 0;
}

/**
 * cpuidle_register_governor - registers a governor
 * @gov: the governor
 */
int cpuidle_register_governor(struct cpuidle_governor *gov)
{
	int ret = -EEXIST;

	if (!gov || !gov->select_state)
		return -EINVAL;

	mutex_lock(&cpuidle_lock);
	if (__cpuidle_find_governor(gov->name) == NULL) {
		ret = 0;
		list_add_tail(&gov->governor_list, &cpuidle_governors);
		if (!cpuidle_curr_governor)
			cpuidle_switch_governor(gov);
	}
	mutex_unlock(&cpuidle_lock);

	return ret;
}

EXPORT_SYMBOL_GPL(cpuidle_register_governor);

/**
 * cpuidle_unregister_governor - unregisters a governor
 * @gov: the governor
 */
void cpuidle_unregister_governor(struct cpuidle_governor *gov)
{
	if (!gov)
		return;

	mutex_lock(&cpuidle_lock);
	if (gov == cpuidle_curr_governor)
		cpuidle_switch_governor(NULL);
	list_del(&gov->governor_list);
	mutex_unlock(&cpuidle_lock);
}

EXPORT_SYMBOL_GPL(cpuidle_unregister_governor);
