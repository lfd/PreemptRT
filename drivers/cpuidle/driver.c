/*
 * driver.c - driver support
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

LIST_HEAD(cpuidle_drivers);
struct cpuidle_driver *cpuidle_curr_driver;


/**
 * cpuidle_attach_driver - attaches a driver to a CPU
 * @dev: the target CPU
 *
 * Must be called with cpuidle_lock aquired.
 */
int cpuidle_attach_driver(struct cpuidle_device *dev)
{
	int ret;

	if (dev->status & CPUIDLE_STATUS_DRIVER_ATTACHED)
		return -EIO;

	if (!try_module_get(cpuidle_curr_driver->owner))
		return -EINVAL;

	ret = cpuidle_curr_driver->init(dev);
	if (ret) {
		module_put(cpuidle_curr_driver->owner);
		printk(KERN_ERR "cpuidle: driver %s failed to attach to cpu %d\n",
			cpuidle_curr_driver->name, dev->cpu);
	} else {
		if (dev->status & CPUIDLE_STATUS_GOVERNOR_ATTACHED)
			cpuidle_rescan_device(dev);
		smp_wmb();
		dev->status |= CPUIDLE_STATUS_DRIVER_ATTACHED;
		cpuidle_add_driver_sysfs(dev);
	}

	return ret;
}

/**
 * cpuidle_detach_govenor - detaches a driver from a CPU
 * @dev: the target CPU
 *
 * Must be called with cpuidle_lock aquired.
 */
void cpuidle_detach_driver(struct cpuidle_device *dev)
{
	if (dev->status & CPUIDLE_STATUS_DRIVER_ATTACHED) {
		cpuidle_remove_driver_sysfs(dev);
		dev->status &= ~CPUIDLE_STATUS_DRIVER_ATTACHED;
		if (cpuidle_curr_driver->exit)
			cpuidle_curr_driver->exit(dev);
		module_put(cpuidle_curr_driver->owner);
	}
}

/**
 * __cpuidle_find_driver - finds a driver of the specified name
 * @str: the name
 *
 * Must be called with cpuidle_lock aquired.
 */
struct cpuidle_driver * __cpuidle_find_driver(const char *str)
{
	struct cpuidle_driver *drv;

	list_for_each_entry(drv, &cpuidle_drivers, driver_list)
		if (!strnicmp(str, drv->name, CPUIDLE_NAME_LEN))
			return drv;

	return NULL;
}

/**
 * cpuidle_switch_driver - changes the driver
 * @drv: the new target driver
 *
 * NOTE: "drv" can be NULL to specify disabled
 * Must be called with cpuidle_lock aquired.
 */
int cpuidle_switch_driver(struct cpuidle_driver *drv)
{
	struct cpuidle_device *dev;

	if (drv == cpuidle_curr_driver)
		return -EINVAL;

	cpuidle_uninstall_idle_handler();

	if (cpuidle_curr_driver)
		list_for_each_entry(dev, &cpuidle_detected_devices, device_list)
			cpuidle_detach_driver(dev);

	cpuidle_curr_driver = drv;

	if (drv) {
		list_for_each_entry(dev, &cpuidle_detected_devices, device_list)
			cpuidle_attach_driver(dev);
		if (cpuidle_curr_governor)
			cpuidle_install_idle_handler();
		printk(KERN_INFO "cpuidle: using driver %s\n", drv->name);
	}

	return 0;
}

/**
 * cpuidle_register_driver - registers a driver
 * @drv: the driver
 */
int cpuidle_register_driver(struct cpuidle_driver *drv)
{
	int ret = -EEXIST;

	if (!drv || !drv->init)
		return -EINVAL;

	mutex_lock(&cpuidle_lock);
	if (__cpuidle_find_driver(drv->name) == NULL) {
		ret = 0;
		list_add_tail(&drv->driver_list, &cpuidle_drivers);
		if (!cpuidle_curr_driver)
			cpuidle_switch_driver(drv);
	}
	mutex_unlock(&cpuidle_lock);

	return ret;
}

EXPORT_SYMBOL_GPL(cpuidle_register_driver);

/**
 * cpuidle_unregister_driver - unregisters a driver
 * @drv: the driver
 */
void cpuidle_unregister_driver(struct cpuidle_driver *drv)
{
	if (!drv)
		return;

	mutex_lock(&cpuidle_lock);
	if (drv == cpuidle_curr_driver)
		cpuidle_switch_driver(NULL);
	list_del(&drv->driver_list);
	mutex_unlock(&cpuidle_lock);
}

EXPORT_SYMBOL_GPL(cpuidle_unregister_driver);

/**
 * cpuidle_force_redetect - redetects the idle states of a CPU
 *
 * @dev: the CPU to redetect
 *
 * Generally, the driver will call this when the supported states set has
 * changed. (e.g. as the result of an ACPI transition to battery power)
 */
int cpuidle_force_redetect(struct cpuidle_device *dev)
{
	int uninstalled = 0;

	mutex_lock(&cpuidle_lock);

	if (!(dev->status & CPUIDLE_STATUS_DRIVER_ATTACHED) ||
	    !cpuidle_curr_driver->redetect) {
		mutex_unlock(&cpuidle_lock);
		return -EIO;
	}

	if (cpuidle_device_can_idle(dev)) {
		uninstalled = 1;
		cpuidle_uninstall_idle_handler();
	}

	cpuidle_remove_driver_sysfs(dev);
	cpuidle_curr_driver->redetect(dev);
	cpuidle_add_driver_sysfs(dev);

	if (cpuidle_device_can_idle(dev)) {
		cpuidle_rescan_device(dev);
		cpuidle_install_idle_handler();
	}

	/* other devices are still ok */
	if (uninstalled)
		cpuidle_install_idle_handler();

	mutex_unlock(&cpuidle_lock);

	return 0;
}

EXPORT_SYMBOL_GPL(cpuidle_force_redetect);

/**
 * cpuidle_get_bm_activity - determines if BM activity has occured
 */
int cpuidle_get_bm_activity(void)
{
	if (cpuidle_curr_driver->bm_check)
		return cpuidle_curr_driver->bm_check();
	else
		return 0;
}
EXPORT_SYMBOL_GPL(cpuidle_get_bm_activity);

