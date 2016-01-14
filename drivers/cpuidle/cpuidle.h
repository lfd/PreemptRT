/*
 * cpuidle.h - The internal header file
 */

#ifndef __DRIVER_CPUIDLE_H
#define __DRIVER_CPUIDLE_H

#include <linux/sysdev.h>

/* For internal use only */
extern struct cpuidle_governor *cpuidle_curr_governor;
extern struct cpuidle_driver *cpuidle_curr_driver;
extern struct list_head cpuidle_drivers;
extern struct list_head cpuidle_governors;
extern struct list_head cpuidle_detected_devices;
extern struct mutex cpuidle_lock;

/* idle loop */
extern void cpuidle_install_idle_handler(void);
extern void cpuidle_uninstall_idle_handler(void);
extern void cpuidle_rescan_device(struct cpuidle_device *dev);

/* drivers */
extern int cpuidle_attach_driver(struct cpuidle_device *dev);
extern void cpuidle_detach_driver(struct cpuidle_device *dev);
extern struct cpuidle_driver * __cpuidle_find_driver(const char *str);
extern int cpuidle_switch_driver(struct cpuidle_driver *drv);

/* governors */
extern int cpuidle_attach_governor(struct cpuidle_device *dev);
extern void cpuidle_detach_governor(struct cpuidle_device *dev);
extern struct cpuidle_governor * __cpuidle_find_governor(const char *str);
extern int cpuidle_switch_governor(struct cpuidle_governor *gov);

/* sysfs */
extern int cpuidle_add_class_sysfs(struct sysdev_class *cls);
extern void cpuidle_remove_class_sysfs(struct sysdev_class *cls);
extern int cpuidle_add_driver_sysfs(struct cpuidle_device *device);
extern void cpuidle_remove_driver_sysfs(struct cpuidle_device *device);
extern int cpuidle_add_sysfs(struct sys_device *sysdev);
extern void cpuidle_remove_sysfs(struct sys_device *sysdev);

/**
 * cpuidle_device_can_idle - determines if a CPU can utilize the idle loop
 * @dev: the target CPU
 */
static inline int cpuidle_device_can_idle(struct cpuidle_device *dev)
{
	return (dev->status == CPUIDLE_STATUS_DOIDLE);
}

#endif /* __DRIVER_CPUIDLE_H */
