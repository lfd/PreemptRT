/*
 * cpuidle.c - core cpuidle infrastructure
 *
 * (C) 2006-2007 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *               Shaohua Li <shaohua.li@intel.com>
 *               Adam Belay <abelay@novell.com>
 *
 * This code is licenced under the GPL.
 */

#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/latency.h>
#include <linux/cpuidle.h>

#include "cpuidle.h"

DEFINE_PER_CPU(struct cpuidle_device *, cpuidle_devices);
EXPORT_PER_CPU_SYMBOL_GPL(cpuidle_devices);

DEFINE_MUTEX(cpuidle_lock);
LIST_HEAD(cpuidle_detected_devices);
static void (*pm_idle_old)(void);


/**
 * cpuidle_idle_call - the main idle loop
 *
 * NOTE: no locks or semaphores should be used here
 */
static void cpuidle_idle_call(void)
{
	struct cpuidle_device *dev = __get_cpu_var(cpuidle_devices);
	struct cpuidle_state *target_state;
	int next_state;

	/* check if the device is ready */
	if (!dev || dev->status != CPUIDLE_STATUS_DOIDLE) {
		if (pm_idle_old)
			pm_idle_old();
		else
			local_irq_enable();
		return;
	}

	/* ask the governor for the next state */
	next_state = cpuidle_curr_governor->select(dev);
	if (need_resched())
		return;
	target_state = &dev->states[next_state];

	/* enter the state and update stats */
	dev->last_residency = target_state->enter(dev, target_state);
	dev->last_state = target_state;
	target_state->time += dev->last_residency;
	target_state->usage++;

	/* give the governor an opportunity to reflect on the outcome */
	if (cpuidle_curr_governor->reflect)
		cpuidle_curr_governor->reflect(dev);
}

/**
 * cpuidle_install_idle_handler - installs the cpuidle idle loop handler
 */
void cpuidle_install_idle_handler(void)
{
	if (pm_idle != cpuidle_idle_call) {
		/* Make sure all changes finished before we switch to new idle */
		smp_wmb();
		pm_idle = cpuidle_idle_call;
	}
}

/**
 * cpuidle_uninstall_idle_handler - uninstalls the cpuidle idle loop handler
 */
void cpuidle_uninstall_idle_handler(void)
{
	if (pm_idle != pm_idle_old) {
		pm_idle = pm_idle_old;
		cpu_idle_wait();
	}
}

/**
 * cpuidle_rescan_device - prepares for a new state configuration
 * @dev: the target device
 *
 * Must be called with cpuidle_lock aquired.
 */
void cpuidle_rescan_device(struct cpuidle_device *dev)
{
	int i;

	if (cpuidle_curr_governor->scan)
		cpuidle_curr_governor->scan(dev);

	for (i = 0; i < dev->state_count; i++) {
		dev->states[i].usage = 0;
		dev->states[i].time = 0;
	}
}

/**
 * cpuidle_add_device - attaches the driver to a CPU instance
 * @sys_dev: the system device (driver model CPU representation)
 */
static int cpuidle_add_device(struct sys_device *sys_dev)
{
	int cpu = sys_dev->id;
	struct cpuidle_device *dev;

	dev = per_cpu(cpuidle_devices, cpu);

	mutex_lock(&cpuidle_lock);
	if (cpu_is_offline(cpu)) {
		mutex_unlock(&cpuidle_lock);
		return 0;
	}

	if (!dev) {
		dev = kzalloc(sizeof(struct cpuidle_device), GFP_KERNEL);
		if (!dev) {
			mutex_unlock(&cpuidle_lock);
			return -ENOMEM;
		}
		init_completion(&dev->kobj_unregister);
		per_cpu(cpuidle_devices, cpu) = dev;
	}
	dev->cpu = cpu;

	if (dev->status & CPUIDLE_STATUS_DETECTED) {
		mutex_unlock(&cpuidle_lock);
		return 0;
	}

	cpuidle_add_sysfs(sys_dev);

	if (cpuidle_curr_driver) {
		if (cpuidle_attach_driver(dev))
			goto err_ret;
	}

	if (cpuidle_curr_governor) {
		if (cpuidle_attach_governor(dev)) {
			cpuidle_detach_driver(dev);
			goto err_ret;
		}
	}

	if (cpuidle_device_can_idle(dev))
		cpuidle_install_idle_handler();

	list_add(&dev->device_list, &cpuidle_detected_devices);
	dev->status |= CPUIDLE_STATUS_DETECTED;

err_ret:
	mutex_unlock(&cpuidle_lock);

	return 0;
}

/**
 * __cpuidle_remove_device - detaches the driver from a CPU instance
 * @sys_dev: the system device (driver model CPU representation)
 *
 * Must be called with cpuidle_lock aquired.
 */
static int __cpuidle_remove_device(struct sys_device *sys_dev)
{
	struct cpuidle_device *dev;

	dev = per_cpu(cpuidle_devices, sys_dev->id);

	if (!(dev->status & CPUIDLE_STATUS_DETECTED)) {
		return 0;
	}
	dev->status &= ~CPUIDLE_STATUS_DETECTED;
	/* NOTE: we don't wait because the cpu is already offline */
	if (cpuidle_curr_governor)
		cpuidle_detach_governor(dev);
	if (cpuidle_curr_driver)
		cpuidle_detach_driver(dev);
	cpuidle_remove_sysfs(sys_dev);
	list_del(&dev->device_list);
	wait_for_completion(&dev->kobj_unregister);
	per_cpu(cpuidle_devices, sys_dev->id) = NULL;
	kfree(dev);

	return 0;
}

/**
 * cpuidle_remove_device - detaches the driver from a CPU instance
 * @sys_dev: the system device (driver model CPU representation)
 */
static int cpuidle_remove_device(struct sys_device *sys_dev)
{
	int ret;
	mutex_lock(&cpuidle_lock);
	ret = __cpuidle_remove_device(sys_dev);
	mutex_unlock(&cpuidle_lock);

	return ret;
}

static struct sysdev_driver cpuidle_sysdev_driver = {
	.add		= cpuidle_add_device,
	.remove		= cpuidle_remove_device,
};

static int cpuidle_cpu_callback(struct notifier_block *nfb,
					unsigned long action, void *hcpu)
{
	struct sys_device *sys_dev;

	sys_dev = get_cpu_sysdev((unsigned long)hcpu);

	switch (action) {
	case CPU_ONLINE:
		cpuidle_add_device(sys_dev);
		break;
	case CPU_DOWN_PREPARE:
		mutex_lock(&cpuidle_lock);
		break;
	case CPU_DEAD:
		__cpuidle_remove_device(sys_dev);
		mutex_unlock(&cpuidle_lock);
		break;
	case CPU_DOWN_FAILED:
		mutex_unlock(&cpuidle_lock);
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata cpuidle_cpu_notifier =
{
    .notifier_call = cpuidle_cpu_callback,
};

#ifdef CONFIG_SMP

static void smp_callback(void *v)
{
	/* we already woke the CPU up, nothing more to do */
}

/*
 * This function gets called when a part of the kernel has a new latency
 * requirement.  This means we need to get all processors out of their C-state,
 * and then recalculate a new suitable C-state. Just do a cross-cpu IPI; that
 * wakes them all right up.
 */
static int cpuidle_latency_notify(struct notifier_block *b,
		unsigned long l, void *v)
{
	smp_call_function(smp_callback, NULL, 0, 1);
	return NOTIFY_OK;
}

static struct notifier_block cpuidle_latency_notifier = {
	.notifier_call = cpuidle_latency_notify,
};

#define latency_notifier_init(x) do { register_latency_notifier(x); } while (0)

#else /* CONFIG_SMP */

#define latency_notifier_init(x) do { } while (0)

#endif /* CONFIG_SMP */

/**
 * cpuidle_init - core initializer
 */
static int __init cpuidle_init(void)
{
	int ret;

	pm_idle_old = pm_idle;

	ret = cpuidle_add_class_sysfs(&cpu_sysdev_class);
	if (ret)
		return ret;

	register_hotcpu_notifier(&cpuidle_cpu_notifier);

	ret = sysdev_driver_register(&cpu_sysdev_class, &cpuidle_sysdev_driver);

	if (ret) {
		cpuidle_remove_class_sysfs(&cpu_sysdev_class);
		printk(KERN_ERR "cpuidle: failed to initialize\n");
		return ret;
	}

	latency_notifier_init(&cpuidle_latency_notifier);

	return 0;
}

core_initcall(cpuidle_init);
