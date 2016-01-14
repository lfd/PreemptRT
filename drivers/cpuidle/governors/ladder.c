/*
 * ladder.c - the residency ladder algorithm
 *
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2004, 2005 Dominik Brodowski <linux@brodo.de>
 *
 * (C) 2006-2007 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *               Shaohua Li <shaohua.li@intel.com>
 *               Adam Belay <abelay@novell.com>
 *
 * This code is licenced under the GPL.
 */

#include <linux/kernel.h>
#include <linux/cpuidle.h>
#include <linux/latency.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>

#include <asm/io.h>
#include <asm/uaccess.h>

#define PROMOTION_COUNT 4
#define DEMOTION_COUNT 1

/*
 * bm_history -- bit-mask with a bit per jiffy of bus-master activity
 * 1000 HZ: 0xFFFFFFFF: 32 jiffies = 32ms
 * 800 HZ: 0xFFFFFFFF: 32 jiffies = 40ms
 * 100 HZ: 0x0000000F: 4 jiffies = 40ms
 * reduce history for more aggressive entry into C3
 */
static unsigned int bm_history __read_mostly =
    (HZ >= 800 ? 0xFFFFFFFF : ((1U << (HZ / 25)) - 1));
module_param(bm_history, uint, 0644);

struct ladder_device_state {
	struct {
		u32 promotion_count;
		u32 demotion_count;
		u32 promotion_time;
		u32 demotion_time;
		u32 bm;
	} threshold;
	struct {
		int promotion_count;
		int demotion_count;
	} stats;
};

struct ladder_device {
	struct ladder_device_state states[CPUIDLE_STATE_MAX];
	int bm_check:1;
	unsigned long bm_check_timestamp;
	unsigned long bm_activity; /* FIXME: bm activity should be global */
	int last_state_idx;
};

/**
 * ladder_do_selection - prepares private data for a state change
 * @ldev: the ladder device
 * @old_idx: the current state index
 * @new_idx: the new target state index
 */
static inline void ladder_do_selection(struct ladder_device *ldev,
				       int old_idx, int new_idx)
{
	ldev->states[old_idx].stats.promotion_count = 0;
	ldev->states[old_idx].stats.demotion_count = 0;
	ldev->last_state_idx = new_idx;
}

/**
 * ladder_select_state - selects the next state to enter
 * @dev: the CPU
 */
static int ladder_select_state(struct cpuidle_device *dev)
{
	struct ladder_device *ldev = dev->governor_data;
	struct ladder_device_state *last_state;
	int last_residency, last_idx = ldev->last_state_idx;

	if (unlikely(!ldev))
		return 0;

	last_state = &ldev->states[last_idx];

	/* demote if within BM threshold */
	if (ldev->bm_check) {
		unsigned long diff;

		diff = jiffies - ldev->bm_check_timestamp;
		if (diff > 31)
			diff = 31;

		ldev->bm_activity <<= diff;
		if (cpuidle_get_bm_activity())
			ldev->bm_activity |= ((1 << diff) - 1);

		ldev->bm_check_timestamp = jiffies;
		if ((last_idx > 0) &&
		    (last_state->threshold.bm & ldev->bm_activity)) {
			ladder_do_selection(ldev, last_idx, last_idx - 1);
			return last_idx - 1;
		}
	}

	if (dev->states[last_idx].flags & CPUIDLE_FLAG_TIME_VALID)
		last_residency = cpuidle_get_last_residency(dev) - dev->states[last_idx].exit_latency;
	else
		last_residency = last_state->threshold.promotion_time + 1;

	/* consider promotion */
	if (last_idx < dev->state_count - 1 &&
	    last_residency > last_state->threshold.promotion_time &&
	    dev->states[last_idx + 1].exit_latency <= system_latency_constraint()) {
		last_state->stats.promotion_count++;
		last_state->stats.demotion_count = 0;
		if (last_state->stats.promotion_count >= last_state->threshold.promotion_count) {
			ladder_do_selection(ldev, last_idx, last_idx + 1);
			return last_idx + 1;
		}
	}

	/* consider demotion */
	if (last_idx > 0 &&
	    last_residency < last_state->threshold.demotion_time) {
		last_state->stats.demotion_count++;
		last_state->stats.promotion_count = 0;
		if (last_state->stats.demotion_count >= last_state->threshold.demotion_count) {
			ladder_do_selection(ldev, last_idx, last_idx - 1);
			return last_idx - 1;
		}
	}

	/* otherwise remain at the current state */
	return last_idx;
}

/**
 * ladder_scan_device - scans a CPU's states and does setup
 * @dev: the CPU
 */
static void ladder_scan_device(struct cpuidle_device *dev)
{
	int i, bm_check = 0;
	struct ladder_device *ldev = dev->governor_data;
	struct ladder_device_state *lstate;
	struct cpuidle_state *state;

	ldev->last_state_idx = 0;
	ldev->bm_check_timestamp = 0;
	ldev->bm_activity = 0;

	for (i = 0; i < dev->state_count; i++) {
		state = &dev->states[i];
		lstate = &ldev->states[i];

		lstate->stats.promotion_count = 0;
		lstate->stats.demotion_count = 0;

		lstate->threshold.promotion_count = PROMOTION_COUNT;
		lstate->threshold.demotion_count = DEMOTION_COUNT;

		if (i < dev->state_count - 1)
			lstate->threshold.promotion_time = state->exit_latency;
		if (i > 0)
			lstate->threshold.demotion_time = state->exit_latency;
		if (state->flags & CPUIDLE_FLAG_CHECK_BM) {
			lstate->threshold.bm = bm_history;
			bm_check = 1;
		} else
			lstate->threshold.bm = 0;
	}

	ldev->bm_check = bm_check;
}

/**
 * ladder_init_device - initializes a CPU-instance
 * @dev: the CPU
 */
static int ladder_init_device(struct cpuidle_device *dev)
{
	dev->governor_data = kmalloc(sizeof(struct ladder_device), GFP_KERNEL);

	return !dev->governor_data;
}

/**
 * ladder_exit_device - exits a CPU-instance
 * @dev: the CPU
 */
static void ladder_exit_device(struct cpuidle_device *dev)
{
	kfree(dev->governor_data);
}

static struct cpuidle_governor ladder_governor = {
	.name =		"ladder",
	.init =		ladder_init_device,
	.exit =		ladder_exit_device,
	.scan =		ladder_scan_device,
	.select_state =	ladder_select_state,
	.owner =	THIS_MODULE,
};

/**
 * init_ladder - initializes the governor
 */
static int __init init_ladder(void)
{
	return cpuidle_register_governor(&ladder_governor);
}

/**
 * exit_ladder - exits the governor
 */
static void __exit exit_ladder(void)
{
	cpuidle_unregister_governor(&ladder_governor);
}

MODULE_LICENSE("GPL");
module_init(init_ladder);
module_exit(exit_ladder);
