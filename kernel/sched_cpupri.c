/*
 *  kernel/sched_cpupri.c
 *
 *  CPU priority management
 *
 *  Copyright (C) 2007 Novell
 *
 *  Author: Gregory Haskins <ghaskins@novell.com>
 *
 *  This code tracks the priority of each CPU so that global migration
 *  decisions are easy to calculate.  Each CPU can be in a state as follows:
 *
 *                 (INVALID), IDLE, NORMAL, RT1, ... RT99
 *
 *  going from the lowest priority to the highest.  CPUs in the INVALID state
 *  are not eligible for routing.  The system maintains this state with
 *  a 2 dimensional bitmap (the first for priority class, the second for cpus
 *  in that class).  Therefore a typical application without affinity
 *  restrictions can find a suitable CPU with O(1) complexity (e.g. two bit
 *  searches).  For tasks with affinity restrictions, the algorithm has a
 *  worst case complexity of O(min(102, NR_CPUS)), though the scenario that
 *  yields the worst case search is fairly contrived.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; version 2
 *  of the License.
 */

#include "sched_cpupri.h"

#define CPUPRI_NR_PRIORITIES 2+MAX_RT_PRIO
#define CPUPRI_NR_PRI_WORDS CPUPRI_NR_PRIORITIES/BITS_PER_LONG

#define CPUPRI_INVALID -1
#define CPUPRI_IDLE     0
#define CPUPRI_NORMAL   1
/* values 2-101 are RT priorities 0-99 */

struct pri_vec
{
	raw_spinlock_t lock;
	cpumask_t      mask;
};

struct cpu_priority {
	struct pri_vec pri_to_cpu[CPUPRI_NR_PRIORITIES];
	long           pri_active[CPUPRI_NR_PRI_WORDS];
	int            cpu_to_pri[NR_CPUS];
};

static __cacheline_aligned_in_smp struct cpu_priority cpu_priority;

/* Convert between a 140 based task->prio, and our 102 based cpupri */
static int convert_prio(int prio)
{
	int cpupri;

	if (prio == MAX_PRIO)
		cpupri = CPUPRI_IDLE;
	else if (prio >= MAX_RT_PRIO)
		cpupri = CPUPRI_NORMAL;
	else
		cpupri = MAX_RT_PRIO - prio + 1;

	return cpupri;
}

#define for_each_cpupri_active(array, idx)                    \
  for (idx = find_first_bit(array, CPUPRI_NR_PRIORITIES);     \
       idx < CPUPRI_NR_PRIORITIES;                            \
       idx = find_next_bit(array, CPUPRI_NR_PRIORITIES, idx+1))

/**
 * cpupri_find - find the best (lowest-pri) CPU in the system
 * @p: The task
 * @lowest_mask: A mask to fill in with selected CPUs
 *
 * Note: This function returns the recommended CPUs as calculated during the
 * current invokation.  By the time the call returns, the CPUs may have in
 * fact changed priorities any number of times.  While not ideal, it is not
 * an issue of correctness since the normal rebalancer logic will correct
 * any discrepancies created by racing against the uncertainty of the current
 * priority configuration.
 *
 * Returns: (int)bool - CPUs were found
 */
int cpupri_find(struct task_struct *p, cpumask_t *lowest_mask)
{
	int                  idx      = 0;
	struct cpu_priority *cp       = &cpu_priority;
	int                  task_pri = convert_prio(p->prio);

	for_each_cpupri_active(cp->pri_active, idx) {
		struct pri_vec *vec  = &cp->pri_to_cpu[idx];
		cpumask_t mask;

		if (idx >= task_pri)
			break;

		cpus_and(mask, p->cpus_allowed, vec->mask);

		if (cpus_empty(mask))
			continue;

		*lowest_mask = mask;
		return 1;
	}

	return 0;
}

/**
 * cpupri_set - update the cpu priority setting
 * @cpu: The target cpu
 * @pri: The priority (INVALID-RT99) to assign to this CPU
 *
 * Note: Assumes cpu_rq(cpu)->lock is locked
 *
 * Returns: (void)
 */
void cpupri_set(int cpu, int newpri)
{
	struct cpu_priority *cp      = &cpu_priority;
	int                 *currpri = &cp->cpu_to_pri[cpu];
	int                  oldpri  = *currpri;
	unsigned long        flags;

	newpri = convert_prio(newpri);

	if (newpri == oldpri)
		return;

	/*
	 * If the cpu was currently mapped to a different value, we
	 * first need to unmap the old value
	 */
	if (likely(oldpri != CPUPRI_INVALID)) {
		struct pri_vec *vec  = &cp->pri_to_cpu[oldpri];

		spin_lock_irqsave(&vec->lock, flags);

		cpu_clear(cpu, vec->mask);
		if (cpus_empty(vec->mask))
			clear_bit(oldpri, cp->pri_active);

		spin_unlock_irqrestore(&vec->lock, flags);
	}

	if (likely(newpri != CPUPRI_INVALID)) {
		struct pri_vec *vec = &cp->pri_to_cpu[newpri];

		spin_lock_irqsave(&vec->lock, flags);

		cpu_set(cpu, vec->mask);
		set_bit(newpri, cp->pri_active);

		spin_unlock_irqrestore(&vec->lock, flags);
	}

	*currpri = newpri;
}

/**
 * cpupri_init - initialize the cpupri subsystem
 *
 * This must be called during the scheduler initialization before the
 * other methods may be used.
 *
 * Returns: (void)
 */
void cpupri_init(void)
{
	struct cpu_priority *cp = &cpu_priority;
	int i;

	memset(cp, 0, sizeof(*cp));

	for (i = 0; i < CPUPRI_NR_PRIORITIES; i++)
		spin_lock_init(&cp->pri_to_cpu[i].lock);

	for_each_possible_cpu(i)
		cp->cpu_to_pri[i] = CPUPRI_INVALID;
}


