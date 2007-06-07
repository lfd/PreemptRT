/*
 * Read-Copy Update mechanism for mutual exclusion, realtime implementation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2001
 *
 * Authors: Paul E. McKenney <paulmck@us.ibm.com>
 *		With thanks to Esben Nielsen, Bill Huey, and Ingo Molnar
 *		for pushing me away from locks and towards counters.
 *
 * Papers:  http://www.rdrop.com/users/paulmck/RCU
 *
 * For detailed explanation of Read-Copy Update mechanism see -
 * 		Documentation/RCU/ *.txt
 *
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/rcupdate.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <asm/atomic.h>
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/moduleparam.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/rcupdate.h>
#include <linux/cpu.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/byteorder/swabb.h>
#include <linux/cpumask.h>
#include <linux/rcupreempt_trace.h>

/*
 * PREEMPT_RCU data structures.
 */

struct rcu_data {
	spinlock_t	lock;
	long		completed;	/* Number of last completed batch. */
	struct rcu_head *nextlist;
	struct rcu_head **nexttail;
	struct rcu_head *waitlist;
	struct rcu_head **waittail;
	struct rcu_head *donelist;
	struct rcu_head **donetail;
#ifdef CONFIG_RCU_TRACE
	struct rcupreempt_trace trace;
#endif /* #ifdef CONFIG_RCU_TRACE */
};
struct rcu_ctrlblk {
	spinlock_t	fliplock;
	long		completed;	/* Number of last completed batch. */
};
static struct rcu_data rcu_data;
static struct rcu_ctrlblk rcu_ctrlblk = {
	.fliplock = SPIN_LOCK_UNLOCKED,
	.completed = 0,
};
static DEFINE_PER_CPU(atomic_t [2], rcu_flipctr) =
	{ ATOMIC_INIT(0), ATOMIC_INIT(0) };

/*
 * Return the number of RCU batches processed thus far.  Useful
 * for debug and statistics.
 */
long rcu_batches_completed(void)
{
	return rcu_ctrlblk.completed;
}

void __rcu_read_lock(void)
{
	int flipctr;
	unsigned long oldirq;

	local_irq_save(oldirq);

	if (current->rcu_read_lock_nesting++ == 0) {

		/*
		 * Outermost nesting of rcu_read_lock(), so atomically
		 * increment the current counter for the current CPU.
		 */

		flipctr = rcu_ctrlblk.completed & 0x1;
		smp_read_barrier_depends();
		current->rcu_flipctr1 = &(__get_cpu_var(rcu_flipctr)[flipctr]);
		/* Can optimize to non-atomic on fastpath, but start simple. */
		atomic_inc(current->rcu_flipctr1);
		smp_mb__after_atomic_inc();  /* might optimize out... */
		if (unlikely(flipctr != (rcu_ctrlblk.completed & 0x1))) {

			/*
			 * We raced with grace-period processing (flip).
			 * Although we cannot be preempted here, there
			 * could be interrupts, ECC errors and the like,
			 * so just nail down both sides of the rcu_flipctr
			 * array for the duration of our RCU read-side
			 * critical section, preventing a second flip
			 * from racing with us.  At some point, it would
			 * be safe to decrement one of the counters, but
			 * we have no way of knowing when that would be.
			 * So just decrement them both in rcu_read_unlock().
			 */

			current->rcu_flipctr2 =
				&(__get_cpu_var(rcu_flipctr)[!flipctr]);
			/* Can again optimize to non-atomic on fastpath. */
			atomic_inc(current->rcu_flipctr2);
			smp_mb__after_atomic_inc();  /* might optimize out... */
		}
	}
	local_irq_restore(oldirq);
}

void __rcu_read_unlock(void)
{
	unsigned long oldirq;

	local_irq_save(oldirq);
	if (--current->rcu_read_lock_nesting == 0) {

		/*
		 * Just atomically decrement whatever we incremented.
		 * Might later want to awaken some task waiting for the
		 * grace period to complete, but keep it simple for the
		 * moment.
		 */

		smp_mb__before_atomic_dec();
		atomic_dec(current->rcu_flipctr1);
		current->rcu_flipctr1 = NULL;
		if (unlikely(current->rcu_flipctr2 != NULL)) {
			atomic_dec(current->rcu_flipctr2);
			current->rcu_flipctr2 = NULL;
		}
	}

	local_irq_restore(oldirq);
}

static void __rcu_advance_callbacks(void)
{

	if (rcu_data.completed != rcu_ctrlblk.completed) {
		if (rcu_data.waitlist != NULL) {
			*rcu_data.donetail = rcu_data.waitlist;
			rcu_data.donetail = rcu_data.waittail;
			RCU_TRACE(rcupreempt_trace_move2done, &rcu_data.trace);
		}
		if (rcu_data.nextlist != NULL) {
			rcu_data.waitlist = rcu_data.nextlist;
			rcu_data.waittail = rcu_data.nexttail;
			rcu_data.nextlist = NULL;
			rcu_data.nexttail = &rcu_data.nextlist;
			RCU_TRACE(rcupreempt_trace_move2wait, &rcu_data.trace);
		} else {
			rcu_data.waitlist = NULL;
			rcu_data.waittail = &rcu_data.waitlist;
		}
		rcu_data.completed = rcu_ctrlblk.completed;
	}
}

/*
 * Attempt a single flip of the counters.  Remember, a single flip does
 * -not- constitute a grace period.  Instead, the interval between
 * a pair of consecutive flips is a grace period.
 *
 * If anyone is nuts enough to run this CONFIG_PREEMPT_RCU implementation
 * on a large SMP, they might want to use a hierarchical organization of
 * the per-CPU-counter pairs.
 */
static void rcu_try_flip(void)
{
	int cpu;
	long flipctr;
	unsigned long oldirq;

	flipctr = rcu_ctrlblk.completed;
	RCU_TRACE(rcupreempt_trace_try_flip1, &rcu_data.trace);
	if (unlikely(!spin_trylock_irqsave(&rcu_ctrlblk.fliplock, oldirq))) {
		RCU_TRACE(rcupreempt_trace_try_flip_e1, &rcu_data.trace);
		return;
	}
	if (unlikely(flipctr != rcu_ctrlblk.completed)) {

		/* Our work is done!  ;-) */

		RCU_TRACE(rcupreempt_trace_try_flip_e2, &rcu_data.trace);
		spin_unlock_irqrestore(&rcu_ctrlblk.fliplock, oldirq);
		return;
	}
	flipctr &= 0x1;

	/*
	 * Check for completion of all RCU read-side critical sections
	 * that started prior to the previous flip.
	 */

	RCU_TRACE(rcupreempt_trace_try_flip2, &rcu_data.trace);
	for_each_possible_cpu(cpu) {
		if (atomic_read(&per_cpu(rcu_flipctr, cpu)[!flipctr]) != 0) {
			RCU_TRACE(rcupreempt_trace_try_flip_e3,
							&rcu_data.trace);
			spin_unlock_irqrestore(&rcu_ctrlblk.fliplock, oldirq);
			return;
		}
	}

	/* Do the flip. */

	smp_mb();
	rcu_ctrlblk.completed++;

	RCU_TRACE(rcupreempt_trace_try_flip3, &rcu_data.trace);
	spin_unlock_irqrestore(&rcu_ctrlblk.fliplock, oldirq);
}

void rcu_check_callbacks(int cpu, int user)
{
	unsigned long oldirq;

	if (rcu_ctrlblk.completed == rcu_data.completed) {
		rcu_try_flip();
		if (rcu_ctrlblk.completed == rcu_data.completed) {
			return;
		}
	}
	spin_lock_irqsave(&rcu_data.lock, oldirq);
	RCU_TRACE(rcupreempt_trace_check_callbacks, &rcu_data.trace);
	__rcu_advance_callbacks();
	if (rcu_data.donelist == NULL) {
		spin_unlock_irqrestore(&rcu_data.lock, oldirq);
	} else {
		spin_unlock_irqrestore(&rcu_data.lock, oldirq);
		raise_softirq(RCU_SOFTIRQ);
	}
}

/*
 * Needed by dynticks, to make sure all RCU processing has finished
 * when we go idle:
 */
void rcu_advance_callbacks(int cpu, int user)
{
	unsigned long oldirq;

	if (rcu_ctrlblk.completed == rcu_data.completed) {
		rcu_try_flip();
		if (rcu_ctrlblk.completed == rcu_data.completed) {
			return;
		}
	}
	spin_lock_irqsave(&rcu_data.lock, oldirq);
	RCU_TRACE(rcupreempt_trace_check_callbacks, &rcu_data.trace);
	__rcu_advance_callbacks();
	spin_unlock_irqrestore(&rcu_data.lock, oldirq);
}

void rcu_process_callbacks(struct softirq_action *unused)
{
	unsigned long flags;
	struct rcu_head *next, *list;

	spin_lock_irqsave(&rcu_data.lock, flags);
	list = rcu_data.donelist;
	if (list == NULL) {
		spin_unlock_irqrestore(&rcu_data.lock, flags);
		return;
	}
	rcu_data.donelist = NULL;
	rcu_data.donetail = &rcu_data.donelist;
	RCU_TRACE(rcupreempt_trace_done_remove, &rcu_data.trace);
	spin_unlock_irqrestore(&rcu_data.lock, flags);
	while (list) {
		next = list->next;
		list->func(list);
		list = next;
		RCU_TRACE(rcupreempt_trace_invoke, &rcu_data.trace);
	}
}

void fastcall call_rcu(struct rcu_head *head,
				void (*func)(struct rcu_head *rcu))
{
	unsigned long flags;

	head->func = func;
	head->next = NULL;
	spin_lock_irqsave(&rcu_data.lock, flags);
	__rcu_advance_callbacks();
	*rcu_data.nexttail = head;
	rcu_data.nexttail = &head->next;
	RCU_TRACE(rcupreempt_trace_next_add, &rcu_data.trace);
	spin_unlock_irqrestore(&rcu_data.lock, flags);
}

/*
 * Crude hack, reduces but does not eliminate possibility of failure.
 * Needs to wait for all CPUs to pass through a -voluntary- context
 * switch to eliminate possibility of failure.  (Maybe just crank
 * priority down...)
 */
void __synchronize_sched(void)
{
	cpumask_t oldmask;
	int cpu;

	if (sched_getaffinity(0, &oldmask) < 0) {
		oldmask = cpu_possible_map;
	}
	for_each_online_cpu(cpu) {
		sched_setaffinity(0, cpumask_of_cpu(cpu));
		schedule();
	}
	sched_setaffinity(0, oldmask);
}

/*
 * Check to see if any future RCU-related work will need to be done
 * by the current CPU, even if none need be done immediately, returning
 * 1 if so.  This function is part of the RCU implementation; it is -not-
 * an exported member of the RCU API.
 */
int rcu_needs_cpu(int cpu)
{
	return !!rcu_data.waitlist || rcu_pending(cpu);
}

int rcu_pending(int cpu)
{
	return (rcu_data.donelist != NULL ||
		rcu_data.waitlist != NULL ||
		rcu_data.nextlist != NULL);
}

void __init __rcu_init(void)
{
/*&&&&*/printk("WARNING: experimental RCU implementation.\n");
	spin_lock_init(&rcu_data.lock);
	rcu_data.completed = 0;
	rcu_data.nextlist = NULL;
	rcu_data.nexttail = &rcu_data.nextlist;
	rcu_data.waitlist = NULL;
	rcu_data.waittail = &rcu_data.waitlist;
	rcu_data.donelist = NULL;
	rcu_data.donetail = &rcu_data.donelist;
	open_softirq(RCU_SOFTIRQ, rcu_process_callbacks, NULL);
}

/*
 * Deprecated, use synchronize_rcu() or synchronize_sched() instead.
 */
void synchronize_kernel(void)
{
	synchronize_rcu();
}

#ifdef CONFIG_RCU_TRACE
int rcu_read_proc_data(char *page)
{
	struct rcupreempt_trace *trace = &rcu_data.trace;
	return sprintf(page,
		       "ggp=%ld lgp=%ld rcc=%ld\n"
		       "na=%ld nl=%ld wa=%ld wl=%ld da=%ld dl=%ld dr=%ld di=%d\n"
		       "rtf1=%d rtf2=%ld rtf3=%ld rtfe1=%d rtfe2=%ld rtfe3=%ld\n",

		       rcu_ctrlblk.completed,
		       rcu_data.completed,
		       trace->rcu_check_callbacks,

		       trace->next_add,
		       trace->next_length,
		       trace->wait_add,
		       trace->wait_length,
		       trace->done_add,
		       trace->done_length,
		       trace->done_remove,
		       atomic_read(&trace->done_invoked),

		       atomic_read(&trace->rcu_try_flip1),
		       trace->rcu_try_flip2,
		       trace->rcu_try_flip3,
		       atomic_read(&trace->rcu_try_flip_e1),
		       trace->rcu_try_flip_e2,
		       trace->rcu_try_flip_e3);
}

int rcu_read_proc_gp_data(char *page)
{
	long oldgp = rcu_ctrlblk.completed;

	synchronize_rcu();
	return sprintf(page, "oldggp=%ld  newggp=%ld\n",
		       oldgp, rcu_ctrlblk.completed);
}

int rcu_read_proc_ptrs_data(char *page)
{
	return sprintf(page,
		       "nl=%p/%p nt=%p\n wl=%p/%p wt=%p dl=%p/%p dt=%p\n",
		       &rcu_data.nextlist, rcu_data.nextlist, rcu_data.nexttail,
		       &rcu_data.waitlist, rcu_data.waitlist, rcu_data.waittail,
		       &rcu_data.donelist, rcu_data.donelist, rcu_data.donetail
		      );
}

int rcu_read_proc_ctrs_data(char *page)
{
	int cnt = 0;
	int cpu;
	int f = rcu_data.completed & 0x1;

	cnt += sprintf(&page[cnt], "CPU last cur\n");
	for_each_online_cpu(cpu) {
		cnt += sprintf(&page[cnt], "%3d %4d %3d\n",
			       cpu,
			       atomic_read(&per_cpu(rcu_flipctr, cpu)[!f]),
			       atomic_read(&per_cpu(rcu_flipctr, cpu)[f]));
	}
	cnt += sprintf(&page[cnt], "ggp = %ld\n", rcu_data.completed);
	return (cnt);
}

#endif /* #ifdef CONFIG_RCU_TRACE */

EXPORT_SYMBOL_GPL(call_rcu);
EXPORT_SYMBOL_GPL(rcu_batches_completed);
EXPORT_SYMBOL_GPL(__synchronize_sched);
EXPORT_SYMBOL_GPL(__rcu_read_lock);
EXPORT_SYMBOL_GPL(__rcu_read_unlock);

