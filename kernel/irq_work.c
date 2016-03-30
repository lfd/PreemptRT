/*
 * Copyright (C) 2010 Red Hat, Inc., Peter Zijlstra <pzijlstr@redhat.com>
 *
 * Provides a framework for enqueueing and running callbacks from hardirq
 * context. The enqueueing is NMI-safe.
 */

#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/irq_work.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/irqflags.h>
#include <linux/sched.h>
#include <linux/tick.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/smp.h>
#include <asm/processor.h>


static DEFINE_PER_CPU(struct llist_head, raised_list);
static DEFINE_PER_CPU(struct llist_head, lazy_list);
#ifdef CONFIG_PREEMPT_RT_FULL
static DEFINE_PER_CPU(struct llist_head, hirq_work_list);
#endif
/*
 * Claim the entry so that no one else will poke at it.
 */
static bool irq_work_claim(struct irq_work *work)
{
	unsigned long flags, oflags, nflags;

	/*
	 * Start with our best wish as a premise but only trust any
	 * flag value after cmpxchg() result.
	 */
	flags = work->flags & ~IRQ_WORK_PENDING;
	for (;;) {
		nflags = flags | IRQ_WORK_FLAGS;
		oflags = cmpxchg(&work->flags, flags, nflags);
		if (oflags == flags)
			break;
		if (oflags & IRQ_WORK_PENDING)
			return false;
		flags = oflags;
		cpu_relax();
	}

	return true;
}

#ifdef CONFIG_PREEMPT_RT_FULL
void arch_irq_work_raise(void)
#else
void __weak arch_irq_work_raise(void)
#endif
{
	/*
	 * Lame architectures will get the timer tick callback
	 */
}

#ifdef CONFIG_SMP
/*
 * Enqueue the irq_work @work on @cpu unless it's already pending
 * somewhere.
 *
 * Can be re-enqueued while the callback is still in progress.
 */
bool irq_work_queue_on(struct irq_work *work, int cpu)
{
	bool raise_irqwork;

	/* All work should have been flushed before going offline */
	WARN_ON_ONCE(cpu_is_offline(cpu));

	/* Arch remote IPI send/receive backend aren't NMI safe */
	WARN_ON_ONCE(in_nmi());

	/* Only queue if not already pending */
	if (!irq_work_claim(work))
		return false;

#ifdef CONFIG_PREEMPT_RT_FULL
	if (work->flags & IRQ_WORK_HARD_IRQ)
		raise_irqwork = llist_add(&work->llnode,
					  &per_cpu(hirq_work_list, cpu));
	else
		raise_irqwork = llist_add(&work->llnode,
					  &per_cpu(lazy_list, cpu));
#else
		raise_irqwork = llist_add(&work->llnode,
					  &per_cpu(raised_list, cpu));
#endif

	if (raise_irqwork)
		arch_send_call_function_single_ipi(cpu);

	return true;
}
EXPORT_SYMBOL_GPL(irq_work_queue_on);
#endif

/* Enqueue the irq work @work on the current CPU */
bool irq_work_queue(struct irq_work *work)
{
	/* Only queue if not already pending */
	if (!irq_work_claim(work))
		return false;

	/* Queue the entry and raise the IPI if needed. */
	preempt_disable();

#ifdef CONFIG_PREEMPT_RT_FULL
	if (work->flags & IRQ_WORK_HARD_IRQ) {
		if (llist_add(&work->llnode, this_cpu_ptr(&hirq_work_list)))
			arch_irq_work_raise();
	} else {
		if (llist_add(&work->llnode, this_cpu_ptr(&lazy_list)))
			arch_irq_work_raise();
	}
#else
	if (work->flags & IRQ_WORK_LAZY) {
		if (llist_add(&work->llnode, this_cpu_ptr(&lazy_list)) &&
		    tick_nohz_tick_stopped())
			arch_irq_work_raise();
	} else {
		if (llist_add(&work->llnode, this_cpu_ptr(&raised_list)))
			arch_irq_work_raise();
	}
#endif

	preempt_enable();

	return true;
}
EXPORT_SYMBOL_GPL(irq_work_queue);

bool irq_work_needs_cpu(void)
{
	struct llist_head *raised, *lazy;

	raised = this_cpu_ptr(&raised_list);
	lazy = this_cpu_ptr(&lazy_list);

	if (llist_empty(raised))
		if (llist_empty(lazy))
#ifdef CONFIG_PREEMPT_RT_FULL
			if (llist_empty(this_cpu_ptr(&hirq_work_list)))
#endif
				return false;

	/* All work should have been flushed before going offline */
	WARN_ON_ONCE(cpu_is_offline(smp_processor_id()));

	return true;
}

static void irq_work_run_list(struct llist_head *list)
{
	unsigned long flags;
	struct irq_work *work;
	struct llist_node *llnode;

#ifndef CONFIG_PREEMPT_RT_FULL
	BUG_ON(!irqs_disabled());
#endif

	if (llist_empty(list))
		return;

	llnode = llist_del_all(list);
	while (llnode != NULL) {
		work = llist_entry(llnode, struct irq_work, llnode);

		llnode = llist_next(llnode);

		/*
		 * Clear the PENDING bit, after this point the @work
		 * can be re-used.
		 * Make it immediately visible so that other CPUs trying
		 * to claim that work don't rely on us to handle their data
		 * while we are in the middle of the func.
		 */
		flags = work->flags & ~IRQ_WORK_PENDING;
		xchg(&work->flags, flags);

		work->func(work);
		/*
		 * Clear the BUSY bit and return to the free state if
		 * no-one else claimed it meanwhile.
		 */
		(void)cmpxchg(&work->flags, flags, flags & ~IRQ_WORK_BUSY);
	}
}

/*
 * hotplug calls this through:
 *  hotplug_cfd() -> flush_smp_call_function_queue()
 */
void irq_work_run(void)
{
#ifdef CONFIG_PREEMPT_RT_FULL
	if (in_irq()) {
		irq_work_run_list(this_cpu_ptr(&hirq_work_list));
		return;
	}
#endif
	irq_work_run_list(this_cpu_ptr(&raised_list));
	irq_work_run_list(this_cpu_ptr(&lazy_list));
}
EXPORT_SYMBOL_GPL(irq_work_run);

void irq_work_tick(void)
{
	struct llist_head *raised;

#ifdef CONFIG_PREEMPT_RT_FULL
	if (in_irq()) {
		irq_work_run_list(this_cpu_ptr(&hirq_work_list));
		return;
	}
#endif
	raised = &__get_cpu_var(raised_list);
	if (!llist_empty(raised))
		irq_work_run_list(raised);
	irq_work_run_list(&__get_cpu_var(lazy_list));
}

/*
 * Synchronize against the irq_work @entry, ensures the entry is not
 * currently in use.
 */
void irq_work_sync(struct irq_work *work)
{
	WARN_ON_ONCE(irqs_disabled());

	while (work->flags & IRQ_WORK_BUSY)
		cpu_relax();
}
EXPORT_SYMBOL_GPL(irq_work_sync);
