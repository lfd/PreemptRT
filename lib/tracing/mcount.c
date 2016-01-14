/*
 * Infrastructure for profiling code inserted by 'gcc -pg'.
 *
 * Copyright (C) 2007-2008 Steven Rostedt <srostedt@redhat.com>
 *
 * Originally ported from the -rt patch by:
 *   Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
 *
 * Based on code in the latency_tracer, that is:
 *
 *  Copyright (C) 2004-2006 Ingo Molnar
 *  Copyright (C) 2004 William Lee Irwin III
 */

#include <linux/module.h>
#include <linux/mcount.h>

/*
 * Since we have nothing protecting between the test of
 * mcount_trace_function and the call to it, we can't
 * set it to NULL without risking a race that will have
 * the kernel call the NULL pointer. Instead, we just
 * set the function pointer to a dummy function.
 */
notrace void dummy_mcount_tracer(unsigned long ip,
				 unsigned long parent_ip)
{
	/* do nothing */
}

static DEFINE_SPINLOCK(mcount_func_lock);
static struct mcount_ops mcount_list_end __read_mostly =
{
	.func = dummy_mcount_tracer,
};

static struct mcount_ops *mcount_list __read_mostly = &mcount_list_end;
mcount_func_t mcount_trace_function __read_mostly = dummy_mcount_tracer;
int mcount_enabled __read_mostly;

/* mcount is defined per arch in assembly */
EXPORT_SYMBOL_GPL(mcount);

notrace void mcount_list_func(unsigned long ip, unsigned long parent_ip)
{
	struct mcount_ops *op = mcount_list;

	while (op != &mcount_list_end) {
		op->func(ip, parent_ip);
		op = op->next;
	};
}

/**
 * register_mcount_function - register a function for profiling
 * @ops - ops structure that holds the function for profiling.
 *
 * Register a function to be called by all functions in the
 * kernel.
 *
 * Note: @ops->func and all the functions it calls must be labeled
 *       with "notrace", otherwise it will go into a
 *       recursive loop.
 */
int register_mcount_function(struct mcount_ops *ops)
{
	unsigned long flags;

	spin_lock_irqsave(&mcount_func_lock, flags);
	ops->next = mcount_list;
	/* must have next seen before we update the list pointer */
	smp_wmb();
	mcount_list = ops;
	/*
	 * For one func, simply call it directly.
	 * For more than one func, call the chain.
	 */
	if (ops->next == &mcount_list_end)
		mcount_trace_function = ops->func;
	else
		mcount_trace_function = mcount_list_func;
	spin_unlock_irqrestore(&mcount_func_lock, flags);

	return 0;
}

/**
 * unregister_mcount_function - unresgister a function for profiling.
 * @ops - ops structure that holds the function to unregister
 *
 * Unregister a function that was added to be called by mcount profiling.
 */
int unregister_mcount_function(struct mcount_ops *ops)
{
	unsigned long flags;
	struct mcount_ops **p;
	int ret = 0;

	spin_lock_irqsave(&mcount_func_lock, flags);

	/*
	 * If we are the only function, then the mcount pointer is
	 * pointing directly to that function.
	 */
	if (mcount_list == ops && ops->next == &mcount_list_end) {
		mcount_trace_function = dummy_mcount_tracer;
		mcount_list = &mcount_list_end;
		goto out;
	}

	for (p = &mcount_list; *p != &mcount_list_end; p = &(*p)->next)
		if (*p == ops)
			break;

	if (*p != ops) {
		ret = -1;
		goto out;
	}

	*p = (*p)->next;

	/* If we only have one func left, then call that directly */
	if (mcount_list->next == &mcount_list_end)
		mcount_trace_function = mcount_list->func;

 out:
	spin_unlock_irqrestore(&mcount_func_lock, flags);

	return 0;
}

/**
 * clear_mcount_function - reset the mcount function
 *
 * This NULLs the mcount function and in essence stops
 * tracing.  There may be lag
 */
void clear_mcount_function(void)
{
	mcount_trace_function = dummy_mcount_tracer;
}
