/*
 * Infrastructure for profiling code inserted by 'gcc -pg'.
 *
 * Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
 *
 * Converted to be more generic:
 *   Copyright (C) 2007-2008 Steven Rostedt <srostedt@redhat.com>
 *
 * From code in the latency_tracer, that is:
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

mcount_func_t mcount_trace_function __read_mostly = dummy_mcount_tracer;
int mcount_enabled __read_mostly;
EXPORT_SYMBOL_GPL(mcount);
/*
 * The above EXPORT_SYMBOL is for the gcc call of mcount
 * I put the export under mcount_enabled to fool checkpatch.pl.
 * It wants that export to be with the function, but that function
 * happens to be in assembly.
 */

/**
 * register_mcount_function - register a function for profiling
 * @func - the function for profiling.
 *
 * Register a function to be called by all functions in the
 * kernel.
 *
 * Note: @func and all the functions it calls must be labeled
 *       with "notrace", otherwise it will go into a
 *       recursive loop.
 */
int register_mcount_function(mcount_func_t func)
{
	mcount_trace_function = func;
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
