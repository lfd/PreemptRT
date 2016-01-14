/*
 * trace task events
 *
 * Copyright (C) 2007 Steven Rostedt <srostedt@redhat.com>
 *
 * Based on code from the latency_tracer, that is:
 *
 *  Copyright (C) 2004-2006 Ingo Molnar
 *  Copyright (C) 2004 William Lee Irwin III
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>

#include "trace.h"

int	ftrace_events_enabled __read_mostly;

static struct trace_array	*events_trace __read_mostly;

static void event_reset(struct trace_array *tr)
{
	struct trace_array_cpu *data;
	int cpu;

	for_each_possible_cpu(cpu) {
		data = tr->data[cpu];
		tracing_reset(data);
	}

	tr->time_start = ftrace_now(raw_smp_processor_id());
}

void trace_event_sched_switch(struct task_struct *prev,
			      struct task_struct *next)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	long disabled;
	int cpu;

	if (!ftrace_events_enabled || !tr)
		return;

	local_irq_save(flags);
	cpu = raw_smp_processor_id();
	data = tr->data[cpu];

	disabled = atomic_inc_return(&data->disabled);
	if (unlikely(disabled != 1))
		goto out;

	tracing_sched_switch_trace(tr, data, prev, next, flags);

 out:
	atomic_dec(&data->disabled);
	local_irq_restore(flags);
}

/* Taken from sched.c */
#define __PRIO(prio) \
	((prio) <= 99 ? 199 - (prio) : (prio) - 120)

#define PRIO(p) __PRIO((p)->prio)

void trace_event_wakeup(struct task_struct *wakee,
			struct task_struct *curr)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags, ip;
	long disabled;
	int cpu;

	if (!ftrace_events_enabled || !tr)
		return;

	ip = CALLER_ADDR0;

	local_irq_save(flags);
	cpu = raw_smp_processor_id();
	data = tr->data[cpu];

	disabled = atomic_inc_return(&data->disabled);
	if (unlikely(disabled != 1))
		goto out;

	/* record process's command line */
	tracing_record_cmdline(wakee);
	tracing_record_cmdline(curr);
	tracing_event_wakeup(tr, data, flags, ip, wakee->pid, PRIO(wakee), PRIO(curr));

 out:
	atomic_dec(&data->disabled);
	local_irq_restore(flags);
}

#define getarg(arg, ap) arg = va_arg(ap, typeof(arg));

/* HACK */
void notrace
sys_call(unsigned long nr, unsigned long p1, unsigned long p2, unsigned long p3)
{
	struct trace_array *tr;
	struct trace_array_cpu *data;
	unsigned long flags;
	unsigned long ip;
	int cpu;

	if (!ftrace_events_enabled || !events_trace)
		return;

	tr = events_trace;
	local_irq_save(flags);
	cpu = raw_smp_processor_id();
	data = tr->data[cpu];

	atomic_inc(&data->disabled);
	if (atomic_read(&data->disabled) != 1)
		goto out;

	ip = CALLER_ADDR0;

	tracing_event_syscall(tr, data, flags, ip, nr, p1, p2, p3);

 out:
	atomic_dec(&data->disabled);
	local_irq_restore(flags);
}

#if defined(CONFIG_COMPAT) && defined(CONFIG_X86)
void notrace
sys_ia32_call(unsigned long nr, unsigned long p1, unsigned long p2,
	      unsigned long p3)
{
	struct trace_array *tr;
	struct trace_array_cpu *data;
	unsigned long flags;
	unsigned long ip;
	int cpu;

	if (!ftrace_events_enabled || !events_trace)
		return;

	tr = events_trace;
	local_irq_save(flags);
	cpu = raw_smp_processor_id();
	data = tr->data[cpu];

	atomic_inc(&data->disabled);
	if (atomic_read(&data->disabled) != 1)
		goto out;

	ip = CALLER_ADDR0;
	tracing_event_syscall(tr, data, flags, ip, nr | 0x80000000, p1, p2, p3);

 out:
	atomic_dec(&data->disabled);
	local_irq_restore(flags);
}
#endif

void notrace
sys_ret(unsigned long ret)
{
	struct trace_array *tr;
	struct trace_array_cpu *data;
	unsigned long flags;
	unsigned long ip;
	int cpu;

	if (!ftrace_events_enabled || !events_trace)
		return;

	tr = events_trace;
	local_irq_save(flags);
	cpu = raw_smp_processor_id();
	data = tr->data[cpu];

	atomic_inc(&data->disabled);
	if (atomic_read(&data->disabled) != 1)
		goto out;

	ip = CALLER_ADDR0;
	tracing_event_sysret(tr, data, flags, ip, ret);

 out:
	atomic_dec(&data->disabled);
	local_irq_restore(flags);
}

void ftrace_record_event(enum ftrace_event_enum event, ...)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	unsigned long ip;
	long disabled;
	int cpu;
	va_list ap;
	int irq, usermode, prio;
	pid_t pid;
	ktime_t *time;
	void *p1, *p2;
	unsigned long ret_ip, error_code, address, running;


	if (!ftrace_events_enabled || !events_trace)
		return;

	local_irq_save(flags);
	cpu = raw_smp_processor_id();
	data = tr->data[cpu];

	disabled = atomic_inc_return(&data->disabled);
	if (unlikely(disabled != 1))
		goto out;

	ip = CALLER_ADDR0;

	va_start(ap, event);
	switch (event) {
	case FTRACE_EVENTS_IRQ:
		getarg(irq, ap);
		getarg(usermode, ap);
		getarg(ret_ip, ap);
		tracing_event_irq(tr, data, flags, ip, irq, usermode, ret_ip);
		break;
	case FTRACE_EVENTS_FAULT:
		getarg(ret_ip, ap);
		getarg(error_code, ap);
		getarg(address, ap);
		tracing_event_fault(tr, data, flags, ip, ret_ip, error_code, address);
		break;
	case FTRACE_EVENTS_TIMER:
		getarg(p1, ap);
		getarg(p2, ap);
		tracing_event_timer(tr, data, flags, ip, p1, p2);
		break;
	case FTRACE_EVENTS_TIMESTAMP:
		getarg(time, ap);
		tracing_event_timestamp(tr, data, flags, ip, time);
		break;
	case FTRACE_EVENTS_TASK:
		getarg(pid, ap);
		getarg(prio, ap);
		getarg(running, ap);
		tracing_event_task(tr, data, flags, ip, pid, prio, running);
		break;
	}
	va_end(ap);

 out:
	atomic_dec(&data->disabled);
	local_irq_restore(flags);
}

static void start_event_trace(struct trace_array *tr)
{
	event_reset(tr);
	ftrace_events_enabled = 1;
	tracing_start_function_trace();
}

static void stop_event_trace(struct trace_array *tr)
{
	tracing_stop_function_trace();
	ftrace_events_enabled = 0;
}

static void event_trace_init(struct trace_array *tr)
{
	events_trace = tr;

	if (tr->ctrl)
		start_event_trace(tr);
}

static void event_trace_reset(struct trace_array *tr)
{
	if (tr->ctrl)
		stop_event_trace(tr);
}

static void event_trace_ctrl_update(struct trace_array *tr)
{
	if (tr->ctrl)
		start_event_trace(tr);
	else
		stop_event_trace(tr);
}

static void event_trace_open(struct trace_iterator *iter)
{
	/* stop the trace while dumping */
	if (iter->tr->ctrl)
		stop_event_trace(iter->tr);
}

static void event_trace_close(struct trace_iterator *iter)
{
	if (iter->tr->ctrl)
		start_event_trace(iter->tr);
}

static struct tracer event_trace __read_mostly =
{
	.name = "events",
	.init = event_trace_init,
	.reset = event_trace_reset,
	.open = event_trace_open,
	.close = event_trace_close,
	.ctrl_update = event_trace_ctrl_update,
};

void trace_event_register(struct trace_array *tr)
{
	events_trace = tr;
}

void trace_event_unregister(struct trace_array *tr)
{
}

void trace_start_events(void)
{
	ftrace_events_enabled = 1;
}

void trace_stop_events(void)
{
	ftrace_events_enabled = 0;
}

__init static int init_event_trace(void)
{
	int ret;

	ret = register_tracer(&event_trace);
	if (ret)
		return ret;

	return 0;
}

device_initcall(init_event_trace);
