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

#include <trace/sched.h>

#include "trace.h"

static struct trace_array __read_mostly	*events_trace;
static int __read_mostly	tracer_enabled;
static atomic_t			event_ref;

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

/* HACK */
void notrace
sys_call(unsigned long nr, unsigned long p1, unsigned long p2, unsigned long p3)
{
	struct trace_array *tr;
	struct trace_array_cpu *data;
	unsigned long flags;
	unsigned long ip;
	int cpu;

	if (!tracer_enabled || function_trace_stop)
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

	if (!tracer_enabled || function_trace_stop)
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

	if (!tracer_enabled || function_trace_stop)
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

static void
event_irq_callback(int irq, int user, unsigned long ip)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	int cpu;
	long disable;

	if (!tracer_enabled || function_trace_stop)
		return;

	/* interrupts should be off, we are in an interrupt */
	cpu = smp_processor_id();
	data = tr->data[cpu];

	disable = atomic_inc_return(&data->disabled);
	if (disable != 1)
		goto out;

	local_save_flags(flags);
	tracing_event_irq(tr, data, flags, CALLER_ADDR1, irq, user, ip);

 out:
	atomic_dec(&data->disabled);
}

static void
event_fault_callback(unsigned long ip, unsigned long error, unsigned long addr)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	long disable;
	int cpu;

	if (!tracer_enabled || function_trace_stop)
		return;

	preempt_disable_notrace();
	cpu = smp_processor_id();
	data = tr->data[cpu];

	disable = atomic_inc_return(&data->disabled);
	if (disable != 1)
		goto out;

	local_save_flags(flags);
	tracing_event_fault(tr, data, flags, CALLER_ADDR1, ip, error, addr);

 out:
	atomic_dec(&data->disabled);
	preempt_enable_notrace();
}

static void
event_timer_set_callback(ktime_t *expires, struct hrtimer *timer)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	long disable;
	int cpu;

	if (!tracer_enabled || function_trace_stop)
		return;

	/* interrupts should be off, we are in an interrupt */
	cpu = smp_processor_id();
	data = tr->data[cpu];

	disable = atomic_inc_return(&data->disabled);
	if (disable != 1)
		goto out;

	local_save_flags(flags);
	tracing_event_timer_set(tr, data, flags, CALLER_ADDR1, expires, timer);

 out:
	atomic_dec(&data->disabled);
}

static void
event_timer_triggered_callback(ktime_t *expires, struct hrtimer *timer)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	long disable;
	int cpu;

	if (!tracer_enabled || function_trace_stop)
		return;

	/* interrupts should be off, we are in an interrupt */
	cpu = smp_processor_id();
	data = tr->data[cpu];

	disable = atomic_inc_return(&data->disabled);
	if (disable != 1)
		goto out;

	local_save_flags(flags);
	tracing_event_timer_triggered(tr, data, flags, CALLER_ADDR1, expires, timer);

 out:
	atomic_dec(&data->disabled);
}

static void
event_hrtimer_callback(ktime_t *time)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	long disable;
	int cpu;

	if (!tracer_enabled || function_trace_stop)
		return;

	/* interrupts should be off, we are in an interrupt */
	cpu = smp_processor_id();
	data = tr->data[cpu];

	disable = atomic_inc_return(&data->disabled);
	if (disable != 1)
		goto out;

	local_save_flags(flags);
	tracing_event_timestamp(tr, data, flags, CALLER_ADDR1, time);

 out:
	atomic_dec(&data->disabled);
}

static void
event_program_event_callback(ktime_t *expires, int64_t *delta)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	long disable;
	int cpu;

	if (!tracer_enabled || function_trace_stop)
		return;

	/* interrupts should be off, we are in an interrupt */
	cpu = smp_processor_id();
	data = tr->data[cpu];

	disable = atomic_inc_return(&data->disabled);
	if (disable != 1)
		goto out;

	local_save_flags(flags);
	tracing_event_program_event(tr, data, flags, CALLER_ADDR1, expires, delta);

 out:
	atomic_dec(&data->disabled);
}

static void
event_resched_task_callback(struct task_struct *task, int task_cpu)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	long disable;
	int cpu;

	if (!tracer_enabled || function_trace_stop)
		return;

	/* interrupts should be off, we are in an interrupt */
	cpu = smp_processor_id();
	data = tr->data[cpu];

	disable = atomic_inc_return(&data->disabled);
	if (disable != 1)
		goto out;

	local_save_flags(flags);
	tracing_event_resched_task(tr, data, flags, CALLER_ADDR1, task, task_cpu);

 out:
	atomic_dec(&data->disabled);
}

static void
event_task_activate_callback(struct task_struct *p, int rqcpu)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	long disable;
	int cpu;

	if (!tracer_enabled || function_trace_stop)
		return;

	/* interrupts should be off, we are in an interrupt */
	cpu = smp_processor_id();
	data = tr->data[cpu];

	disable = atomic_inc_return(&data->disabled);
	if (disable != 1)
		goto out;

	local_save_flags(flags);
	tracing_event_task_activate(tr, data, flags, CALLER_ADDR1, p, rqcpu);

 out:
	atomic_dec(&data->disabled);
}

static void
event_task_deactivate_callback(struct task_struct *p, int rqcpu)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	long disable;
	int cpu;

	if (!tracer_enabled || function_trace_stop)
		return;

	/* interrupts should be off, we are in an interrupt */
	cpu = smp_processor_id();
	data = tr->data[cpu];

	disable = atomic_inc_return(&data->disabled);
	if (disable != 1)
		goto out;

	local_save_flags(flags);
	tracing_event_task_deactivate(tr, data, flags, CALLER_ADDR1, p, rqcpu);

 out:
	atomic_dec(&data->disabled);
}

static void
event_wakeup_callback(struct rq *rq, struct task_struct *wakee)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	long disable;
	int cpu;

	if (!tracer_enabled || function_trace_stop)
		return;

	/* interrupts should be disabled */
	cpu = smp_processor_id();
	data = tr->data[cpu];

	disable = atomic_inc_return(&data->disabled);
	if (unlikely(disable != 1))
		goto out;

	local_save_flags(flags);
	/* record process's command line */
	tracing_record_cmdline(wakee);
	tracing_record_cmdline(current);

	tracing_sched_wakeup_trace(tr, data, wakee, current, flags);

 out:
	atomic_dec(&data->disabled);
}

static void
event_ctx_callback(struct rq *rq, struct task_struct *prev,
		   struct task_struct *next)
{
	struct trace_array *tr = events_trace;
	struct trace_array_cpu *data;
	unsigned long flags;
	long disable;
	int cpu;

	if (!tracer_enabled || function_trace_stop)
		return;

	tracing_record_cmdline(prev);
	tracing_record_cmdline(next);

	/* interrupts should be disabled */
	cpu = smp_processor_id();
	data = tr->data[cpu];
	disable = atomic_inc_return(&data->disabled);

	if (likely(disable != 1))
		goto out;

	local_save_flags(flags);
	tracing_sched_switch_trace(tr, data, prev, next, flags);
 out:
	atomic_dec(&data->disabled);
}

static void event_tracer_register(struct trace_array *tr)
{
	int ret;

	ret = register_trace_event_irq(event_irq_callback);
	if (ret) {
		pr_info("event trace: Couldn't activate tracepoint"
			" probe to event_irq\n");
		return;
	}

	ret = register_trace_event_fault(event_fault_callback);
	if (ret) {
		pr_info("event trace: Couldn't activate tracepoint"
			" probe to event_fault\n");
		goto out1;
	}

	ret = register_trace_event_timer_set(event_timer_set_callback);
	if (ret) {
		pr_info("event trace: Couldn't activate tracepoint"
			" probe to event_timer_set\n");
		goto out2;
	}

	ret = register_trace_event_timer_triggered(event_timer_triggered_callback);
	if (ret) {
		pr_info("event trace: Couldn't activate tracepoint"
			" probe to event_timer_triggered\n");
		goto out3;
	}

	ret = register_trace_event_timestamp(event_hrtimer_callback);
	if (ret) {
		pr_info("event trace: Couldn't activate tracepoint"
			" probe to event_timestamp\n");
		goto out4;
	}

	ret = register_trace_event_task_activate(event_task_activate_callback);
	if (ret) {
		pr_info("event trace: Couldn't activate tracepoint"
			" probe to event_task_activate\n");
		goto out5;
	}

	ret = register_trace_event_task_deactivate(event_task_deactivate_callback);
	if (ret) {
		pr_info("event trace: Couldn't activate tracepoint"
			" probe to event_task_deactivate\n");
		goto out6;
	}

	ret = register_trace_sched_wakeup(event_wakeup_callback);
	if (ret) {
		pr_info("event trace: Couldn't activate tracepoint"
			" probe to kernel_sched_wakeup\n");
		goto out7;
	}

	ret = register_trace_sched_wakeup_new(event_wakeup_callback);
	if (ret) {
		pr_info("event trace: Couldn't activate tracepoint"
			" probe to kernel_sched_wakeup_new\n");
		goto out8;
	}

	ret = register_trace_sched_switch(event_ctx_callback);
	if (ret) {
		pr_info("event trace: Couldn't activate tracepoint"
			" probe to kernel_sched_schedule\n");
		goto out9;
	}

	ret = register_trace_event_program_event(event_program_event_callback);
	if (ret) {
		pr_info("event trace: Couldn't activate tracepoint"
			" probe to kernel_event_program_event\n");
		goto out10;
	}

	ret = register_trace_sched_resched_task(event_resched_task_callback);
	if (ret) {
		pr_info("event trace: Couldn't activate tracepoint"
			" probe to kernel_event_resched_task\n");
		goto out11;
	}

	return;

 out11:
	unregister_trace_event_program_event(event_program_event_callback);
 out10:
	unregister_trace_sched_switch(event_ctx_callback);
 out9:
	unregister_trace_sched_wakeup_new(event_wakeup_callback);
 out8:
	unregister_trace_sched_wakeup(event_wakeup_callback);
 out7:
	unregister_trace_event_task_deactivate(event_task_deactivate_callback);
 out6:
	unregister_trace_event_task_activate(event_task_activate_callback);
 out5:
	unregister_trace_event_timestamp(event_hrtimer_callback);
 out4:
	unregister_trace_event_timer_triggered(event_timer_triggered_callback);
 out3:
	unregister_trace_event_timer_set(event_timer_set_callback);
 out2:
	unregister_trace_event_fault(event_fault_callback);
 out1:
	unregister_trace_event_irq(event_irq_callback);
}

static void event_tracer_unregister(struct trace_array *tr)
{
	unregister_trace_sched_resched_task(event_resched_task_callback);
	unregister_trace_event_program_event(event_program_event_callback);
	unregister_trace_sched_switch(event_ctx_callback);
	unregister_trace_sched_wakeup_new(event_wakeup_callback);
	unregister_trace_sched_wakeup(event_wakeup_callback);
	unregister_trace_event_task_deactivate(event_task_deactivate_callback);
	unregister_trace_event_task_activate(event_task_activate_callback);
	unregister_trace_event_timestamp(event_hrtimer_callback);
	unregister_trace_event_timer_triggered(event_timer_triggered_callback);
	unregister_trace_event_timer_set(event_timer_set_callback);
	unregister_trace_event_fault(event_fault_callback);
	unregister_trace_event_irq(event_irq_callback);
}

void trace_event_register(struct trace_array *tr)
{
	long ref;

	ref = atomic_inc_return(&event_ref);
	if (ref == 1)
		event_tracer_register(tr);
}

void trace_event_unregister(struct trace_array *tr)
{
	long ref;

	ref = atomic_dec_and_test(&event_ref);
	if (ref)
		event_tracer_unregister(tr);
}

static void start_event_trace(struct trace_array *tr)
{
	event_reset(tr);
	trace_event_register(tr);
	tracing_start_function_trace();
	tracer_enabled = 1;
}

static void stop_event_trace(struct trace_array *tr)
{
	tracer_enabled = 0;
	tracing_stop_function_trace();
	trace_event_unregister(tr);
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
		tracer_enabled = 0;
}

static void event_trace_close(struct trace_iterator *iter)
{
	if (iter->tr->ctrl)
		tracer_enabled = 1;
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

__init static int init_event_trace(void)
{
	int ret;

	ret = register_tracer(&event_trace);
	if (ret)
		return ret;

	return 0;
}

device_initcall(init_event_trace);
