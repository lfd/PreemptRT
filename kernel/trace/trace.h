#ifndef _LINUX_KERNEL_TRACE_H
#define _LINUX_KERNEL_TRACE_H

#include <linux/fs.h>
#include <asm/atomic.h>
#include <linux/sched.h>
#include <linux/clocksource.h>

/*
 * Function trace entry - function address and parent function addres:
 */
struct ftrace_entry {
	unsigned long		ip;
	unsigned long		parent_ip;
};

/*
 * Context switch trace entry - which task (and prio) we switched from/to:
 */
struct ctx_switch_entry {
	unsigned int		prev_pid;
	unsigned char		prev_prio;
	unsigned char		prev_state;
	unsigned int		next_pid;
	unsigned char		next_prio;
};

struct irq_entry {
	unsigned long		ip;
	unsigned long		ret_ip;
	unsigned		irq;
	unsigned		usermode;
};

struct fault_entry {
	unsigned long		ip;
	unsigned long		ret_ip;
	unsigned long		errorcode;
	unsigned long		address;
};

struct timer_entry {
	unsigned long		ip;
	void			*p1;
	void			*p2;
};

struct timestamp_entry {
	unsigned long		ip;
	ktime_t			now;
};

struct task_entry {
	unsigned long		ip;
	pid_t			pid;
	unsigned		prio;
	unsigned long		running;
};

struct wakeup_entry {
	unsigned long		ip;
	pid_t			pid;
	unsigned		prio;
	unsigned		curr_prio;
};

/*
 * The trace entry - the most basic unit of tracing. This is what
 * is printed in the end as a single line in the trace output, such as:
 *
 *     bash-15816 [01]   235.197585: idle_cpu <- irq_enter
 */
struct trace_entry {
	char			type;
	char			cpu;
	char			flags;
	char			preempt_count;
	int			pid;
	cycle_t			t;
	unsigned long		idx;
	union {
		struct ftrace_entry		fn;
		struct ctx_switch_entry		ctx;
		struct irq_entry		irq;
		struct fault_entry		fault;
		struct timer_entry		timer;
		struct timestamp_entry		timestamp;
		struct task_entry		task;
		struct wakeup_entry		wakeup;
	};
};

#define TRACE_ENTRY_SIZE	sizeof(struct trace_entry)

/*
 * The CPU trace array - it consists of thousands of trace entries
 * plus some other descriptor data: (for example which task started
 * the trace, etc.)
 */
struct trace_array_cpu {
	struct list_head	trace_pages;
	atomic_t		disabled;
	cycle_t			time_offset;

	/* these fields get copied into max-trace: */
	void			*trace_current;
	unsigned		trace_current_idx;
	unsigned long		trace_idx;
	unsigned long		saved_latency;
	unsigned long		critical_start;
	unsigned long		critical_end;
	unsigned long		critical_sequence;
	unsigned long		nice;
	unsigned long		policy;
	unsigned long		rt_priority;
	cycle_t			preempt_timestamp;
	pid_t			pid;
	uid_t			uid;
	char			comm[TASK_COMM_LEN];
};

struct trace_iterator;

/*
 * The trace array - an array of per-CPU trace arrays. This is the
 * highest level data structure that individual tracers deal with.
 * They have on/off state as well:
 */
struct trace_array {
	unsigned long		entries;
	long			ctrl;
	int			cpu;
	cycle_t			time_start;
	struct trace_array_cpu	*data[NR_CPUS];
};

/*
 * A specific tracer, represented by methods that operate on a trace array:
 */
struct tracer {
	const char		*name;
	void			(*init)(struct trace_array *tr);
	void			(*reset)(struct trace_array *tr);
	void			(*open)(struct trace_iterator *iter);
	void			(*close)(struct trace_iterator *iter);
	void			(*start)(struct trace_iterator *iter);
	void			(*stop)(struct trace_iterator *iter);
	void			(*ctrl_update)(struct trace_array *tr);
#ifdef CONFIG_FTRACE_STARTUP_TEST
	int			(*selftest)(struct tracer *trace,
					    struct trace_array *tr);
#endif
	struct tracer		*next;
	int			print_max;
};

/*
 * Trace iterator - used by printout routines who present trace
 * results to users and which routines might sleep, etc:
 */
struct trace_iterator {
	struct trace_array	*tr;
	struct tracer		*trace;

	struct trace_entry	*ent;
	int			cpu;

	struct trace_entry	*prev_ent;
	int			prev_cpu;

	unsigned long		iter_flags;
	loff_t			pos;
	unsigned long		next_idx[NR_CPUS];
	struct list_head	*next_page[NR_CPUS];
	unsigned		next_page_idx[NR_CPUS];
	long			idx;
};

void notrace tracing_reset(struct trace_array_cpu *data);
int tracing_open_generic(struct inode *inode, struct file *filp);
struct dentry *tracing_init_dentry(void);
void ftrace(struct trace_array *tr,
			    struct trace_array_cpu *data,
			    unsigned long ip,
			    unsigned long parent_ip,
			    unsigned long flags);
void tracing_sched_switch_trace(struct trace_array *tr,
				struct trace_array_cpu *data,
				struct task_struct *prev,
				struct task_struct *next,
				unsigned long flags);
void tracing_record_cmdline(struct task_struct *tsk);
void tracing_event_irq(struct trace_array *tr,
		       struct trace_array_cpu *data,
		       unsigned long flags,
		       unsigned long ip,
		       int irq, int usermode,
		       unsigned long retip);
void tracing_event_fault(struct trace_array *tr,
			 struct trace_array_cpu *data,
			 unsigned long flags,
			 unsigned long ip,
			 unsigned long retip,
			 unsigned long error_code,
			 unsigned long address);
void tracing_event_timer(struct trace_array *tr,
			 struct trace_array_cpu *data,
			 unsigned long flags,
			 unsigned long ip,
			 void *p1, void *p2);
void tracing_event_timestamp(struct trace_array *tr,
			     struct trace_array_cpu *data,
			     unsigned long flags,
			     unsigned long ip,
			     ktime_t *now);
void tracing_event_task(struct trace_array *tr,
			struct trace_array_cpu *data,
			unsigned long flags,
			unsigned long ip,
			pid_t pid, int prio,
			unsigned long running);
void tracing_event_wakeup(struct trace_array *tr,
			  struct trace_array_cpu *data,
			  unsigned long flags,
			  unsigned long ip,
			  pid_t pid, int prio,
			  int curr_prio);

void tracing_start_function_trace(void);
void tracing_stop_function_trace(void);
int register_tracer(struct tracer *type);
void unregister_tracer(struct tracer *type);

extern unsigned long nsecs_to_usecs(unsigned long nsecs);

extern unsigned long tracing_max_latency;
extern unsigned long tracing_thresh;

extern atomic_t trace_record_cmdline_enabled;

void update_max_tr(struct trace_array *tr, struct task_struct *tsk, int cpu);
void update_max_tr_single(struct trace_array *tr,
			  struct task_struct *tsk, int cpu);

static inline notrace cycle_t now(int cpu)
{
	return sched_clock();
}

#ifdef CONFIG_SCHED_TRACER
extern void notrace
wakeup_sched_switch(struct task_struct *prev, struct task_struct *next);
#else
static inline void
wakeup_sched_switch(struct task_struct *prev, struct task_struct *next)
{
}
#endif

#ifdef CONFIG_CONTEXT_SWITCH_TRACER
typedef void
(*tracer_switch_func_t)(void *private,
			struct task_struct *prev,
			struct task_struct *next);

struct tracer_switch_ops {
	tracer_switch_func_t		func;
	void				*private;
	struct tracer_switch_ops	*next;
};

extern int register_tracer_switch(struct tracer_switch_ops *ops);
extern int unregister_tracer_switch(struct tracer_switch_ops *ops);

#endif /* CONFIG_CONTEXT_SWITCH_TRACER */

#ifdef CONFIG_DYNAMIC_FTRACE
extern unsigned long ftrace_update_tot_cnt;
#endif

#ifdef CONFIG_FTRACE_STARTUP_TEST
#ifdef CONFIG_FTRACE
extern int trace_selftest_startup_function(struct tracer *trace,
					   struct trace_array *tr);
#endif
#ifdef CONFIG_IRQSOFF_TRACER
extern int trace_selftest_startup_irqsoff(struct tracer *trace,
					  struct trace_array *tr);
#endif
#ifdef CONFIG_PREEMPT_TRACER
extern int trace_selftest_startup_preemptoff(struct tracer *trace,
					     struct trace_array *tr);
#endif
#if defined(CONFIG_IRQSOFF_TRACER) && defined(CONFIG_PREEMPT_TRACER)
extern int trace_selftest_startup_preemptirqsoff(struct tracer *trace,
						 struct trace_array *tr);
#endif
#ifdef CONFIG_SCHED_TRACER
extern int trace_selftest_startup_wakeup(struct tracer *trace,
					 struct trace_array *tr);
#endif
#ifdef CONFIG_CONTEXT_SWITCH_TRACER
extern int trace_selftest_startup_sched_switch(struct tracer *trace,
					       struct trace_array *tr);
#endif
#endif /* CONFIG_FTRACE_STARTUP_TEST */

extern void *head_page(struct trace_array_cpu *data);

#ifdef CONFIG_EVENT_TRACER
extern void trace_event_sched_switch(struct task_struct *prev,
				     struct task_struct *next);
extern void trace_event_wakeup(struct task_struct *wakee,
			       struct task_struct *curr);
extern void trace_start_events(void);
extern void trace_stop_events(void);
extern void trace_event_register(struct trace_array *tr);
extern void trace_event_unregister(struct trace_array *tr);
#else
# define trace_event_sched_switch(prev, next)	do { } while (0)
# define trace_event_wakeup(wakee, curr)	do { } while (0)
# define trace_start_events()			do { } while (0)
# define trace_stop_events()			do { } while (0)
# define trace_event_register(tr)		do { } while (0)
# define trace_event_unregister(tr)		do { } while (0)
#endif

#endif /* _LINUX_KERNEL_TRACE_H */
