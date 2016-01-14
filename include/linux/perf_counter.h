/*
 *  Performance counters:
 *
 *   Copyright(C) 2008, Thomas Gleixner <tglx@linutronix.de>
 *   Copyright(C) 2008, Red Hat, Inc., Ingo Molnar
 *
 *  Data type definitions, declarations, prototypes.
 *
 *  Started by: Thomas Gleixner and Ingo Molnar
 *
 *  For licencing details see kernel-base/COPYING
 */
#ifndef _LINUX_PERF_COUNTER_H
#define _LINUX_PERF_COUNTER_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include <asm/byteorder.h>

/*
 * User-space ABI bits:
 */

/*
 * hw_event.type
 */
enum perf_event_types {
	PERF_TYPE_HARDWARE		= 0,
	PERF_TYPE_SOFTWARE		= 1,
	PERF_TYPE_TRACEPOINT		= 2,

	/*
	 * available TYPE space, raw is the max value.
	 */

	PERF_TYPE_RAW			= 128,
};

/*
 * Generalized performance counter event types, used by the hw_event.event_id
 * parameter of the sys_perf_counter_open() syscall:
 */
enum hw_event_ids {
	/*
	 * Common hardware events, generalized by the kernel:
	 */
	PERF_COUNT_CPU_CYCLES		= 0,
	PERF_COUNT_INSTRUCTIONS		= 1,
	PERF_COUNT_CACHE_REFERENCES	= 2,
	PERF_COUNT_CACHE_MISSES		= 3,
	PERF_COUNT_BRANCH_INSTRUCTIONS	= 4,
	PERF_COUNT_BRANCH_MISSES	= 5,
	PERF_COUNT_BUS_CYCLES		= 6,

	PERF_HW_EVENTS_MAX		= 7,
};

/*
 * Special "software" counters provided by the kernel, even if the hardware
 * does not support performance counters. These counters measure various
 * physical and sw events of the kernel (and allow the profiling of them as
 * well):
 */
enum sw_event_ids {
	PERF_COUNT_CPU_CLOCK		= 0,
	PERF_COUNT_TASK_CLOCK		= 1,
	PERF_COUNT_PAGE_FAULTS		= 2,
	PERF_COUNT_CONTEXT_SWITCHES	= 3,
	PERF_COUNT_CPU_MIGRATIONS	= 4,
	PERF_COUNT_PAGE_FAULTS_MIN	= 5,
	PERF_COUNT_PAGE_FAULTS_MAJ	= 6,

	PERF_SW_EVENTS_MAX		= 7,
};

/*
 * IRQ-notification data record type:
 */
enum perf_counter_record_type {
	PERF_RECORD_SIMPLE		= 0,
	PERF_RECORD_IRQ			= 1,
	PERF_RECORD_GROUP		= 2,
};

/*
 * Hardware event to monitor via a performance monitoring counter:
 */
struct perf_counter_hw_event {
	union {
#ifndef __BIG_ENDIAN_BITFIELD
		struct {
			__u64			event_id	: 56,
						type		:  8;
		};
		struct {
			__u64			raw_event_id	: 63,
						raw_type	:  1;
		};
#else
		struct {
			__u64			type		:  8,
						event_id	: 56;
		};
		struct {
			__u64			raw_type	:  1,
						raw_event_id	: 63;
		};
#endif /* __BIT_ENDIAN_BITFIELD */
		__u64		event_config;
	};

	__u64			irq_period;
	__u64			record_type;
	__u64			read_format;

	__u64			disabled       :  1, /* off by default        */
				nmi	       :  1, /* NMI sampling          */
				inherit	       :  1, /* children inherit it   */
				pinned	       :  1, /* must always be on PMU */
				exclusive      :  1, /* only group on PMU     */
				exclude_user   :  1, /* don't count user      */
				exclude_kernel :  1, /* ditto kernel          */
				exclude_hv     :  1, /* ditto hypervisor      */
				exclude_idle   :  1, /* don't count when idle */

				__reserved_1   : 55;

	__u32			extra_config_len;
	__u32			__reserved_4;

	__u64			__reserved_2;
	__u64			__reserved_3;
};

/*
 * Ioctls that can be done on a perf counter fd:
 */
#define PERF_COUNTER_IOC_ENABLE		_IO('$', 0)
#define PERF_COUNTER_IOC_DISABLE	_IO('$', 1)

#ifdef __KERNEL__
/*
 * Kernel-internal data types and definitions:
 */

#ifdef CONFIG_PERF_COUNTERS
# include <asm/perf_counter.h>
#endif

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/hrtimer.h>
#include <asm/atomic.h>

struct task_struct;

/**
 * struct hw_perf_counter - performance counter hardware details:
 */
struct hw_perf_counter {
#ifdef CONFIG_PERF_COUNTERS
	union {
		struct { /* hardware */
			u64				config;
			unsigned long			config_base;
			unsigned long			counter_base;
			int				nmi;
			unsigned int			idx;
		};
		union { /* software */
			atomic64_t			count;
			struct hrtimer			hrtimer;
		};
	};
	atomic64_t			prev_count;
	u64				irq_period;
	atomic64_t			period_left;
#endif
};

/*
 * Hardcoded buffer length limit for now, for IRQ-fed events:
 */
#define PERF_DATA_BUFLEN		2048

/**
 * struct perf_data - performance counter IRQ data sampling ...
 */
struct perf_data {
	int				len;
	int				rd_idx;
	int				overrun;
	u8				data[PERF_DATA_BUFLEN];
};

struct perf_counter;

/**
 * struct hw_perf_counter_ops - performance counter hw ops
 */
struct hw_perf_counter_ops {
	int (*enable)			(struct perf_counter *counter);
	void (*disable)			(struct perf_counter *counter);
	void (*read)			(struct perf_counter *counter);
};

/**
 * enum perf_counter_active_state - the states of a counter
 */
enum perf_counter_active_state {
	PERF_COUNTER_STATE_ERROR	= -2,
	PERF_COUNTER_STATE_OFF		= -1,
	PERF_COUNTER_STATE_INACTIVE	=  0,
	PERF_COUNTER_STATE_ACTIVE	=  1,
};

struct file;

/**
 * struct perf_counter - performance counter kernel representation:
 */
struct perf_counter {
#ifdef CONFIG_PERF_COUNTERS
	struct list_head		list_entry;
	struct list_head		event_entry;
	struct list_head		sibling_list;
	struct perf_counter		*group_leader;
	const struct hw_perf_counter_ops *hw_ops;

	enum perf_counter_active_state	state;
	enum perf_counter_active_state	prev_state;
	atomic64_t			count;

	struct perf_counter_hw_event	hw_event;
	struct hw_perf_counter		hw;

	struct perf_counter_context	*ctx;
	struct task_struct		*task;
	struct file			*filp;

	struct perf_counter		*parent;
	struct list_head		child_list;

	/*
	 * Protect attach/detach and child_list:
	 */
	struct mutex			mutex;

	int				oncpu;
	int				cpu;

	/* read() / irq related data */
	wait_queue_head_t		waitq;
	/* optional: for NMIs */
	int				wakeup_pending;
	struct perf_data		*irqdata;
	struct perf_data		*usrdata;
	struct perf_data		data[2];

	void (*destroy)(struct perf_counter *);
	struct rcu_head			rcu_head;
#endif
};

/**
 * struct perf_counter_context - counter context structure
 *
 * Used as a container for task counters and CPU counters as well:
 */
struct perf_counter_context {
#ifdef CONFIG_PERF_COUNTERS
	/*
	 * Protect the states of the counters in the list,
	 * nr_active, and the list:
	 */
	spinlock_t		lock;
	/*
	 * Protect the list of counters.  Locking either mutex or lock
	 * is sufficient to ensure the list doesn't change; to change
	 * the list you need to lock both the mutex and the spinlock.
	 */
	struct mutex		mutex;

	struct list_head	counter_list;
	struct list_head	event_list;
	int			nr_counters;
	int			nr_active;
	int			is_active;
	struct task_struct	*task;
#endif
};

/**
 * struct perf_counter_cpu_context - per cpu counter context structure
 */
struct perf_cpu_context {
	struct perf_counter_context	ctx;
	struct perf_counter_context	*task_ctx;
	int				active_oncpu;
	int				max_pertask;
	int				exclusive;
};

/*
 * Set by architecture code:
 */
extern int perf_max_counters;

#ifdef CONFIG_PERF_COUNTERS
extern const struct hw_perf_counter_ops *
hw_perf_counter_init(struct perf_counter *counter);

extern void perf_counter_task_sched_in(struct task_struct *task, int cpu);
extern void perf_counter_task_sched_out(struct task_struct *task, int cpu);
extern void perf_counter_task_tick(struct task_struct *task, int cpu);
extern void perf_counter_init_task(struct task_struct *child);
extern void perf_counter_exit_task(struct task_struct *child);
extern void perf_counter_notify(struct pt_regs *regs);
extern void perf_counter_print_debug(void);
extern void perf_counter_unthrottle(void);
extern u64 hw_perf_save_disable(void);
extern void hw_perf_restore(u64 ctrl);
extern int perf_counter_task_disable(void);
extern int perf_counter_task_enable(void);
extern int hw_perf_group_sched_in(struct perf_counter *group_leader,
	       struct perf_cpu_context *cpuctx,
	       struct perf_counter_context *ctx, int cpu);

extern void perf_counter_output(struct perf_counter *counter,
				int nmi, struct pt_regs *regs);
/*
 * Return 1 for a software counter, 0 for a hardware counter
 */
static inline int is_software_counter(struct perf_counter *counter)
{
	return !counter->hw_event.raw_type &&
		counter->hw_event.type != PERF_TYPE_HARDWARE;
}

extern void perf_swcounter_event(u32, u64, int, struct pt_regs *);

#else
static inline void
perf_counter_task_sched_in(struct task_struct *task, int cpu)		{ }
static inline void
perf_counter_task_sched_out(struct task_struct *task, int cpu)		{ }
static inline void
perf_counter_task_tick(struct task_struct *task, int cpu)		{ }
static inline void perf_counter_init_task(struct task_struct *child)	{ }
static inline void perf_counter_exit_task(struct task_struct *child)	{ }
static inline void perf_counter_notify(struct pt_regs *regs)		{ }
static inline void perf_counter_print_debug(void)			{ }
static inline void perf_counter_unthrottle(void)			{ }
static inline void hw_perf_restore(u64 ctrl)				{ }
static inline u64 hw_perf_save_disable(void)		      { return 0; }
static inline int perf_counter_task_disable(void)	{ return -EINVAL; }
static inline int perf_counter_task_enable(void)	{ return -EINVAL; }

static inline void perf_swcounter_event(u32 event, u64 nr,
					int nmi, struct pt_regs *regs)	{ }
#endif

#endif /* __KERNEL__ */
#endif /* _LINUX_PERF_COUNTER_H */
