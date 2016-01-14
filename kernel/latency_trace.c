/*
 *  kernel/latency_trace.c
 *
 *  Copyright (C) 2004-2006 Ingo Molnar
 *  Copyright (C) 2004 William Lee Irwin III
 */
#include <linux/mm.h>
#include <linux/nmi.h>
#include <linux/rtc.h>
#include <linux/sched.h>
#include <linux/percpu.h>

#include <linux/module.h>
#include <linux/profile.h>
#include <linux/bootmem.h>
#include <linux/version.h>
#include <linux/notifier.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/interrupt.h>
#include <linux/clocksource.h>
#include <linux/proc_fs.h>
#include <linux/latency_hist.h>
#include <linux/utsrelease.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/asm-offsets.h>
#include <asm/rtc.h>
#include <linux/stacktrace.h>

#ifndef DEFINE_RAW_SPINLOCK
# define DEFINE_RAW_SPINLOCK		DEFINE_SPINLOCK
#endif

#ifndef RAW_SPIN_LOCK_UNLOCKED
# define RAW_SPIN_LOCK_UNLOCKED		SPIN_LOCK_UNLOCKED
#endif

int trace_use_raw_cycles = 0;

#define __raw_spinlock_t raw_spinlock_t
#define need_resched_delayed() 0

#ifdef CONFIG_EVENT_TRACE
/*
 * Convert raw cycles to usecs.
 * Note: this is not the 'clocksource cycles' value, it's the raw
 * cycle counter cycles. We use GTOD to timestamp latency start/end
 * points, but the trace entries inbetween are timestamped with
 * get_cycles().
 */
static unsigned long notrace cycles_to_us(cycle_t delta)
{
	if (!trace_use_raw_cycles)
		return cycles_to_usecs(delta);
#ifdef CONFIG_X86
	do_div(delta, cpu_khz/1000+1);
#elif defined(CONFIG_PPC)
	delta = mulhwu(tb_to_us, delta);
#elif defined(CONFIG_ARM)
	delta = mach_cycles_to_usecs(delta);
#else
	#error Implement cycles_to_usecs.
#endif

	return (unsigned long) delta;
}
#endif

static notrace inline cycle_t now(void)
{
	if (trace_use_raw_cycles)
		return get_cycles();
	return get_monotonic_cycles();
}

#ifndef irqs_off
# define irqs_off()			0
#endif

#ifndef DEBUG_WARN_ON
static inline int DEBUG_WARN_ON(int cond)
{
	WARN_ON(cond);
	return 0;
}
#endif

#ifdef CONFIG_CRITICAL_IRQSOFF_TIMING
# ifdef CONFIG_CRITICAL_PREEMPT_TIMING
#  define irqs_off_preempt_count() preempt_count()
# else
#  define irqs_off_preempt_count() 0
# endif
#endif

#ifdef CONFIG_WAKEUP_TIMING
struct sch_struct {
	__raw_spinlock_t trace_lock;
	struct task_struct *task;
	int cpu;
	struct cpu_trace *tr;
} ____cacheline_aligned_in_smp;

static __cacheline_aligned_in_smp struct sch_struct sch =
		{ trace_lock: __RAW_SPIN_LOCK_UNLOCKED };

int wakeup_timing = 1;
#endif

/*
 * Track maximum latencies and save the trace:
 */

/*
 * trace_stop_sched_switched must not be called with runqueue locks held!
 */
static __cacheline_aligned_in_smp DECLARE_MUTEX(max_mutex);

/*
 * Sequence count - we record it when starting a measurement and
 * skip the latency if the sequence has changed - some other section
 * did a maximum and could disturb our measurement with serial console
 * printouts, etc. Truly coinciding maximum latencies should be rare
 * and what happens together happens separately as well, so this doesnt
 * decrease the validity of the maximum found:
 */
static __cacheline_aligned_in_smp unsigned long max_sequence;

enum trace_type
{
	__TRACE_FIRST_TYPE = 0,

	TRACE_FN,
	TRACE_SPECIAL,
	TRACE_SPECIAL_PID,
	TRACE_SPECIAL_U64,
	TRACE_SPECIAL_SYM,
	TRACE_CMDLINE,
	TRACE_SYSCALL,
	TRACE_SYSRET,

	__TRACE_LAST_TYPE
};

enum trace_flag_type
{
	TRACE_FLAG_IRQS_OFF		= 0x01,
	TRACE_FLAG_NEED_RESCHED		= 0x02,
	TRACE_FLAG_NEED_RESCHED_DELAYED	= 0x04,
	TRACE_FLAG_HARDIRQ		= 0x08,
	TRACE_FLAG_SOFTIRQ		= 0x10,
	TRACE_FLAG_IRQS_HARD_OFF	= 0x20,
};

/*
 * Maximum preemption latency measured. Initialize to maximum,
 * we clear it after bootup.
 */
#ifdef CONFIG_LATENCY_HIST
unsigned long preempt_max_latency = (cycle_t)0UL;
#else
unsigned long preempt_max_latency = (cycle_t)ULONG_MAX;
#endif

unsigned long preempt_thresh;

/*
 * Should this new latency be reported/recorded?
 */
static int report_latency(cycle_t delta)
{
	if (latency_hist_flag && !trace_user_triggered)
		return 1;

	if (preempt_thresh) {
		if (delta < preempt_thresh)
			return 0;
	} else {
		if (delta <= preempt_max_latency)
			return 0;
	}
	return 1;
}

#ifdef CONFIG_EVENT_TRACE

/*
 * Number of per-CPU trace entries:
 */
#define MAX_TRACE (65536UL*16UL)

#define CMDLINE_BYTES 16

/*
 * 32 bytes on 32-bit platforms:
 */
struct trace_entry {
	char type;
	char cpu;
	char flags;
	char preempt_count; // assumes PREEMPT_MASK is 8 bits or less
	int pid;
	cycle_t timestamp;
	union {
		struct {
			unsigned long eip;
			unsigned long parent_eip;
		} fn;
		struct {
			unsigned long eip;
			unsigned long v1, v2, v3;
		} special;
		struct {
			unsigned char str[CMDLINE_BYTES];
		} cmdline;
		struct {
			unsigned long nr; // highest bit: compat call
			unsigned long p1, p2, p3;
		} syscall;
		struct {
			unsigned long ret;
		} sysret;
		struct {
			unsigned long __pad3[4];
		} pad;
	} u;
} __attribute__((packed));

#endif

struct cpu_trace {
	atomic_t disabled;
	unsigned long trace_idx;
	cycle_t preempt_timestamp;
	unsigned long critical_start, critical_end;
	unsigned long critical_sequence;
	atomic_t underrun;
	atomic_t overrun;
	int early_warning;
	int latency_type;
	int cpu;

#ifdef CONFIG_EVENT_TRACE
	struct trace_entry *trace;
	char comm[CMDLINE_BYTES];
	pid_t pid;
	unsigned long uid;
	unsigned long nice;
	unsigned long policy;
	unsigned long rt_priority;
	unsigned long saved_latency;
#endif
#ifdef CONFIG_DEBUG_STACKOVERFLOW
	unsigned long stack_check;
#endif
} ____cacheline_aligned_in_smp;

static struct cpu_trace cpu_traces[NR_CPUS] ____cacheline_aligned_in_smp =
{ [0 ... NR_CPUS-1] = {
#ifdef CONFIG_DEBUG_STACKOVERFLOW
 .stack_check = 1
#endif
 } };

#ifdef CONFIG_EVENT_TRACE

int trace_enabled = 0;
int syscall_tracing = 1;
int stackframe_tracing = 0;
int mcount_enabled = 0;
int trace_freerunning = 0;
int trace_print_on_crash = 0;
int trace_verbose = 0;
int trace_all_cpus = 0;
int print_functions = 0;
int trace_all_runnable = 0;

/*
 * user-triggered via gettimeofday(0,1)/gettimeofday(0,0)
 */
int trace_user_triggered = 0;
int trace_user_trigger_irq = -1;

struct saved_trace_struct {
	int cpu;
	cycle_t first_timestamp, last_timestamp;
	struct cpu_trace traces[NR_CPUS];
} ____cacheline_aligned_in_smp;

/*
 * The current worst-case trace:
 */
static struct saved_trace_struct max_tr;

/*
 * /proc/latency_trace atomicity:
 */
static DECLARE_MUTEX(out_mutex);

static struct saved_trace_struct out_tr;

static void notrace printk_name(unsigned long eip)
{
	char namebuf[KSYM_NAME_LEN+1];
	unsigned long size, offset;
	const char *sym_name;
	char *modname;

	sym_name = kallsyms_lookup(eip, &size, &offset, &modname, namebuf);
	if (sym_name)
		printk("%s+%#lx/%#lx", sym_name, offset, size);
	else
		printk("<%08lx>", eip);
}

#ifdef CONFIG_DEBUG_STACKOVERFLOW

#ifndef STACK_WARN
# define STACK_WARN (THREAD_SIZE/8)
#endif

#define MIN_STACK_NEEDED (sizeof(struct thread_info) + STACK_WARN)
#define MAX_STACK (THREAD_SIZE - sizeof(struct thread_info))

#if (defined(__i386__) || defined(__x86_64__)) && defined(CONFIG_FRAME_POINTER)
# define PRINT_EXACT_STACKFRAME
#endif

#ifdef PRINT_EXACT_STACKFRAME
static unsigned long *worst_stack_bp;
#endif
static DEFINE_RAW_SPINLOCK(worst_stack_lock);
unsigned long worst_stack_left = THREAD_SIZE;
static unsigned long worst_stack_printed = THREAD_SIZE;
static char worst_stack_comm[TASK_COMM_LEN+1];
static int worst_stack_pid;
static unsigned long worst_stack_sp;
static char worst_stack[THREAD_SIZE];

static notrace void fill_worst_stack(unsigned long stack_left)
{
	unsigned long flags;

	/*
	 * On x64, we must not read the PDA during early bootup:
	 */
#ifdef CONFIG_X86_64
	if (system_state == SYSTEM_BOOTING)
		return;
#endif
	spin_lock_irqsave(&worst_stack_lock, flags);
	if (likely(stack_left < worst_stack_left)) {
		worst_stack_left = stack_left;
		memcpy(worst_stack, current_thread_info(), THREAD_SIZE);
		worst_stack_sp = (unsigned long)&stack_left;
		memcpy(worst_stack_comm, current->comm, TASK_COMM_LEN);
		worst_stack_pid = current->pid;
#ifdef PRINT_EXACT_STACKFRAME
# ifdef __i386__
		asm ("mov %%ebp, %0\n" :"=g"(worst_stack_bp));
# elif defined(__x86_64__)
		asm ("mov %%rbp, %0\n" :"=g"(worst_stack_bp));
# else
#  error Poke the author of above asm code lines !
# endif
#endif
	}
	spin_unlock_irqrestore(&worst_stack_lock, flags);
}

#ifdef PRINT_EXACT_STACKFRAME

/*
 * This takes a BP offset to point the BP back into the saved stack,
 * the original stack might be long gone (but the stackframe within
 * the saved copy still contains references to it).
 */
#define CONVERT_TO_SAVED_STACK(bp) \
	((void *)worst_stack + ((unsigned long)bp & (THREAD_SIZE-1)))

static void show_stackframe(void)
{
	unsigned long addr, frame_size, *bp, *prev_bp, sum = 0;

	bp = CONVERT_TO_SAVED_STACK(worst_stack_bp);

	while (bp[0]) {
		addr = bp[1];
		if (!kernel_text_address(addr))
			break;

		prev_bp = bp;
		bp = CONVERT_TO_SAVED_STACK((unsigned long *)bp[0]);

		frame_size = (bp - prev_bp) * sizeof(long);

		if (frame_size < THREAD_SIZE) {
			printk("{ %4ld} ", frame_size);
			sum += frame_size;
		} else
			printk("{=%4ld} ", sum);

		printk("[<%08lx>] ", addr);
		printk_name(addr);
		printk("\n");
	}
}

#else

static inline int valid_stack_ptr(void *p)
{
	return  p > (void *)worst_stack &&
                p < (void *)worst_stack + THREAD_SIZE - 3;
}

static void show_stackframe(void)
{
	unsigned long prev_frame, addr;
	unsigned long *stack;

	prev_frame = (unsigned long)(worst_stack +
					(worst_stack_sp & (THREAD_SIZE-1)));
	stack = (unsigned long *)prev_frame;

	while (valid_stack_ptr(stack)) {
		addr = *stack++;
		if (__kernel_text_address(addr)) {
			printk("(%4ld) ", (unsigned long)stack - prev_frame);
			printk("[<%08lx>] ", addr);
			print_symbol("%s\n", addr);
			prev_frame = (unsigned long)stack;
		}
		if ((char *)stack >= worst_stack + THREAD_SIZE)
			break;
	}
}

#endif

static notrace void __print_worst_stack(void)
{
	unsigned long fill_ratio;
	printk("----------------------------->\n");
	printk("| new stack fill maximum: %s/%d, %ld bytes (out of %ld bytes).\n",
		worst_stack_comm, worst_stack_pid,
		MAX_STACK-worst_stack_left, (long)MAX_STACK);
	fill_ratio = (MAX_STACK-worst_stack_left)*100/(long)MAX_STACK;
	printk("| Stack fill ratio: %02ld%%", fill_ratio);
	if (fill_ratio >= 90)
		printk(" - BUG: that's quite high, please report this!\n");
	else
		printk(" - that's still OK, no need to report this.\n");
	printk("------------|\n");

	show_stackframe();
	printk("<---------------------------\n\n");
}

static notrace void print_worst_stack(void)
{
	unsigned long flags;

	if (irqs_disabled() || preempt_count())
		return;

	spin_lock_irqsave(&worst_stack_lock, flags);
	if (worst_stack_printed == worst_stack_left) {
		spin_unlock_irqrestore(&worst_stack_lock, flags);
		return;
	}
	worst_stack_printed = worst_stack_left;
	spin_unlock_irqrestore(&worst_stack_lock, flags);

	__print_worst_stack();
}

static notrace void debug_stackoverflow(struct cpu_trace *tr)
{
	long stack_left;

	if (unlikely(tr->stack_check <= 0))
		return;
	atomic_inc(&tr->disabled);

	/* Debugging check for stack overflow: is there less than 1KB free? */
#ifdef __i386__
	__asm__ __volatile__("and %%esp,%0" :
				"=r" (stack_left) : "0" (THREAD_SIZE - 1));
#elif defined(__x86_64__)
	__asm__ __volatile__("and %%rsp,%0" :
				"=r" (stack_left) : "0" (THREAD_SIZE - 1));
#else
# error Poke the author of above asm code lines !
#endif
	if (unlikely(stack_left < MIN_STACK_NEEDED)) {
		tr->stack_check = 0;
		printk(KERN_ALERT "BUG: stack overflow: only %ld bytes left! [%08lx...(%08lx-%08lx)]\n",
			stack_left - sizeof(struct thread_info),
			(long)&stack_left,
			(long)current_thread_info(),
			(long)current_thread_info() + THREAD_SIZE);
		fill_worst_stack(stack_left);
		__print_worst_stack();
		goto out;
	}
	if (unlikely(stack_left < worst_stack_left)) {
		tr->stack_check--;
		fill_worst_stack(stack_left);
		print_worst_stack();
		tr->stack_check++;
	} else
		if (worst_stack_printed != worst_stack_left) {
			tr->stack_check--;
			print_worst_stack();
			tr->stack_check++;
		}
out:
	atomic_dec(&tr->disabled);
}

#endif

#ifdef CONFIG_EARLY_PRINTK
static void notrace early_printk_name(unsigned long eip)
{
	char namebuf[KSYM_NAME_LEN+1];
	unsigned long size, offset;
	const char *sym_name;
	char *modname;

	sym_name = kallsyms_lookup(eip, &size, &offset, &modname, namebuf);
	if (sym_name)
		early_printk("%s <%08lx>", sym_name, eip);
	else
		early_printk("<%08lx>", eip);
}

static __raw_spinlock_t early_print_lock = __RAW_SPIN_LOCK_UNLOCKED;

static void notrace early_print_entry(struct trace_entry *entry)
{
	int hardirq, softirq;

	__raw_spin_lock(&early_print_lock);
	early_printk("%-5d ", entry->pid);

	early_printk("%d%c%c",
		entry->cpu,
		(entry->flags & TRACE_FLAG_IRQS_OFF) ? 'd' :
		(entry->flags & TRACE_FLAG_IRQS_HARD_OFF) ? 'D' : '.',
		(entry->flags & TRACE_FLAG_NEED_RESCHED_DELAYED) ? 'n' :
 		((entry->flags & TRACE_FLAG_NEED_RESCHED) ? 'N' : '.'));

	hardirq = entry->flags & TRACE_FLAG_HARDIRQ;
	softirq = entry->flags & TRACE_FLAG_SOFTIRQ;
	if (hardirq && softirq)
		early_printk("H");
	else {
		if (hardirq)
			early_printk("h");
		else {
			if (softirq)
				early_printk("s");
			else
				early_printk(".");
		}
	}

	early_printk(":%d: ", entry->preempt_count);

	if (entry->type == TRACE_FN) {
		early_printk_name(entry->u.fn.eip);
		early_printk("  <= (");
		early_printk_name(entry->u.fn.parent_eip);
		early_printk(")\n");
	} else {
		/* special entries: */
		early_printk_name(entry->u.special.eip);
		early_printk(": <%08lx> <%08lx> <%08lx>\n",
			entry->u.special.v1,
			entry->u.special.v2,
			entry->u.special.v3);
	}
	__raw_spin_unlock(&early_print_lock);
}
#else
#  define early_print_entry(x) do { } while(0)
#endif

static void notrace
____trace(int cpu, enum trace_type type, struct cpu_trace *tr,
	  unsigned long eip, unsigned long parent_eip,
	  unsigned long v1, unsigned long v2, unsigned long v3,
	  unsigned long flags)
{
	struct trace_entry *entry;
	unsigned long idx, idx_next;
	cycle_t timestamp;
	u32 pc;

#ifdef CONFIG_DEBUG_PREEMPT
//	WARN_ON(!atomic_read(&tr->disabled));
#endif
	if (!tr->critical_start && !trace_user_triggered && !trace_all_cpus &&
	    !trace_print_on_crash && !print_functions)
		goto out;
	/*
	 * Allocate the next index. Make sure an NMI (or interrupt)
	 * has not taken it away. Potentially redo the timestamp as
	 * well to make sure the trace timestamps are in chronologic
	 * order.
	 */
again:
	idx = tr->trace_idx;
	idx_next = idx + 1;
	timestamp = now();

	if (unlikely((trace_freerunning || print_functions || atomic_read(&tr->underrun)) &&
		     (idx_next >= MAX_TRACE) && !atomic_read(&tr->overrun))) {
		atomic_inc(&tr->underrun);
		idx_next = 0;
	}
	if (unlikely(idx >= MAX_TRACE)) {
		atomic_inc(&tr->overrun);
		goto out;
	}
#ifdef __HAVE_ARCH_CMPXCHG
	if (unlikely(cmpxchg(&tr->trace_idx, idx, idx_next) != idx)) {
		if (idx_next == 0)
			atomic_dec(&tr->underrun);
		goto again;
	}
#else
# ifdef CONFIG_SMP
#  error CMPXCHG missing
# else
	/* No worry, we are protected by the atomic_incr(&tr->disabled)
	 * in __trace further down
	 */
	tr->trace_idx = idx_next;
# endif
#endif
	if (unlikely(idx_next != 0 && atomic_read(&tr->underrun)))
		atomic_inc(&tr->underrun);

	pc = preempt_count();

	if (unlikely(!tr->trace))
		goto out;
	entry = tr->trace + idx;
	entry->type = type;
#ifdef CONFIG_SMP
	entry->cpu = cpu;
#endif
	entry->flags = (irqs_off() ? TRACE_FLAG_IRQS_OFF : 0) |
		(irqs_disabled_flags(flags) ? TRACE_FLAG_IRQS_HARD_OFF : 0)|
		((pc & HARDIRQ_MASK) ? TRACE_FLAG_HARDIRQ : 0) |
		((pc & SOFTIRQ_MASK) ? TRACE_FLAG_SOFTIRQ : 0) |
		(need_resched() ? TRACE_FLAG_NEED_RESCHED : 0) |
		(need_resched_delayed() ? TRACE_FLAG_NEED_RESCHED_DELAYED : 0);
	entry->preempt_count = pc & 0xff;
	entry->pid = current->pid;
	entry->timestamp = timestamp;

	switch (type) {
	case TRACE_FN:
		entry->u.fn.eip = eip;
		entry->u.fn.parent_eip = parent_eip;
		if (unlikely(print_functions && !in_interrupt()))
			early_print_entry(entry);
		break;
	case TRACE_SPECIAL:
	case TRACE_SPECIAL_PID:
	case TRACE_SPECIAL_U64:
	case TRACE_SPECIAL_SYM:
		entry->u.special.eip = eip;
		entry->u.special.v1 = v1;
		entry->u.special.v2 = v2;
		entry->u.special.v3 = v3;
		if (unlikely(print_functions && !in_interrupt()))
			early_print_entry(entry);
		break;
	case TRACE_SYSCALL:
		entry->u.syscall.nr = eip;
		entry->u.syscall.p1 = v1;
		entry->u.syscall.p2 = v2;
		entry->u.syscall.p3 = v3;
		break;
	case TRACE_SYSRET:
		entry->u.sysret.ret = eip;
		break;
	case TRACE_CMDLINE:
		memcpy(entry->u.cmdline.str, current->comm, CMDLINE_BYTES);
		break;
	default:
		break;
	}
out:
	;
}

static inline void notrace
___trace(enum trace_type type, unsigned long eip, unsigned long parent_eip,
		unsigned long v1, unsigned long v2,
			unsigned long v3)
{
	struct cpu_trace *tr;
	unsigned long flags;
	int cpu;

	if (unlikely(trace_enabled <= 0))
		return;

#if defined(CONFIG_DEBUG_STACKOVERFLOW) && defined(CONFIG_X86)
	debug_stackoverflow(cpu_traces + raw_smp_processor_id());
#endif

	raw_local_irq_save(flags);
	cpu = raw_smp_processor_id();
	/*
	 * Trace on the CPU where the current highest-prio task
	 * is waiting to become runnable:
	 */
#ifdef CONFIG_WAKEUP_TIMING
	if (wakeup_timing && !trace_all_cpus && !trace_print_on_crash &&
	    !print_functions) {
		if (!sch.tr || cpu != sch.cpu)
			goto out;
		tr = sch.tr;
	} else
		tr = cpu_traces + cpu;
#else
	tr = cpu_traces + cpu;
#endif
	atomic_inc(&tr->disabled);
	if (likely(atomic_read(&tr->disabled) == 1)) {
//#define DEBUG_STACK_POISON
#ifdef DEBUG_STACK_POISON
		char stack;

		memset(&stack - 128, 0x34, 128);
#endif
		____trace(cpu, type, tr, eip, parent_eip, v1, v2, v3, flags);
	}
	atomic_dec(&tr->disabled);
#ifdef CONFIG_WAKEUP_TIMING
out:
#endif
	raw_local_irq_restore(flags);
}

/*
 * Special, ad-hoc tracepoints:
 */
void notrace trace_special(unsigned long v1, unsigned long v2, unsigned long v3)
{
	___trace(TRACE_SPECIAL, CALLER_ADDR0, 0, v1, v2, v3);
}

EXPORT_SYMBOL(trace_special);

void notrace trace_special_pid(int pid, unsigned long v1, unsigned long v2)
{
	___trace(TRACE_SPECIAL_PID, CALLER_ADDR0, 0, pid, v1, v2);
}

EXPORT_SYMBOL(trace_special_pid);

void notrace trace_special_u64(unsigned long long v1, unsigned long v2)
{
	___trace(TRACE_SPECIAL_U64, CALLER_ADDR0, 0,
		 (unsigned long) (v1 >> 32), (unsigned long) (v1 & 0xFFFFFFFF),
		 v2);
}

EXPORT_SYMBOL(trace_special_u64);

void notrace trace_special_sym(void)
{
#define STACK_ENTRIES 8
	unsigned long entries[STACK_ENTRIES];
	struct stack_trace trace;

	if (!trace_enabled || !stackframe_tracing)
		return;

	trace.entries = entries;
	trace.skip = 3;
	trace.max_entries = STACK_ENTRIES;
	trace.nr_entries = 0;

	save_stack_trace(&trace);
	/*
	 * clear out the rest:
	 */
	while (trace.nr_entries < trace.max_entries)
		entries[trace.nr_entries++] = 0;

	___trace(TRACE_SPECIAL_SYM, entries[0], 0,
					entries[1], entries[2], entries[3]);
	___trace(TRACE_SPECIAL_SYM, entries[4], 0,
					entries[5], entries[6], entries[7]);
}

EXPORT_SYMBOL(trace_special_sym);

/*
 * Non-inlined function:
 */
void notrace __trace(unsigned long eip, unsigned long parent_eip)
{
	___trace(TRACE_FN, eip, parent_eip, 0, 0, 0);
}

#ifdef CONFIG_MCOUNT

extern void mcount(void);

EXPORT_SYMBOL(mcount);

void notrace __mcount(void)
{
	___trace(TRACE_FN, CALLER_ADDR1, CALLER_ADDR2, 0, 0, 0);
}

#endif

void notrace
sys_call(unsigned long nr, unsigned long p1, unsigned long p2, unsigned long p3)
{
	if (syscall_tracing)
		___trace(TRACE_SYSCALL, nr, 0, p1, p2, p3);
}

#if defined(CONFIG_COMPAT) && defined(CONFIG_X86)

void notrace
sys_ia32_call(unsigned long nr, unsigned long p1, unsigned long p2,
	      unsigned long p3)
{
	if (syscall_tracing)
		___trace(TRACE_SYSCALL, nr | 0x80000000, 0, p1, p2, p3);
}

#endif

void notrace sys_ret(unsigned long ret)
{
	if (syscall_tracing)
		___trace(TRACE_SYSRET, ret, 0, 0, 0, 0);
}

static void notrace print_name(struct seq_file *m, unsigned long eip)
{
	char namebuf[KSYM_NAME_LEN+1];
	unsigned long size, offset;
	const char *sym_name;
	char *modname;

	/*
	 * Special trace values:
	 */
	if (((long)eip < 100000L) && ((long)eip > -100000L)) {
		seq_printf(m, "(%5ld)", eip);
		return;
	}
	sym_name = kallsyms_lookup(eip, &size, &offset, &modname, namebuf);
	if (sym_name)
		seq_puts(m, sym_name);
	else
		seq_printf(m, "<%08lx>", eip);
}

static void notrace print_name_offset(struct seq_file *m, unsigned long eip)
{
	char namebuf[KSYM_NAME_LEN+1];
	unsigned long size, offset;
	const char *sym_name;
	char *modname;

	sym_name = kallsyms_lookup(eip, &size, &offset, &modname, namebuf);
	if (sym_name)
		seq_printf(m, "%s+%#lx/%#lx <%08lx>",
					sym_name, offset, size, eip);
	else
		seq_printf(m, "<%08lx>", eip);
}

static unsigned long out_sequence = -1;

static int pid_to_cmdline_array[PID_MAX_DEFAULT+1];

static void notrace _trace_cmdline(int cpu, struct cpu_trace *tr)
{
	unsigned long flags;

	local_save_flags(flags);
	____trace(cpu, TRACE_CMDLINE, tr, 0, 0, 0, 0, 0, flags);
}

void notrace trace_cmdline(void)
{
	___trace(TRACE_CMDLINE, 0, 0, 0, 0, 0);
}

static void construct_pid_to_cmdline(struct cpu_trace *tr)
{
	unsigned int i, j, entries, pid;

	if (tr->critical_sequence == out_sequence)
		return;
	out_sequence = tr->critical_sequence;

	memset(pid_to_cmdline_array, -1, sizeof(int) * (PID_MAX_DEFAULT + 1));

	if (!tr->trace)
		return;

	entries = min(tr->trace_idx, MAX_TRACE);

	for (i = 0; i < entries; i++) {
		struct trace_entry *entry = tr->trace + i;

		if (entry->type != TRACE_CMDLINE)
			continue;
		pid = entry->pid;
		if (pid < PID_MAX_DEFAULT) {
			pid_to_cmdline_array[pid] = i;
			/*
			 * Replace space with underline - makes it easier
			 * to process for tools:
			 */
			for (j = 0; j < CMDLINE_BYTES; j++)
				if (entry->u.cmdline.str[j] == ' ')
					entry->u.cmdline.str[j] = '_';
		}
	}
}

char *pid_to_cmdline(unsigned long pid)
{
	struct cpu_trace *tr = out_tr.traces + 0;
	char *cmdline = "<...>";
	int idx;

	pid = min(pid, (unsigned long)PID_MAX_DEFAULT);
	if (!pid)
		return "<idle>";

	if (pid_to_cmdline_array[pid] != -1) {
		idx = pid_to_cmdline_array[pid];
		if (tr->trace[idx].type == TRACE_CMDLINE)
			cmdline = tr->trace[idx].u.cmdline.str;
	}
	return cmdline;
}

static void copy_trace(struct cpu_trace *save, struct cpu_trace *tr, int reorder)
{
	if (!save->trace || !tr->trace)
		return;
	/* free-running needs reordering */
	if (reorder && atomic_read(&tr->underrun)) {
		int i, idx, idx0 = tr->trace_idx;

		for (i = 0; i < MAX_TRACE; i++) {
			idx = (idx0 + i) % MAX_TRACE;
			save->trace[i] = tr->trace[idx];
		}
		save->trace_idx = MAX_TRACE;
	} else {
		save->trace_idx = tr->trace_idx;

		memcpy(save->trace, tr->trace,
			min(save->trace_idx, MAX_TRACE) *
					sizeof(struct trace_entry));
	}
	save->underrun = tr->underrun;
	save->overrun = tr->overrun;
}


struct block_idx {
	int idx[NR_CPUS];
};

/*
 * return the trace entry (position) of the smallest-timestamp
 * one (that is still in the valid idx range):
 */
static int min_idx(struct block_idx *bidx)
{
	cycle_t min_stamp = (cycle_t) -1;
	struct trace_entry *entry;
	int cpu, min_cpu = -1, idx;

	for_each_online_cpu(cpu) {
		idx = bidx->idx[cpu];
		if (idx >= min(max_tr.traces[cpu].trace_idx, MAX_TRACE))
			continue;
		if (idx >= MAX_TRACE*NR_CPUS) {
			printk("huh: idx (%d) > %ld*%d!\n", idx, MAX_TRACE,
				NR_CPUS);
			WARN_ON(1);
			break;
		}
		entry = max_tr.traces[cpu].trace + bidx->idx[cpu];
		if (entry->timestamp < min_stamp) {
			min_cpu = cpu;
			min_stamp = entry->timestamp;
		}
	}

	return min_cpu;
}

/*
 * This code is called to construct an output trace from
 * the maximum trace. Having separate traces serves both
 * atomicity (a new max might be saved while we are busy
 * accessing /proc/latency_trace) and it is also used to
 * delay the (expensive) sorting of the output trace by
 * timestamps, in the trace_all_cpus case.
 */
static void update_out_trace(void)
{
	struct trace_entry *out_entry, *entry, *tmp;
	cycle_t stamp, first_stamp, last_stamp;
	struct block_idx bidx = { { 0, }, };
	struct cpu_trace *tmp_max, *tmp_out;
	int cpu, sum, entries, underrun_sum, overrun_sum;

	/*
	 * For out_tr we only have the first array's trace entries
	 * allocated - and they have are larger on SMP to make room
	 * for all trace entries from all CPUs.
	 */
	tmp_out = out_tr.traces + 0;
	tmp_max = max_tr.traces + max_tr.cpu;
	/*
	 * Easier to copy this way. Note: the trace buffer is private
	 * to the output buffer, so preserve it:
	 */
	copy_trace(tmp_out, tmp_max, 0);
	tmp = tmp_out->trace;
	*tmp_out = *tmp_max;
	tmp_out->trace = tmp;

	out_tr.cpu = max_tr.cpu;

	if (!tmp_out->trace)
		return;

	out_entry = tmp_out->trace + 0;

	if (!trace_all_cpus) {
		entries = min(tmp_out->trace_idx, MAX_TRACE);
		if (!entries)
			return;
		out_tr.first_timestamp = tmp_out->trace[0].timestamp;
		out_tr.last_timestamp = tmp_out->trace[entries-1].timestamp;
		return;
	}
	/*
	 * Find the range of timestamps that are fully traced in
	 * all CPU traces. (since CPU traces can cover a variable
	 * range of time, we have to find the best range.)
	 */
	first_stamp = 0;
	for_each_online_cpu(cpu) {
		tmp_max = max_tr.traces + cpu;
		stamp = tmp_max->trace[0].timestamp;
		if (stamp > first_stamp)
			first_stamp = stamp;
	}
	/*
	 * Save the timestamp range:
	 */
	tmp_max = max_tr.traces + max_tr.cpu;
	entries = min(tmp_max->trace_idx, MAX_TRACE);
	/*
	 * No saved trace yet?
	 */
	if (!entries) {
		out_tr.traces[0].trace_idx = 0;
		return;
	}

	last_stamp = tmp_max->trace[entries-1].timestamp;

	if (last_stamp < first_stamp) {
		WARN_ON(1);

		for_each_online_cpu(cpu) {
			tmp_max = max_tr.traces + cpu;
			entries = min(tmp_max->trace_idx, MAX_TRACE);
			printk("CPU%d: %016Lx (%016Lx) ... #%d (%016Lx) %016Lx\n",
				cpu,
				tmp_max->trace[0].timestamp,
				tmp_max->trace[1].timestamp,
				entries,
				tmp_max->trace[entries-2].timestamp,
				tmp_max->trace[entries-1].timestamp);
		}
		tmp_max = max_tr.traces + max_tr.cpu;
		entries = min(tmp_max->trace_idx, MAX_TRACE);

		printk("CPU%d entries: %d\n", max_tr.cpu, entries);
		printk("first stamp: %016Lx\n", first_stamp);
		printk(" last stamp: %016Lx\n", first_stamp);
	}

#if 0
	printk("first_stamp: %Ld [%016Lx]\n", first_stamp, first_stamp);
	printk(" last_stamp: %Ld [%016Lx]\n", last_stamp, last_stamp);
	printk("   +1 stamp: %Ld [%016Lx]\n",
		tmp_max->trace[entries].timestamp,
		tmp_max->trace[entries].timestamp);
	printk("   +2 stamp: %Ld [%016Lx]\n",
		tmp_max->trace[entries+1].timestamp,
		tmp_max->trace[entries+1].timestamp);
	printk("      delta: %Ld\n", last_stamp-first_stamp);
	printk("    entries: %d\n", entries);
#endif

	out_tr.first_timestamp = first_stamp;
	out_tr.last_timestamp = last_stamp;

	/*
	 * Fetch trace entries one by one, in increasing timestamp
	 * order. Start at first_stamp, stop at last_stamp:
	 */
	sum = 0;
	for (;;) {
		cpu = min_idx(&bidx);
		if (cpu == -1)
			break;
		entry = max_tr.traces[cpu].trace + bidx.idx[cpu];
		if (entry->timestamp > last_stamp)
			break;

		bidx.idx[cpu]++;
		if (entry->timestamp < first_stamp)
			continue;
		*out_entry = *entry;
		out_entry++;
		sum++;
		if (sum >= MAX_TRACE*NR_CPUS) {
			printk("huh: sum (%d) > %ld*%d!\n", sum, MAX_TRACE,
				NR_CPUS);
			WARN_ON(1);
			break;
		}
	}

	sum = 0;
	underrun_sum = 0;
	overrun_sum = 0;
	for_each_online_cpu(cpu) {
		sum += max_tr.traces[cpu].trace_idx;
		underrun_sum += atomic_read(&max_tr.traces[cpu].underrun);
		overrun_sum += atomic_read(&max_tr.traces[cpu].overrun);
	}
	tmp_out->trace_idx = sum;
	atomic_set(&tmp_out->underrun, underrun_sum);
	atomic_set(&tmp_out->overrun, overrun_sum);
}

static void notrace print_help_header(struct seq_file *m)
{
	seq_puts(m, "                 _------=> CPU#            \n");
	seq_puts(m, "                / _-----=> irqs-off        \n");
	seq_puts(m, "               | / _----=> need-resched    \n");
	seq_puts(m, "               || / _---=> hardirq/softirq \n");
	seq_puts(m, "               ||| / _--=> preempt-depth   \n");
	seq_puts(m, "               |||| /                      \n");
	seq_puts(m, "               |||||     delay             \n");
	seq_puts(m, "   cmd     pid ||||| time  |   caller      \n");
	seq_puts(m, "      \\   /    |||||   \\   |   /           \n");
}

static void * notrace l_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;
	unsigned long entries;
	struct cpu_trace *tr = out_tr.traces + 0;

	down(&out_mutex);
	/*
	 * if the file is being read newly, update the output trace:
	 */
	if (!n) {
		// TODO: use the sequence counter here to optimize
		down(&max_mutex);
		update_out_trace();
		up(&max_mutex);
#if 0
		if (!tr->trace_idx) {
			up(&out_mutex);
			return NULL;
		}
#endif
		construct_pid_to_cmdline(tr);
	}
	entries = min(tr->trace_idx, MAX_TRACE);

	if (!n) {
		seq_printf(m, "preemption latency trace v1.1.5 on %s\n",
			   UTS_RELEASE);
		seq_puts(m, "--------------------------------------------------------------------\n");
		seq_printf(m, " latency: %lu us, #%lu/%lu, CPU#%d | (M:%s VP:%d, KP:%d, SP:%d HP:%d",
			cycles_to_usecs(tr->saved_latency),
			entries,
			(entries + atomic_read(&tr->underrun) +
			 atomic_read(&tr->overrun)),
			out_tr.cpu,
#if defined(CONFIG_PREEMPT_NONE)
			"server",
#elif defined(CONFIG_PREEMPT_VOLUNTARY)
			"desktop",
#elif defined(CONFIG_PREEMPT_DESKTOP)
			"preempt",
#else
			"rt",
#endif
			0, 0,
#ifdef CONFIG_PREEMPT_SOFTIRQS
			softirq_preemption
#else
			0
#endif
			,
#ifdef CONFIG_PREEMPT_HARDIRQS
 hardirq_preemption
#else
			0
#endif
		);
#ifdef CONFIG_SMP
		seq_printf(m, " #P:%d)\n", num_online_cpus());
#else
		seq_puts(m, ")\n");
#endif
		seq_puts(m, "    -----------------\n");
		seq_printf(m, "    | task: %.16s-%d (uid:%ld nice:%ld policy:%ld rt_prio:%ld)\n",
			tr->comm, tr->pid, tr->uid, tr->nice,
			tr->policy, tr->rt_priority);
		seq_puts(m, "    -----------------\n");
		if (trace_user_triggered) {
			seq_puts(m, " => started at: ");
			print_name_offset(m, tr->critical_start);
			seq_puts(m, "\n => ended at:   ");
			print_name_offset(m, tr->critical_end);
			seq_puts(m, "\n");
		}
		seq_puts(m, "\n");

		if (!trace_verbose)
			print_help_header(m);
	}
	if (n >= entries || !tr->trace)
		return NULL;

	return tr->trace + n;
}

static void * notrace l_next(struct seq_file *m, void *p, loff_t *pos)
{
	struct cpu_trace *tr = out_tr.traces;
	unsigned long entries = min(tr->trace_idx, MAX_TRACE);

	WARN_ON(!tr->trace);

	if (++*pos >= entries) {
		if (*pos == entries)
			seq_puts(m, "\n\nvim:ft=help\n");
		return NULL;
	}
	return tr->trace + *pos;
}

static void notrace l_stop(struct seq_file *m, void *p)
{
	up(&out_mutex);
}

static void print_timestamp(struct seq_file *m, unsigned long abs_usecs,
						unsigned long rel_usecs)
{
	seq_printf(m, " %4ldus", abs_usecs);
	if (rel_usecs > 100)
		seq_puts(m, "!: ");
	else if (rel_usecs > 1)
		seq_puts(m, "+: ");
	else
		seq_puts(m, " : ");
}

static void
print_timestamp_short(struct seq_file *m, unsigned long abs_usecs,
			unsigned long rel_usecs)
{
	seq_printf(m, " %4ldus", abs_usecs);
	if (rel_usecs > 100)
		seq_putc(m, '!');
	else if (rel_usecs > 1)
		seq_putc(m, '+');
	else
		seq_putc(m, ' ');
}

static void
print_generic(struct seq_file *m, struct trace_entry *entry)
{
	int hardirq, softirq;

	seq_printf(m, "%8.8s-%-5d ", pid_to_cmdline(entry->pid), entry->pid);
	seq_printf(m, "%d", entry->cpu);
	seq_printf(m, "%c%c",
		(entry->flags & TRACE_FLAG_IRQS_OFF) ? 'd' :
		(entry->flags & TRACE_FLAG_IRQS_HARD_OFF) ? 'D' : '.',
		(entry->flags & TRACE_FLAG_NEED_RESCHED_DELAYED) ? 'n' :
 		((entry->flags & TRACE_FLAG_NEED_RESCHED) ? 'N' : '.'));

	hardirq = entry->flags & TRACE_FLAG_HARDIRQ;
	softirq = entry->flags & TRACE_FLAG_SOFTIRQ;
	if (hardirq && softirq)
		seq_putc(m, 'H');
	else {
		if (hardirq)
			seq_putc(m, 'h');
		else {
			if (softirq)
				seq_putc(m, 's');
			else
				seq_putc(m, '.');
		}
	}

	if (entry->preempt_count)
		seq_printf(m, "%x", entry->preempt_count);
	else
		seq_puts(m, ".");
}


static int notrace l_show_fn(struct seq_file *m, unsigned long trace_idx,
		struct trace_entry *entry, struct trace_entry *entry0,
		struct trace_entry *next_entry)
{
	unsigned long abs_usecs, rel_usecs;

	abs_usecs = cycles_to_us(entry->timestamp - entry0->timestamp);
	rel_usecs = cycles_to_us(next_entry->timestamp - entry->timestamp);

	if (trace_verbose) {
		seq_printf(m, "%16s %5d %d %d %08x %08lx [%016Lx] %ld.%03ldms (+%ld.%03ldms): ",
			pid_to_cmdline(entry->pid),
			entry->pid, entry->cpu, entry->flags,
			entry->preempt_count, trace_idx,
			entry->timestamp, abs_usecs/1000,
			abs_usecs % 1000, rel_usecs/1000, rel_usecs % 1000);
		print_name_offset(m, entry->u.fn.eip);
		seq_puts(m, " (");
		print_name_offset(m, entry->u.fn.parent_eip);
		seq_puts(m, ")\n");
	} else {
		print_generic(m, entry);
		print_timestamp(m, abs_usecs, rel_usecs);
		print_name(m, entry->u.fn.eip);
		seq_puts(m, " (");
		print_name(m, entry->u.fn.parent_eip);
		seq_puts(m, ")\n");
	}
	return 0;
}

static int notrace l_show_special(struct seq_file *m, unsigned long trace_idx,
		struct trace_entry *entry, struct trace_entry *entry0,
		struct trace_entry *next_entry, int mode64)
{
	unsigned long abs_usecs, rel_usecs;

	abs_usecs = cycles_to_us(entry->timestamp - entry0->timestamp);
	rel_usecs = cycles_to_us(next_entry->timestamp - entry->timestamp);

	print_generic(m, entry);
	print_timestamp(m, abs_usecs, rel_usecs);
	if (trace_verbose)
		print_name_offset(m, entry->u.special.eip);
	else
		print_name(m, entry->u.special.eip);

	if (!mode64) {
		/*
		 * For convenience, print small numbers in decimal:
		 */
		if (abs((int)entry->u.special.v1) < 100000)
			seq_printf(m, " (%5ld ", entry->u.special.v1);
		else
			seq_printf(m, " (%lx ", entry->u.special.v1);
		if (abs((int)entry->u.special.v2) < 100000)
			seq_printf(m, "%5ld ", entry->u.special.v2);
		else
			seq_printf(m, "%lx ", entry->u.special.v2);
		if (abs((int)entry->u.special.v3) < 100000)
			seq_printf(m, "%5ld)\n", entry->u.special.v3);
		else
			seq_printf(m, "%lx)\n", entry->u.special.v3);
	} else {
		seq_printf(m, " (%13Ld %ld)\n",
			   ((u64)entry->u.special.v1 << 32)
			   + (u64)entry->u.special.v2, entry->u.special.v3);
	}
	return 0;
}

static int notrace
l_show_special_pid(struct seq_file *m, unsigned long trace_idx,
		struct trace_entry *entry, struct trace_entry *entry0,
		struct trace_entry *next_entry)
{
	unsigned long abs_usecs, rel_usecs;
	unsigned int pid;

	pid = entry->u.special.v1;

	abs_usecs = cycles_to_us(entry->timestamp - entry0->timestamp);
	rel_usecs = cycles_to_us(next_entry->timestamp - entry->timestamp);

	print_generic(m, entry);
	print_timestamp(m, abs_usecs, rel_usecs);
	if (trace_verbose)
		print_name_offset(m, entry->u.special.eip);
	else
		print_name(m, entry->u.special.eip);
	seq_printf(m, " <%.8s-%d> (%ld %ld)\n",
		pid_to_cmdline(pid), pid,
		entry->u.special.v2, entry->u.special.v3);

	return 0;
}

static int notrace
l_show_special_sym(struct seq_file *m, unsigned long trace_idx,
		   struct trace_entry *entry, struct trace_entry *entry0,
		   struct trace_entry *next_entry, int mode64)
{
	unsigned long abs_usecs, rel_usecs;

	abs_usecs = cycles_to_us(entry->timestamp - entry0->timestamp);
	rel_usecs = cycles_to_us(next_entry->timestamp - entry->timestamp);

	print_generic(m, entry);
	print_timestamp(m, abs_usecs, rel_usecs);
	if (trace_verbose)
		print_name_offset(m, entry->u.special.eip);
	else
		print_name(m, entry->u.special.eip);

	seq_puts(m, "()<-");
	print_name(m, entry->u.special.v1);
	seq_puts(m, "()<-");
	print_name(m, entry->u.special.v2);
	seq_puts(m, "()<-");
	print_name(m, entry->u.special.v3);
	seq_puts(m, "()\n");

	return 0;
}


static int notrace l_show_cmdline(struct seq_file *m, unsigned long trace_idx,
		struct trace_entry *entry, struct trace_entry *entry0,
		struct trace_entry *next_entry)
{
	unsigned long abs_usecs, rel_usecs;

	if (!trace_verbose)
		return 0;

	abs_usecs = cycles_to_us(entry->timestamp - entry0->timestamp);
	rel_usecs = cycles_to_us(next_entry->timestamp - entry->timestamp);

	seq_printf(m,
		"[ => %16s ] %ld.%03ldms (+%ld.%03ldms)\n",
			entry->u.cmdline.str,
			abs_usecs/1000, abs_usecs % 1000,
			rel_usecs/1000, rel_usecs % 1000);

	return 0;
}

extern unsigned long sys_call_table[NR_syscalls];

#if defined(CONFIG_COMPAT) && defined(CONFIG_X86)
extern unsigned long ia32_sys_call_table[], ia32_syscall_end[];
#define IA32_NR_syscalls (ia32_syscall_end - ia32_sys_call_table)
#endif

static int notrace l_show_syscall(struct seq_file *m, unsigned long trace_idx,
		struct trace_entry *entry, struct trace_entry *entry0,
		struct trace_entry *next_entry)
{
	unsigned long abs_usecs, rel_usecs;
	unsigned long nr;

	abs_usecs = cycles_to_us(entry->timestamp - entry0->timestamp);
	rel_usecs = cycles_to_us(next_entry->timestamp - entry->timestamp);

	print_generic(m, entry);
	print_timestamp_short(m, abs_usecs, rel_usecs);

	seq_puts(m, "> ");
	nr = entry->u.syscall.nr;
#if defined(CONFIG_COMPAT) && defined(CONFIG_X86)
	if (nr & 0x80000000) {
		nr &= ~0x80000000;
		if (nr < IA32_NR_syscalls)
			print_name(m, ia32_sys_call_table[nr]);
		else
			seq_printf(m, "<badsys(%lu)>", nr);
	} else
#endif
	if (nr < NR_syscalls)
		print_name(m, sys_call_table[nr]);
	else
		seq_printf(m, "<badsys(%lu)>", nr);

#ifdef CONFIG_64BIT
	seq_printf(m, " (%016lx %016lx %016lx)\n",
		entry->u.syscall.p1, entry->u.syscall.p2, entry->u.syscall.p3);
#else
	seq_printf(m, " (%08lx %08lx %08lx)\n",
		entry->u.syscall.p1, entry->u.syscall.p2, entry->u.syscall.p3);
#endif

	return 0;
}

static int notrace l_show_sysret(struct seq_file *m, unsigned long trace_idx,
		struct trace_entry *entry, struct trace_entry *entry0,
		struct trace_entry *next_entry)
{
	unsigned long abs_usecs, rel_usecs;

	abs_usecs = cycles_to_us(entry->timestamp - entry0->timestamp);
	rel_usecs = cycles_to_us(next_entry->timestamp - entry->timestamp);

	print_generic(m, entry);
	print_timestamp_short(m, abs_usecs, rel_usecs);

	seq_printf(m, "< (%ld)\n", entry->u.sysret.ret);

	return 0;
}


static int notrace l_show(struct seq_file *m, void *p)
{
	struct cpu_trace *tr = out_tr.traces;
	struct trace_entry *entry, *entry0, *next_entry;
	unsigned long trace_idx;

	cond_resched();
	entry = p;
	if (entry->timestamp < out_tr.first_timestamp)
		return 0;
	if (entry->timestamp > out_tr.last_timestamp)
		return 0;

	entry0 = tr->trace;
	trace_idx = entry - entry0;

	if (trace_idx + 1 < tr->trace_idx)
		next_entry = entry + 1;
	else
		next_entry = entry;

	if (trace_verbose)
		seq_printf(m, "(T%d/#%ld) ", entry->type, trace_idx);

	switch (entry->type) {
		case TRACE_FN:
			l_show_fn(m, trace_idx, entry, entry0, next_entry);
			break;
		case TRACE_SPECIAL:
			l_show_special(m, trace_idx, entry, entry0, next_entry, 0);
			break;
		case TRACE_SPECIAL_PID:
			l_show_special_pid(m, trace_idx, entry, entry0, next_entry);
			break;
		case TRACE_SPECIAL_U64:
			l_show_special(m, trace_idx, entry, entry0, next_entry, 1);
			break;
		case TRACE_SPECIAL_SYM:
			l_show_special_sym(m, trace_idx, entry, entry0,
					   next_entry, 1);
			break;
		case TRACE_CMDLINE:
			l_show_cmdline(m, trace_idx, entry, entry0, next_entry);
			break;
		case TRACE_SYSCALL:
			l_show_syscall(m, trace_idx, entry, entry0, next_entry);
			break;
		case TRACE_SYSRET:
			l_show_sysret(m, trace_idx, entry, entry0, next_entry);
			break;
		default:
			seq_printf(m, "unknown trace type %d\n", entry->type);
	}
	return 0;
}

struct seq_operations latency_trace_op = {
	.start	= l_start,
	.next	= l_next,
	.stop	= l_stop,
	.show	= l_show
};

/*
 * Copy the new maximum trace into the separate maximum-trace
 * structure. (this way the maximum trace is permanently saved,
 * for later retrieval via /proc/latency_trace)
 */
static void update_max_tr(struct cpu_trace *tr)
{
	struct cpu_trace *save;
	int cpu, all_cpus = 0;

#ifdef CONFIG_PREEMPT
	WARN_ON(!preempt_count() && !irqs_disabled());
#endif

	max_tr.cpu = tr->cpu;
	save = max_tr.traces + tr->cpu;

	if ((wakeup_timing || trace_user_triggered || trace_print_on_crash ||
	     print_functions) && trace_all_cpus) {
		all_cpus = 1;
		for_each_online_cpu(cpu)
			atomic_inc(&cpu_traces[cpu].disabled);
	}

	save->saved_latency = preempt_max_latency;
	save->preempt_timestamp = tr->preempt_timestamp;
	save->critical_start = tr->critical_start;
	save->critical_end = tr->critical_end;
	save->critical_sequence = tr->critical_sequence;

	memcpy(save->comm, current->comm, CMDLINE_BYTES);
	save->pid = current->pid;
	save->uid = current->uid;
	save->nice = current->static_prio - 20 - MAX_RT_PRIO;
	save->policy = current->policy;
	save->rt_priority = current->rt_priority;

	if (all_cpus) {
		for_each_online_cpu(cpu) {
			copy_trace(max_tr.traces + cpu, cpu_traces + cpu, 1);
			atomic_dec(&cpu_traces[cpu].disabled);
		}
	} else
		copy_trace(save, tr, 1);
}

#else /* !EVENT_TRACE */

static inline void notrace
____trace(int cpu, enum trace_type type, struct cpu_trace *tr,
	  unsigned long eip, unsigned long parent_eip,
	  unsigned long v1, unsigned long v2, unsigned long v3,
	  unsigned long flags)
{
}

static inline void notrace
___trace(enum trace_type type, unsigned long eip, unsigned long parent_eip,
		unsigned long v1, unsigned long v2,
			unsigned long v3)
{
}

static inline void notrace __trace(unsigned long eip, unsigned long parent_eip)
{
}

static inline void update_max_tr(struct cpu_trace *tr)
{
}

static inline void notrace _trace_cmdline(int cpu, struct cpu_trace *tr)
{
}

#endif

static int setup_preempt_thresh(char *s)
{
	int thresh;

	get_option(&s, &thresh);
	if (thresh > 0) {
		preempt_thresh = usecs_to_cycles(thresh);
		printk("Preemption threshold = %u us\n", thresh);
	}
	return 1;
}
__setup("preempt_thresh=", setup_preempt_thresh);

static inline void notrace reset_trace_idx(int cpu, struct cpu_trace *tr)
{
	if (trace_all_cpus)
		for_each_online_cpu(cpu) {
			tr = cpu_traces + cpu;
			tr->trace_idx = 0;
			atomic_set(&tr->underrun, 0);
			atomic_set(&tr->overrun, 0);
		}
	else{
		tr->trace_idx = 0;
		atomic_set(&tr->underrun, 0);
		atomic_set(&tr->overrun, 0);
	}
}

#ifdef CONFIG_CRITICAL_TIMING

static void notrace
check_critical_timing(int cpu, struct cpu_trace *tr, unsigned long parent_eip)
{
	unsigned long latency, t0, t1;
	cycle_t T0, T1, T2, delta;
	unsigned long flags;

	if (trace_user_triggered)
		return;
	/*
	 * usecs conversion is slow so we try to delay the conversion
	 * as long as possible:
	 */
	T0 = tr->preempt_timestamp;
	T1 = get_monotonic_cycles();
	delta = T1-T0;

	local_save_flags(flags);

	if (!report_latency(delta))
		goto out;

	____trace(cpu, TRACE_FN, tr, CALLER_ADDR0, parent_eip, 0, 0, 0, flags);
	/*
	 * Update the timestamp, because the trace entry above
	 * might change it (it can only get larger so the latency
	 * is fair to be reported):
	 */
	T2 = get_monotonic_cycles();

	delta = T2-T0;

	latency = cycles_to_usecs(delta);
	latency_hist(tr->latency_type, cpu, latency);

	if (latency_hist_flag) {
		if (preempt_max_latency >= delta)
			goto out;
	}

	if (tr->critical_sequence != max_sequence || down_trylock(&max_mutex))
		goto out;

#ifndef CONFIG_CRITICAL_LATENCY_HIST
	if (!preempt_thresh && preempt_max_latency > delta) {
		printk("bug: updating %016Lx > %016Lx?\n",
			preempt_max_latency, delta);
		printk("  [%016Lx %016Lx %016Lx]\n", T0, T1, T2);
	}
#endif

	preempt_max_latency = delta;
	t0 = cycles_to_usecs(T0);
	t1 = cycles_to_usecs(T1);

	tr->critical_end = parent_eip;

	update_max_tr(tr);

#ifndef CONFIG_CRITICAL_LATENCY_HIST
	if (preempt_thresh)
		printk("(%16s-%-5d|#%d): %lu us critical section "
			"violates %lu us threshold.\n"
			" => started at timestamp %lu: ",
				current->comm, current->pid,
				raw_smp_processor_id(),
				latency, cycles_to_usecs(preempt_thresh), t0);
	else
		printk("(%16s-%-5d|#%d): new %lu us maximum-latency "
			"critical section.\n => started at timestamp %lu: ",
				current->comm, current->pid,
				raw_smp_processor_id(),
				latency, t0);

	print_symbol("<%s>\n", tr->critical_start);
	printk(" =>   ended at timestamp %lu: ", t1);
	print_symbol("<%s>\n", tr->critical_end);
	dump_stack();
	t1 = cycles_to_usecs(get_monotonic_cycles());
	printk(" =>   dump-end timestamp %lu\n\n", t1);
#endif

	max_sequence++;

	up(&max_mutex);

out:
	tr->critical_sequence = max_sequence;
	tr->preempt_timestamp = get_monotonic_cycles();
	tr->early_warning = 0;
	reset_trace_idx(cpu, tr);
	_trace_cmdline(cpu, tr);
	____trace(cpu, TRACE_FN, tr, CALLER_ADDR0, parent_eip, 0, 0, 0, flags);
}

void notrace touch_critical_timing(void)
{
	int cpu = raw_smp_processor_id();
	struct cpu_trace *tr = cpu_traces + cpu;

	if (!tr->critical_start || atomic_read(&tr->disabled) ||
			trace_user_triggered || wakeup_timing)
		return;

	if (preempt_count() > 0 && tr->critical_start) {
		atomic_inc(&tr->disabled);
		check_critical_timing(cpu, tr, CALLER_ADDR0);
		tr->critical_start = CALLER_ADDR0;
		tr->critical_sequence = max_sequence;
		atomic_dec(&tr->disabled);
	}
}
EXPORT_SYMBOL(touch_critical_timing);

void notrace stop_critical_timing(void)
{
	struct cpu_trace *tr = cpu_traces + raw_smp_processor_id();

	tr->critical_start = 0;
}
EXPORT_SYMBOL(stop_critical_timing);

static inline void notrace
__start_critical_timing(unsigned long eip, unsigned long parent_eip,
			int latency_type)
{
	int cpu = raw_smp_processor_id();
	struct cpu_trace *tr = cpu_traces + cpu;
	unsigned long flags;

	if (tr->critical_start || atomic_read(&tr->disabled) ||
			trace_user_triggered || wakeup_timing)
		return;

	atomic_inc(&tr->disabled);

	tr->critical_sequence = max_sequence;
	tr->preempt_timestamp = get_monotonic_cycles();
	tr->critical_start = eip;
	reset_trace_idx(cpu, tr);
	tr->latency_type = latency_type;
	_trace_cmdline(cpu, tr);

	local_save_flags(flags);
	____trace(cpu, TRACE_FN, tr, eip, parent_eip, 0, 0, 0, flags);

	atomic_dec(&tr->disabled);
}

static inline void notrace
__stop_critical_timing(unsigned long eip, unsigned long parent_eip)
{
	int cpu = raw_smp_processor_id();
	struct cpu_trace *tr = cpu_traces + cpu;
	unsigned long flags;

	if (!tr->critical_start || atomic_read(&tr->disabled) ||
			trace_user_triggered || wakeup_timing)
		return;

	atomic_inc(&tr->disabled);
	local_save_flags(flags);
	____trace(cpu, TRACE_FN, tr, eip, parent_eip, 0, 0, 0, flags);
	check_critical_timing(cpu, tr, eip);
	tr->critical_start = 0;
	atomic_dec(&tr->disabled);
}

#endif

#ifdef CONFIG_CRITICAL_IRQSOFF_TIMING

#ifdef CONFIG_LOCKDEP

void notrace time_hardirqs_on(unsigned long a0, unsigned long a1)
{
	unsigned long flags;

	local_save_flags(flags);

	if (!irqs_off_preempt_count() && irqs_disabled_flags(flags))
		__stop_critical_timing(a0, a1);
}

void notrace time_hardirqs_off(unsigned long a0, unsigned long a1)
{
	unsigned long flags;

	local_save_flags(flags);

	if (!irqs_off_preempt_count() && irqs_disabled_flags(flags))
		__start_critical_timing(a0, a1, INTERRUPT_LATENCY);
}

#else /* !CONFIG_LOCKDEP */

/*
 * Dummy:
 */

void early_boot_irqs_off(void)
{
}

void early_boot_irqs_on(void)
{
}

void trace_softirqs_on(unsigned long ip)
{
}

void trace_softirqs_off(unsigned long ip)
{
}

inline void print_irqtrace_events(struct task_struct *curr)
{
}

/*
 * We are only interested in hardirq on/off events:
 */
void notrace trace_hardirqs_on(void)
{
	unsigned long flags;

	local_save_flags(flags);

	if (!irqs_off_preempt_count() && irqs_disabled_flags(flags))
		__stop_critical_timing(CALLER_ADDR0, 0 /* CALLER_ADDR1 */);
}

EXPORT_SYMBOL(trace_hardirqs_on);

void notrace trace_hardirqs_off(void)
{
	unsigned long flags;

	local_save_flags(flags);

	if (!irqs_off_preempt_count() && irqs_disabled_flags(flags))
		__start_critical_timing(CALLER_ADDR0, 0 /* CALLER_ADDR1 */,
					INTERRUPT_LATENCY);
}

EXPORT_SYMBOL(trace_hardirqs_off);

#endif /* !CONFIG_LOCKDEP */

#endif /* CONFIG_CRITICAL_IRQSOFF_TIMING */

#if defined(CONFIG_DEBUG_PREEMPT) || defined(CONFIG_CRITICAL_TIMING)

static inline unsigned long get_parent_eip(void)
{
	unsigned long parent_eip = CALLER_ADDR1;

	if (in_lock_functions(parent_eip)) {
		parent_eip = CALLER_ADDR2;
		if (in_lock_functions(parent_eip))
			parent_eip = CALLER_ADDR3;
	}

	return parent_eip;
}

void notrace add_preempt_count(unsigned int val)
{
	unsigned long eip = CALLER_ADDR0;
	unsigned long parent_eip = get_parent_eip();

#ifdef CONFIG_DEBUG_PREEMPT
	/*
	 * Underflow?
	 */
	if (DEBUG_WARN_ON(((int)preempt_count() < 0)))
		return;
	/*
	 * Spinlock count overflowing soon?
	 */
	if (DEBUG_WARN_ON((preempt_count() & PREEMPT_MASK) >= PREEMPT_MASK-10))
		return;
#endif

	preempt_count() += val;
#ifdef CONFIG_PREEMPT_TRACE
	if (val <= 10) {
		unsigned int idx = preempt_count() & PREEMPT_MASK;
		if (idx < MAX_PREEMPT_TRACE) {
			current->preempt_trace_eip[idx] = eip;
			current->preempt_trace_parent_eip[idx] = parent_eip;
		}
	}
#endif
#ifdef CONFIG_CRITICAL_PREEMPT_TIMING
	{
#ifdef CONFIG_CRITICAL_IRQSOFF_TIMING
		unsigned long flags;

		local_save_flags(flags);

		if (!irqs_disabled_flags(flags))
#endif
			if (preempt_count() == val)
				__start_critical_timing(eip, parent_eip,
							PREEMPT_LATENCY);
	}
#endif
	(void)eip, (void)parent_eip;
}
EXPORT_SYMBOL(add_preempt_count);

void notrace sub_preempt_count(unsigned int val)
{
#ifdef CONFIG_DEBUG_PREEMPT
	/*
	 * Underflow?
	 */
	if (DEBUG_WARN_ON(unlikely(val > preempt_count())))
		return;
	/*
	 * Is the spinlock portion underflowing?
	 */
	if (DEBUG_WARN_ON((val < PREEMPT_MASK) &&
			  !(preempt_count() & PREEMPT_MASK)))
		return;
#endif

#ifdef CONFIG_CRITICAL_PREEMPT_TIMING
	{
#ifdef CONFIG_CRITICAL_IRQSOFF_TIMING
		unsigned long flags;

		local_save_flags(flags);

		if (!irqs_disabled_flags(flags))
#endif
			if (preempt_count() == val)
				__stop_critical_timing(CALLER_ADDR0,
						       CALLER_ADDR1);
	}
#endif
	preempt_count() -= val;
}

EXPORT_SYMBOL(sub_preempt_count);

void notrace mask_preempt_count(unsigned int mask)
{
	unsigned long eip = CALLER_ADDR0;
	unsigned long parent_eip = get_parent_eip();

	preempt_count() |= mask;

#ifdef CONFIG_CRITICAL_PREEMPT_TIMING
	{
#ifdef CONFIG_CRITICAL_IRQSOFF_TIMING
		unsigned long flags;

		local_save_flags(flags);

		if (!irqs_disabled_flags(flags))
#endif
			if (preempt_count() == mask)
				__start_critical_timing(eip, parent_eip,
							PREEMPT_LATENCY);
	}
#endif
	(void) eip, (void) parent_eip;
}
EXPORT_SYMBOL(mask_preempt_count);

void notrace unmask_preempt_count(unsigned int mask)
{
#ifdef CONFIG_CRITICAL_PREEMPT_TIMING
	{
#ifdef CONFIG_CRITICAL_IRQSOFF_TIMING
		unsigned long flags;

		local_save_flags(flags);

		if (!irqs_disabled_flags(flags))
#endif
			if (preempt_count() == mask)
				__stop_critical_timing(CALLER_ADDR0,
						       CALLER_ADDR1);
	}
#endif
	preempt_count() &= ~mask;
}
EXPORT_SYMBOL(unmask_preempt_count);


#endif

/*
 * Wakeup latency timing/tracing. We get upcalls from the scheduler
 * when a task is being woken up and we time/trace it until it gets
 * to a CPU - or an even-higher-prio task supercedes it. (in that
 * case we throw away the currently traced task - we dont try to
 * handle nesting, that simplifies things significantly)
 */
#ifdef CONFIG_WAKEUP_TIMING

static void notrace
check_wakeup_timing(struct cpu_trace *tr, unsigned long parent_eip,
		    unsigned long *flags)
{
	int cpu = raw_smp_processor_id();
	unsigned long latency, t0, t1;
	cycle_t T0, T1, delta;

	if (trace_user_triggered)
		return;

	atomic_inc(&tr->disabled);
	if (atomic_read(&tr->disabled) != 1)
		goto out;

	T0 = tr->preempt_timestamp;
	T1 = get_monotonic_cycles();
	/*
	 * Any wraparound or time warp and we are out:
	 */
	if (T0 > T1)
		goto out;
	delta = T1-T0;

	if (!report_latency(delta))
		goto out;

	____trace(smp_processor_id(), TRACE_FN, tr, CALLER_ADDR0, parent_eip,
		  0, 0, 0, *flags);

	latency = cycles_to_usecs(delta);
	latency_hist(tr->latency_type, cpu, latency);

	if (latency_hist_flag) {
		if (preempt_max_latency >= delta)
			goto out;
	}

	if (tr->critical_sequence != max_sequence || down_trylock(&max_mutex))
		goto out;

#ifndef CONFIG_WAKEUP_LATENCY_HIST
	if (!preempt_thresh && preempt_max_latency > delta) {
		printk("bug2: updating %016lx > %016Lx?\n",
			preempt_max_latency, delta);
		printk("  [%016Lx %016Lx]\n", T0, T1);
	}
#endif

	preempt_max_latency = delta;
	t0 = cycles_to_usecs(T0);
	t1 = cycles_to_usecs(T1);
	tr->critical_end = parent_eip;

	update_max_tr(tr);

	atomic_dec(&tr->disabled);
	__raw_spin_unlock(&sch.trace_lock);
	local_irq_restore(*flags);

#ifndef CONFIG_WAKEUP_LATENCY_HIST
	if (preempt_thresh)
		printk("(%16s-%-5d|#%d): %lu us wakeup latency "
			"violates %lu us threshold.\n",
				current->comm, current->pid,
				raw_smp_processor_id(), latency,
				cycles_to_usecs(preempt_thresh));
	else
		printk("(%16s-%-5d|#%d): new %lu us maximum-latency "
			"wakeup.\n", current->comm, current->pid,
				raw_smp_processor_id(), latency);
#endif

	max_sequence++;

	up(&max_mutex);

	return;

out:
	atomic_dec(&tr->disabled);
	__raw_spin_unlock(&sch.trace_lock);
	local_irq_restore(*flags);
}

/*
 * Start wakeup latency tracing - called with the runqueue held
 * and interrupts disabled:
 */
void __trace_start_sched_wakeup(struct task_struct *p)
{
	struct cpu_trace *tr;
	int cpu;

	if (trace_user_triggered || !wakeup_timing) {
		trace_special_pid(p->pid, p->prio, -1);
		return;
	}

	__raw_spin_lock(&sch.trace_lock);
	if (sch.task && (sch.task->prio <= p->prio))
		goto out_unlock;

	/*
	 * New highest-prio task just woke up - start tracing:
	 */
	sch.task = p;
	cpu = task_cpu(p);
	sch.cpu = cpu;
	/*
	 * We keep using this CPU's trace buffer even if the task
	 * gets migrated to another CPU. Tracing only happens on
	 * the CPU that 'owns' the highest-prio task so it's
	 * fundamentally single-threaded.
	 */
	sch.tr = tr = cpu_traces + cpu;
	reset_trace_idx(cpu, tr);

//	if (!atomic_read(&tr->disabled)) {
		atomic_inc(&tr->disabled);
		tr->critical_sequence = max_sequence;
		tr->preempt_timestamp = get_monotonic_cycles();
		tr->latency_type = WAKEUP_LATENCY;
		tr->critical_start = CALLER_ADDR0;
		_trace_cmdline(raw_smp_processor_id(), tr);
		atomic_dec(&tr->disabled);
//	}

	mcount();
	trace_special_pid(p->pid, p->prio, cpu);
	trace_special_sym();
out_unlock:
	__raw_spin_unlock(&sch.trace_lock);
}

void trace_stop_sched_switched(struct task_struct *p)
{
	struct cpu_trace *tr;
	unsigned long flags;

	if (trace_user_triggered || !wakeup_timing)
		return;

	local_irq_save(flags);
	__raw_spin_lock(&sch.trace_lock);
	if (p == sch.task) {
		trace_special_pid(p->pid, p->prio, task_cpu(p));

		sch.task = NULL;
		tr = sch.tr;
		sch.tr = NULL;
		WARN_ON(!tr);
		/* auto-unlocks the spinlock: */
		check_wakeup_timing(tr, CALLER_ADDR0, &flags);
	} else {
		if (sch.task)
			trace_special_pid(sch.task->pid, sch.task->prio,
					  p->prio);
		if (sch.task && (sch.task->prio >= p->prio))
			sch.task = NULL;
		__raw_spin_unlock(&sch.trace_lock);
	}
	local_irq_restore(flags);
}

void trace_change_sched_cpu(struct task_struct *p, int new_cpu)
{
	unsigned long flags;

	if (!wakeup_timing)
		return;

	trace_special_pid(p->pid, task_cpu(p), new_cpu);
	trace_special_sym();
	local_irq_save(flags);
	__raw_spin_lock(&sch.trace_lock);
	if (p == sch.task && task_cpu(p) != new_cpu) {
		sch.cpu = new_cpu;
		trace_special(task_cpu(p), new_cpu, 0);
	}
	__raw_spin_unlock(&sch.trace_lock);
	local_irq_restore(flags);
}

#endif

#ifdef CONFIG_EVENT_TRACE

long user_trace_start(void)
{
	struct cpu_trace *tr;
	unsigned long flags;
	int cpu;

	if (!trace_user_triggered || trace_print_on_crash || print_functions)
		return -EINVAL;

	/*
	 * If the user has not yet reset the max latency after
	 * bootup then we assume that this was the intention
	 * (we wont get any tracing done otherwise):
	 */
	if (preempt_max_latency == (cycle_t)ULONG_MAX)
		preempt_max_latency = 0;

	/*
	 * user_trace_start() might be called from hardirq
	 * context, if trace_user_triggered_irq is set, so
	 * be careful about locking:
	 */
	if (preempt_count() || irqs_disabled()) {
		if (down_trylock(&max_mutex))
			return -EAGAIN;
	} else
		down(&max_mutex);

	local_irq_save(flags);
	cpu = smp_processor_id();
	tr = cpu_traces + cpu;

#ifdef CONFIG_WAKEUP_TIMING
	if (wakeup_timing) {
		__raw_spin_lock(&sch.trace_lock);
		sch.task = current;
		sch.cpu = cpu;
		sch.tr = tr;
		__raw_spin_unlock(&sch.trace_lock);
	}
#endif
	reset_trace_idx(cpu, tr);

	tr->critical_sequence = max_sequence;
	tr->preempt_timestamp = get_monotonic_cycles();
	tr->critical_start = CALLER_ADDR0;
	_trace_cmdline(cpu, tr);
	mcount();

	WARN_ON(!irqs_disabled());
	local_irq_restore(flags);

	up(&max_mutex);

	return 0;
}

EXPORT_SYMBOL_GPL(user_trace_start);

long user_trace_stop(void)
{
	unsigned long latency = 0, flags;
	struct cpu_trace *tr;
	cycle_t delta;

	if (!trace_user_triggered || trace_print_on_crash || print_functions)
		return -EINVAL;

	local_irq_save(flags);
	mcount();

#ifdef CONFIG_WAKEUP_TIMING
	if (wakeup_timing) {
		struct task_struct *t;

		__raw_spin_lock(&sch.trace_lock);
		t = sch.task;
		if (current != t) {
			__raw_spin_unlock(&sch.trace_lock);
			local_irq_restore(flags);
			printk("wrong stop: curr: %s/%d[%d] => %p\n",
				current->comm, current->pid,
				task_thread_info(current)->cpu, t);
			if (t)
				printk("wrong stop: curr: %s/%d[%d]\n",
					t->comm, t->pid,
					task_thread_info(t)->cpu);
			return -EINVAL;
		}
		sch.task = NULL;
		tr = sch.tr;
		sch.tr = NULL;
		__raw_spin_unlock(&sch.trace_lock);
	} else
#endif
		tr = cpu_traces + smp_processor_id();

	atomic_inc(&tr->disabled);
	if (tr->preempt_timestamp) {
		cycle_t T0, T1;
		unsigned long long tmp0;

		T0 = tr->preempt_timestamp;
		T1 = get_monotonic_cycles();
		tmp0 = preempt_max_latency;
		if (T1 < T0)
			T0 = T1;
		delta = T1 - T0;
		if (!report_latency(delta))
			goto out;
		if (tr->critical_sequence != max_sequence ||
						down_trylock(&max_mutex))
			goto out;

		WARN_ON(!preempt_thresh && preempt_max_latency > delta);

		preempt_max_latency = delta;
		update_max_tr(tr);

		latency = cycles_to_usecs(delta);

		max_sequence++;
		up(&max_mutex);
out:
		tr->preempt_timestamp = 0;
	}
	atomic_dec(&tr->disabled);
	local_irq_restore(flags);

	if (latency) {
		if (preempt_thresh)
			printk("(%16s-%-5d|#%d): %lu us user-latency "
				"violates %lu us threshold.\n",
					current->comm, current->pid,
					raw_smp_processor_id(), latency,
					cycles_to_usecs(preempt_thresh));
		else
			printk("(%16s-%-5d|#%d): new %lu us user-latency.\n",
				current->comm, current->pid,
					raw_smp_processor_id(), latency);
	}

	return 0;
}

EXPORT_SYMBOL(user_trace_stop);

static int trace_print_cpu = -1;

void notrace stop_trace(void)
{
	if (trace_print_on_crash && trace_print_cpu == -1) {
		trace_enabled = -1;
		trace_print_cpu = raw_smp_processor_id();
	}
}

EXPORT_SYMBOL(stop_trace);

static void print_entry(struct trace_entry *entry, struct trace_entry *entry0)
{
	unsigned long abs_usecs;
	int hardirq, softirq;

	abs_usecs = cycles_to_us(entry->timestamp - entry0->timestamp);

	printk("%-5d ", entry->pid);

	printk("%d%c%c",
		entry->cpu,
		(entry->flags & TRACE_FLAG_IRQS_OFF) ? 'd' :
		(entry->flags & TRACE_FLAG_IRQS_HARD_OFF) ? 'D' : '.',
		(entry->flags & TRACE_FLAG_NEED_RESCHED_DELAYED) ? 'n' :
 		((entry->flags & TRACE_FLAG_NEED_RESCHED) ? 'N' : '.'));

	hardirq = entry->flags & TRACE_FLAG_HARDIRQ;
	softirq = entry->flags & TRACE_FLAG_SOFTIRQ;
	if (hardirq && softirq)
		printk("H");
	else {
		if (hardirq)
			printk("h");
		else {
			if (softirq)
				printk("s");
			else
				printk(".");
		}
	}

	if (entry->preempt_count)
		printk(":%x ", entry->preempt_count);
	else
		printk(":. ");

	printk("%ld.%03ldms: ", abs_usecs/1000, abs_usecs % 1000);

	switch (entry->type) {
	case TRACE_FN:
		printk_name(entry->u.fn.eip);
		printk("  <= (");
		printk_name(entry->u.fn.parent_eip);
		printk(")\n");
		break;
	case TRACE_SPECIAL:
		printk(" special: %lx %lx %lx\n",
		       entry->u.special.v1, entry->u.special.v2,
		       entry->u.special.v3);
		break;
	case TRACE_SPECIAL_U64:
		printk("  spec64: %lx%08lx %lx\n",
		       entry->u.special.v1, entry->u.special.v2,
		       entry->u.special.v3);
		break;
	}
}

/*
 * Print the current trace at crash time.
 *
 * We print it backwards, so that the newest (most interesting) entries
 * are printed first.
 */
void print_last_trace(void)
{
	unsigned int idx0, idx, i, cpu;
	struct cpu_trace *tr;
	struct trace_entry *entry0, *entry;

	preempt_disable();
	cpu = smp_processor_id();
	if (trace_enabled != -1 || trace_print_cpu != cpu ||
						!trace_print_on_crash) {
		if (trace_print_on_crash)
			printk("skipping trace printing on CPU#%d != %d\n",
				cpu, trace_print_cpu);
		preempt_enable();
		return;
	}

	trace_print_on_crash = 0;

	tr = cpu_traces + cpu;
	if (!tr->trace)
		goto out;

	printk("Last %ld trace entries:\n", MAX_TRACE);
	idx0 = tr->trace_idx;
	printk("curr idx: %d\n", idx0);
	if (idx0 >= MAX_TRACE)
		idx0 = 0;
	idx = idx0;
	entry0 = tr->trace + idx0;

	for (i = 0; i < MAX_TRACE; i++) {
		if (idx == 0)
			idx = MAX_TRACE-1;
		else
			idx--;
		entry = tr->trace + idx;
		switch (entry->type) {
		case TRACE_FN:
		case TRACE_SPECIAL:
		case TRACE_SPECIAL_U64:
			print_entry(entry, entry0);
			break;
		}
	}
	printk("printed %ld entries\n", MAX_TRACE);
out:
	preempt_enable();
}

#ifdef CONFIG_SMP
/*
 * On SMP, try to 'peek' on other CPU's traces and record them
 * in this CPU's trace. This way we get a rough idea about what's
 * going on there, without the overhead of global tracing.
 *
 * (no need to make this PER_CPU, we bounce it around anyway.)
 */
unsigned long nmi_eips[NR_CPUS];
unsigned long nmi_flags[NR_CPUS];

void notrace nmi_trace(unsigned long eip, unsigned long parent_eip,
			unsigned long flags)
{
	int cpu, this_cpu = smp_processor_id();

	__trace(eip, parent_eip);

	nmi_eips[this_cpu] = parent_eip;
	nmi_flags[this_cpu] = flags;
	for (cpu = 0; cpu < NR_CPUS; cpu++)
		if (cpu_online(cpu) && cpu != this_cpu) {
			__trace(eip, nmi_eips[cpu]);
			__trace(eip, nmi_flags[cpu]);
		}
}
#else
/*
 * On UP, NMI tracing is quite simple:
 */
void notrace nmi_trace(unsigned long eip, unsigned long parent_eip,
			unsigned long flags)
{
	__trace(eip, parent_eip);
}
#endif

#endif

#ifdef CONFIG_PREEMPT_TRACE

static void print_preempt_trace(struct task_struct *task)
{
	unsigned int count = task_thread_info(task)->preempt_count;
	unsigned int i, lim = count & PREEMPT_MASK;
	if (lim >= MAX_PREEMPT_TRACE)
		lim = MAX_PREEMPT_TRACE-1;
	printk("---------------------------\n");
	printk("| preempt count: %08x ]\n", count);
	printk("| %d-level deep critical section nesting:\n", lim);
	printk("----------------------------------------\n");
	for (i = 1; i <= lim; i++) {
		printk(".. [<%08lx>] .... ", task->preempt_trace_eip[i]);
		print_symbol("%s\n", task->preempt_trace_eip[i]);
		printk(".....[<%08lx>] ..   ( <= ",
				task->preempt_trace_parent_eip[i]);
		print_symbol("%s)\n", task->preempt_trace_parent_eip[i]);
	}
	printk("\n");
}

#endif

#if defined(CONFIG_PREEMPT_TRACE) || defined(CONFIG_EVENT_TRACE)
void print_traces(struct task_struct *task)
{
	if (!task)
		task = current;

#ifdef CONFIG_PREEMPT_TRACE
	print_preempt_trace(task);
#endif
#ifdef CONFIG_EVENT_TRACE
	print_last_trace();
#endif
}
#endif

#ifdef CONFIG_EVENT_TRACE
/*
 * Allocate all the per-CPU trace buffers and the
 * save-maximum/save-output staging buffers:
 */
void __init init_tracer(void)
{
	unsigned long size, total_size = 0;
	struct trace_entry *array;
	struct cpu_trace *tr;
	int cpu;

	printk("num_possible_cpus(): %d\n", num_possible_cpus());

	size = sizeof(struct trace_entry)*MAX_TRACE;

	for_each_possible_cpu(cpu) {
		tr = cpu_traces + cpu;
		array = alloc_bootmem(size);
		if (!array) {
			printk(KERN_ERR
			"CPU#%d: failed to allocate %ld bytes trace buffer!\n",
				cpu, size);
		} else {
			printk(KERN_INFO
			"CPU#%d: allocated %ld bytes trace buffer.\n",
				cpu, size);
			total_size += size;
		}
		tr->cpu = cpu;
		tr->trace = array;

		array = alloc_bootmem(size);
		if (!array) {
			printk(KERN_ERR
			"CPU#%d: failed to allocate %ld bytes max-trace buffer!\n",
				cpu, size);
		} else {
			printk(KERN_INFO
			"CPU#%d: allocated %ld bytes max-trace buffer.\n",
				cpu, size);
			total_size += size;
		}
		max_tr.traces[cpu].trace = array;
	}

	/*
	 * The output trace buffer is a special one that only has
	 * trace entries for the first cpu-trace structure:
	 */
	size = sizeof(struct trace_entry)*MAX_TRACE*num_possible_cpus();
	array = alloc_bootmem(size);
	if (!array) {
		printk(KERN_ERR
			"failed to allocate %ld bytes out-trace buffer!\n",
			size);
	} else {
		printk(KERN_INFO "allocated %ld bytes out-trace buffer.\n",
			size);
		total_size += size;
	}
	out_tr.traces[0].trace = array;
	printk(KERN_INFO
		"tracer: a total of %ld bytes allocated.\n",
		total_size);
}
#endif
