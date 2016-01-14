#ifndef __LINUX_PREEMPT_H
#define __LINUX_PREEMPT_H

/*
 * include/linux/preempt.h - macros for accessing and manipulating
 * preempt_count (used for kernel preemption, interrupt count, etc.)
 */

#include <linux/thread_info.h>
#include <linux/linkage.h>
#include <linux/thread_info.h>

#if defined(CONFIG_DEBUG_PREEMPT) || defined(CONFIG_CRITICAL_TIMING)
  extern void notrace add_preempt_count(unsigned int val);
  extern void notrace sub_preempt_count(unsigned int val);
  extern void notrace mask_preempt_count(unsigned int mask);
  extern void notrace unmask_preempt_count(unsigned int mask);
#else
# define add_preempt_count(val)	do { preempt_count() += (val); } while (0)
# define sub_preempt_count(val)	do { preempt_count() -= (val); } while (0)
# define mask_preempt_count(mask) \
		do { preempt_count() |= (mask); } while (0)
# define unmask_preempt_count(mask) \
		do { preempt_count() &= ~(mask); } while (0)
#endif

#ifdef CONFIG_CRITICAL_TIMING
  extern void touch_critical_timing(void);
  extern void stop_critical_timing(void);
#else
# define touch_critical_timing()	do { } while (0)
# define stop_critical_timing()	do { } while (0)
#endif

#define inc_preempt_count() add_preempt_count(1)
#define dec_preempt_count() sub_preempt_count(1)

#define preempt_count()		(current_thread_info()->preempt_count)

#ifdef CONFIG_PREEMPT

asmlinkage void preempt_schedule(void);
asmlinkage void preempt_schedule_irq(void);

#define preempt_disable() \
do { \
	inc_preempt_count(); \
	barrier(); \
} while (0)

#define __preempt_enable_no_resched() \
do { \
	barrier(); \
	dec_preempt_count(); \
} while (0)


#ifdef CONFIG_DEBUG_PREEMPT
extern void notrace preempt_enable_no_resched(void);
#else
# define preempt_enable_no_resched() __preempt_enable_no_resched()
#endif

#define preempt_check_resched() \
do { \
	if (unlikely(test_thread_flag(TIF_NEED_RESCHED))) \
		preempt_schedule(); \
} while (0)


/*
 * If the architecture doens't have TIF_NEED_RESCHED_DELAYED
 * help it out and define it back to TIF_NEED_RESCHED
 */
#ifndef TIF_NEED_RESCHED_DELAYED
# define TIF_NEED_RESCHED_DELAYED TIF_NEED_RESCHED
#endif

#define preempt_check_resched_delayed() \
do { \
	if (unlikely(test_thread_flag(TIF_NEED_RESCHED_DELAYED))) \
		preempt_schedule(); \
} while (0)

#define preempt_enable() \
do { \
	__preempt_enable_no_resched(); \
	barrier(); \
	preempt_check_resched(); \
} while (0)

#else

#define preempt_disable()		do { } while (0)
#define preempt_enable_no_resched()	do { } while (0)
#define __preempt_enable_no_resched()	do { } while (0)
#define preempt_enable()		do { } while (0)
#define preempt_check_resched()		do { } while (0)
#define preempt_check_resched_delayed()	do { } while (0)

#define preempt_schedule_irq()		do { } while (0)

#endif

#endif /* __LINUX_PREEMPT_H */
