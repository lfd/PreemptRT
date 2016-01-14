/*
 * kernel/latency_hist.h
 *
 * Add support for histograms of preemption-off latency and
 * interrupt-off latency and wakeup latency, it depends on
 * Real-Time Preemption Support.
 *
 *  Copyright (C) 2005 MontaVista Software, Inc.
 *  Yi Yang <yyang@ch.mvista.com>
 *
 */
#ifndef _LINUX_LATENCY_HIST_H_
#define _LINUX_LATENCY_HIST_H_

enum {
        INTERRUPT_LATENCY = 0,
        PREEMPT_LATENCY,
        WAKEUP_LATENCY
};

#define MAX_ENTRY_NUM 10240
#define LATENCY_TYPE_NUM 3

#ifdef CONFIG_LATENCY_HIST
extern void latency_hist(int latency_type, int cpu, unsigned long latency);
extern void latency_hist_reset(void);
# define latency_hist_flag 1
#else
# define latency_hist(a,b,c) do { (void)(cpu); } while (0)
# define latency_hist_flag 0
#endif /* CONFIG_LATENCY_HIST */

#endif /* ifndef _LINUX_LATENCY_HIST_H_ */
