#ifndef _LINUX_CPUPRI_H
#define _LINUX_CPUPRI_H

#include <linux/sched.h>

int  cpupri_find(struct task_struct *p, cpumask_t *lowest_mask);
void cpupri_set(int cpu, int pri);
void cpupri_init(void);

#endif /* _LINUX_CPUPRI_H */
