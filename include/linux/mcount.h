#ifndef _LINUX_MCOUNT_H
#define _LINUX_MCOUNT_H

#ifdef CONFIG_MCOUNT
extern int mcount_enabled;

#include <linux/linkage.h>

typedef void (*mcount_func_t)(unsigned long ip, unsigned long parent_ip);

extern void mcount(void);

int register_mcount_function(mcount_func_t func);
void clear_mcount_function(void);

#endif /* CONFIG_MCOUNT */
#endif /* _LINUX_MCOUNT_H */
