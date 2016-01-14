#ifndef _LINUX_MCOUNT_H
#define _LINUX_MCOUNT_H

#ifdef CONFIG_MCOUNT
extern int mcount_enabled;

#include <linux/linkage.h>

#define CALLER_ADDR0 ((unsigned long)__builtin_return_address(0))
#define CALLER_ADDR1 ((unsigned long)__builtin_return_address(1))
#define CALLER_ADDR2 ((unsigned long)__builtin_return_address(2))

typedef void (*mcount_func_t)(unsigned long ip, unsigned long parent_ip);

extern void mcount(void);

int register_mcount_function(mcount_func_t func);
void clear_mcount_function(void);

#endif /* CONFIG_MCOUNT */
#endif /* _LINUX_MCOUNT_H */
