#ifndef _LINUX_MCOUNT_H
#define _LINUX_MCOUNT_H

#ifdef CONFIG_MCOUNT
extern int mcount_enabled;

#include <linux/linkage.h>

#define CALLER_ADDR0 ((unsigned long)__builtin_return_address(0))
#define CALLER_ADDR1 ((unsigned long)__builtin_return_address(1))
#define CALLER_ADDR2 ((unsigned long)__builtin_return_address(2))

typedef void (*mcount_func_t)(unsigned long ip, unsigned long parent_ip);

struct mcount_ops {
	mcount_func_t func;
	struct mcount_ops *next;
};

/*
 * The mcount_ops must be a static and should also
 * be read_mostly.  These functions do modify read_mostly variables
 * so use them sparely. Never free an mcount_op or modify the
 * next pointer after it has been registered. Even after unregistering
 * it, the next pointer may still be used internally.
 */
int register_mcount_function(struct mcount_ops *ops);
int unregister_mcount_function(struct mcount_ops *ops);
void clear_mcount_function(void);

extern void mcount(void);

#else /* !CONFIG_MCOUNT */
# define register_mcount_function(ops) do { } while (0)
# define unregister_mcount_function(ops) do { } while (0)
# define clear_mcount_function(ops) do { } while (0)
#endif /* CONFIG_MCOUNT */
#endif /* _LINUX_MCOUNT_H */
