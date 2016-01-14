#ifndef __LINUX_UACCESS_H__
#define __LINUX_UACCESS_H__

#include <linux/preempt.h>
#include <asm/uaccess.h>

#ifdef CONFIG_MMU
/*
 * These routines enable/disable the pagefault handler in that
 * it will not take any MM locks and go straight to the fixup table.
 */
extern void pagefault_disable(void);
extern void pagefault_enable(void);
#else
static inline void pagefault_disable(void) { }
static inline void pagefault_enable(void) { }
#endif

#ifndef ARCH_HAS_NOCACHE_UACCESS

static inline unsigned long __copy_from_user_inatomic_nocache(void *to,
				const void __user *from, unsigned long n)
{
	return __copy_from_user_inatomic(to, from, n);
}

static inline unsigned long __copy_from_user_nocache(void *to,
				const void __user *from, unsigned long n)
{
	return __copy_from_user(to, from, n);
}

#endif		/* ARCH_HAS_NOCACHE_UACCESS */

/**
 * probe_kernel_address(): safely attempt to read from a location
 * @addr: address to read from - its type is type typeof(retval)*
 * @retval: read into this variable
 *
 * Safely read from address @addr into variable @revtal.  If a kernel fault
 * happens, handle that and return -EFAULT.
 * We ensure that the __get_user() is executed in atomic context so that
 * do_page_fault() doesn't attempt to take mmap_sem.  This makes
 * probe_kernel_address() suitable for use within regions where the caller
 * already holds mmap_sem, or other locks which nest inside mmap_sem.
 * This must be a macro because __get_user() needs to know the types of the
 * args.
 *
 * We don't include enough header files to be able to do the set_fs().  We
 * require that the probe_kernel_address() caller will do that.
 */
#define probe_kernel_address(addr, retval)		\
	({						\
		long ret;				\
		mm_segment_t old_fs = get_fs();		\
							\
		set_fs(KERNEL_DS);			\
		pagefault_disable();			\
		ret = __get_user(retval, (__force typeof(retval) __user *)(addr));		\
		pagefault_enable();			\
		set_fs(old_fs);				\
		ret;					\
	})

#endif		/* __LINUX_UACCESS_H__ */
