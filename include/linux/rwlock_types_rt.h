#ifndef __LINUX_RWLOCK_TYPES_RT_H
#define __LINUX_RWLOCK_TYPES_RT_H

#ifndef __LINUX_SPINLOCK_TYPES_H
#error "Do not include directly. Include spinlock_types.h instead"
#endif

/*
 * rwlocks - rtmutex which allows single reader recursion
 */
typedef struct {
	struct rt_mutex		lock;
	unsigned int		break_lock;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	dep_map;
#endif
} rwlock_t;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define RW_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname }
#else
# define RW_DEP_MAP_INIT(lockname)
#endif

#define __RW_LOCK_UNLOCKED(name) \
	{ .lock = __RT_MUTEX_INITIALIZER_SAVE_STATE(name.lock),	\
	  RW_DEP_MAP_INIT(name) }

#define DEFINE_RWLOCK(name) \
	rwlock_t name = __RW_LOCK_UNLOCKED(name)

#define READER_BIAS	(1U << 31)
#define WRITER_BIAS	(1U << 30)

/*
 * A reader biased implementation primarily for CPU pinning.
 *
 * Can be selected as general replacement for the single reader RT rwlock
 * variant
 */
struct rt_rw_lock {
	struct rt_mutex		rtmutex;
	atomic_t		readers;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	dep_map;
#endif
};

#define __RWLOCK_RT_INITIALIZER(name)					\
{									\
	.readers = ATOMIC_INIT(READER_BIAS),				\
	.rtmutex = __RT_MUTEX_INITIALIZER_SAVE_STATE(name.rtmutex),	\
	RW_DEP_MAP_INIT(name)						\
}

void __rwlock_biased_rt_init(struct rt_rw_lock *lock, const char *name,
			     struct lock_class_key *key);

#define rwlock_biased_rt_init(rwlock)					\
	do {								\
		static struct lock_class_key __key;			\
									\
		__rwlock_biased_rt_init((rwlock), #rwlock, &__key);	\
	} while (0)

int __read_rt_trylock(struct rt_rw_lock *rwlock);
void __read_rt_lock(struct rt_rw_lock *rwlock);
void __read_rt_unlock(struct rt_rw_lock *rwlock);

void __write_rt_lock(struct rt_rw_lock *rwlock);
int __write_rt_trylock(struct rt_rw_lock *rwlock);
void __write_rt_unlock(struct rt_rw_lock *rwlock);

#endif
