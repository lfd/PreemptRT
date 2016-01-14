/*
 * Copyright (C) 2006, Red Hat, Inc., Peter Zijlstra <pzijlstr@redhat.com>
 * Licenced under the GPLv2.
 *
 * simple synchonisation barrier
 *
 * The sync() operation will wait for completion of all lock sections if any.
 *
 * The lock sections are intended to be rare and the sync operation frequent.
 * This construct is created to be scalable and does only 1 read in the fast
 * path (sync), hence avoiding cacheline bounces.
 *
 * NOTE: it _synchronisation_ only, so if there are serialisation requirements
 * those must be met by something external to this construct.
 */
#ifndef _LINUX_BARRIER_H
#define _LINUX_BARRIER_H

#ifdef __KERNEL__

#include <linux/wait.h>
#include <linux/sched.h>
#include <asm/atomic.h>

struct barrier {
	atomic_t count;
	wait_queue_head_t wait;
};

static inline void init_barrier(struct barrier *b)
{
	atomic_set(&b->count, 0);
	init_waitqueue_head(&b->wait);
	__acquire(b);
}

static inline void barrier_lock(struct barrier *b)
{
	__release(b);
	atomic_inc(&b->count);
	smp_wmb();
}

static inline void barrier_unlock(struct barrier *b)
{
	smp_wmb();
	if (atomic_dec_and_test(&b->count))
		__wake_up(&b->wait, TASK_INTERRUPTIBLE|TASK_UNINTERRUPTIBLE, 0, b);
}

static inline void barrier_sync(struct barrier *b)
{
	might_sleep();

	if (unlikely(atomic_read(&b->count))) {
		DEFINE_WAIT(wait);
		prepare_to_wait(&b->wait, &wait, TASK_UNINTERRUPTIBLE);
		while (atomic_read(&b->count))
			schedule();
		finish_wait(&b->wait, &wait);
	}
}

#endif /* __KERNEL__ */
#endif /* _LINUX_BARRIER_H */
