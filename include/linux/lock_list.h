/*
 * Copyright (C) 2006, Red Hat, Inc., Peter Zijlstra <pzijlstr@redhat.com>
 * Licenced under the GPLv2.
 *
 * Simple fine grain locked double linked list.
 */
#ifndef _LINUX_LOCK_LIST_H
#define _LINUX_LOCK_LIST_H

#ifdef __KERNEL__

#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>

struct lock_list_head {
	union {
		struct list_head head;
		struct {
			struct lock_list_head *next, *prev;
		};
	};
	spinlock_t lock;
};

enum {
	LOCK_LIST_NESTING_PREV = 1,
	LOCK_LIST_NESTING_CUR,
	LOCK_LIST_NESTING_NEXT,
};

static inline void INIT_LOCK_LIST_HEAD(struct lock_list_head *list)
{
	INIT_LIST_HEAD(&list->head);
	spin_lock_init(&list->lock);
}

/*
 * Passed pointers are assumed stable by external means (refcount, rcu)
 */
extern void __lock_list_add(struct lock_list_head *new,
			    struct lock_list_head *list);

static inline void lock_list_add(struct lock_list_head *new,
			    struct lock_list_head *list)
{
	spin_lock(&new->lock);
	__lock_list_add(new, list);
	spin_unlock(&new->lock);
}

extern void lock_list_del_init(struct lock_list_head *entry);

static inline
struct lock_list_head *lock_list_next_entry(struct lock_list_head *list,
					    struct lock_list_head *entry)
{
	struct lock_list_head *next = entry->next;
	if (likely(next != list)) {
		lock_set_subclass(&entry->lock.dep_map,
				  LOCK_LIST_NESTING_CUR, _THIS_IP_);
		spin_lock_nested(&next->lock, LOCK_LIST_NESTING_NEXT);
		BUG_ON(entry->next != next);
	} else
		next = NULL;
	spin_unlock(&entry->lock);
	return next;
}

static inline
struct lock_list_head *lock_list_first_entry(struct lock_list_head *list)
{
	spin_lock(&list->lock);
	return lock_list_next_entry(list, list);
}

#define lock_list_for_each_entry(pos, list, member)			\
	for (pos = list_entry(lock_list_first_entry(list), 		\
			      typeof(*pos), member); 			\
	     pos;							\
	     pos = list_entry(lock_list_next_entry(list, &pos->member),	\
			      typeof(*pos), member))

#define lock_list_for_each_entry_stop(pos, member)			\
	spin_unlock(&(pos->member.lock))

#endif /* __KERNEL__ */
#endif /* _LINUX_LOCK_LIST_H */
