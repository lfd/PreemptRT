/*
 * Copyright (C) 2006, Red Hat, Inc., Peter Zijlstra <pzijlstr@redhat.com>
 * Licenced under the GPLv2.
 *
 * Simple fine grain locked double linked list.
 *
 * Locking order is from prev -> next.
 * Edges are locked not nodes; that is, cur->lock protects:
 *  - cur->next,
 *  - cur->next->prev.
 *
 * Passed pointers are assumed to be stable by external means such as
 * refcounts or RCU. The individual list entries are assumed to be RCU
 * freed (requirement of __lock_list_del).
 */

#include <linux/lock_list.h>

void __lock_list_add(struct lock_list_head *new,
		     struct lock_list_head *list)
{
	struct lock_list_head *next;

	spin_lock_nested(&list->lock, LOCK_LIST_NESTING_PREV);
	next = list->next;
	__list_add(&new->head, &list->head, &next->head);
	spin_unlock(&list->lock);
}

void lock_list_del_init(struct lock_list_head *entry)
{
	struct lock_list_head *prev, *next;

	rcu_read_lock();
again:
	prev = entry->prev;
	if (prev == entry)
		goto out;
	spin_lock_nested(&prev->lock, LOCK_LIST_NESTING_PREV);
	if (unlikely(entry->prev != prev)) {
		/*
		 * we lost
		 */
		spin_unlock(&prev->lock);
		goto again;
	}
	spin_lock_nested(&entry->lock, LOCK_LIST_NESTING_CUR);
	next = entry->next;
	__list_del(&prev->head, &next->head);
	INIT_LIST_HEAD(&entry->head);
	spin_unlock(&entry->lock);
	spin_unlock(&prev->lock);
out:
	rcu_read_unlock();
}
