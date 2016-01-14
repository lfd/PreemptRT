/*
 * Copyright (C) 2001 Momchil Velikov
 * Portions Copyright (C) 2001 Christoph Hellwig
 * Copyright (C) 2005 SGI, Christoph Lameter <clameter@sgi.com>
 * Copyright (C) 2006 Nick Piggin
 * Copyright (C) 2007 Peter Zijlstra
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/radix-tree.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/bitops.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>

#undef RADIX_TREE_VERBOSE

#define RADIX_TREE_MAP_SHIFT	4

#define RADIX_TREE_MAP_SIZE	(1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK	(RADIX_TREE_MAP_SIZE-1)

#define RADIX_TREE_TAG_LONGS	\
	((RADIX_TREE_MAP_SIZE + BITS_PER_LONG - 1) / BITS_PER_LONG)

struct radix_tree_node {
	unsigned long	prefix;
	unsigned int	count;
	struct rcu_head	rcu_head;
	void		*slots[RADIX_TREE_MAP_SIZE];
	unsigned long	tags[RADIX_TREE_MAX_TAGS][RADIX_TREE_TAG_LONGS];
#ifdef CONFIG_RADIX_TREE_CONCURRENT
	spinlock_t	lock;
#endif
};

struct radix_tree_path {
	struct radix_tree_node *node;
	int offset;
#ifdef CONFIG_RADIX_TREE_CONCURRENT
	spinlock_t *locked;
#endif
};

#define RADIX_TREE_INDEX_BITS  (8 /* CHAR_BIT */ * sizeof(unsigned long))
#define RADIX_TREE_MAX_PATH (RADIX_TREE_INDEX_BITS/RADIX_TREE_MAP_SHIFT + 2)

#ifdef CONFIG_RADIX_TREE_CONCURRENT
#ifdef CONFIG_DEBUG_LOCK_ALLOC
static const char *radix_node_key_string[RADIX_TREE_MAX_PATH] = {
	"radix-node-00",
	"radix-node-01",
	"radix-node-02",
	"radix-node-03",
	"radix-node-04",
	"radix-node-05",
	"radix-node-06",
	"radix-node-07",
	"radix-node-08",
	"radix-node-09",
	"radix-node-10",
	"radix-node-11",
	"radix-node-12",
	"radix-node-13",
	"radix-node-14",
	"radix-node-15",
};
#endif
static struct lock_class_key radix_node_class[RADIX_TREE_MAX_PATH];
#endif

#ifdef CONFIG_RADIX_TREE_OPTIMISTIC
static DEFINE_PER_CPU(unsigned long[RADIX_TREE_MAX_PATH+1], optimistic_histogram);

static void optimistic_hit(unsigned long prefix)
{
	int height = prefix & RADIX_TREE_MAP_MASK;

	__get_cpu_var(optimistic_histogram)[height]++;
}

#ifdef CONFIG_PROC_FS

#include <linux/seq_file.h>
#include <linux/uaccess.h>

static void *frag_start(struct seq_file *m, loff_t *pos)
{
	if (*pos < 0 || *pos > RADIX_TREE_MAX_PATH)
		return NULL;

	m->private = (void *)(unsigned long)*pos;
	return pos;
}

static void *frag_next(struct seq_file *m, void *arg, loff_t *pos)
{
	if (*pos < RADIX_TREE_MAX_PATH) {
		(*pos)++;
		(*((unsigned long *)&m->private))++;
		return pos;
	}
	return NULL;
}

static void frag_stop(struct seq_file *m, void *arg)
{
}

unsigned long get_optimistic_stat(unsigned long index)
{
	unsigned long total = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		total += per_cpu(optimistic_histogram, cpu)[index];
	}
	return total;
}

static int frag_show(struct seq_file *m, void *arg)
{
	unsigned long index = (unsigned long)m->private;
	unsigned long hits = get_optimistic_stat(index);

	if (index == 0)
		seq_printf(m, "levels skipped\thits\n");

	if (index < RADIX_TREE_MAX_PATH)
		seq_printf(m, "%9lu\t%9lu\n", index, hits);
	else
		seq_printf(m, "failed\t%9lu\n", hits);

	return 0;
}

struct seq_operations optimistic_op = {
	.start = frag_start,
	.next = frag_next,
	.stop = frag_stop,
	.show = frag_show,
};

static void optimistic_reset(void)
{
	int cpu;
	int height;
	for_each_possible_cpu(cpu) {
		for (height = 0; height <= RADIX_TREE_MAX_PATH; height++)
			per_cpu(optimistic_histogram, cpu)[height] = 0;
	}
}

ssize_t optimistic_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	if (count) {
		char c;
		if (get_user(c, buf))
			return -EFAULT;
		if (c == '0')
			optimistic_reset();
	}
	return count;
}

#endif // CONFIG_PROC_FS
#endif // CONFIG_RADIX_TREE_OPTIMISTIC

/*
 * Radix tree node cache.
 */
static struct kmem_cache *radix_tree_node_cachep;

/*
 * Per-cpu pool of preloaded nodes
 */
struct radix_tree_preload {
	int nr;
	struct radix_tree_node *nodes[RADIX_TREE_MAX_PATH];
};
DEFINE_PER_CPU(struct radix_tree_preload, radix_tree_preloads) = { 0, };

static inline gfp_t root_gfp_mask(struct radix_tree_root *root)
{
	return root->gfp_mask & __GFP_BITS_MASK;
}

static int nr_nodes;
static int nr_rcu_nodes;

/*
 * This assumes that the caller has performed appropriate preallocation, and
 * that the caller has pinned this thread of control to the current CPU.
 */
static struct radix_tree_node *
radix_tree_node_alloc(struct radix_tree_root *root, unsigned long prefix)
{
	struct radix_tree_node *ret;
	gfp_t gfp_mask = root_gfp_mask(root);

	ret = kmem_cache_alloc(radix_tree_node_cachep, gfp_mask);
	if (ret == NULL && !(gfp_mask & __GFP_WAIT)) {
		struct radix_tree_preload *rtp;

		rtp = &get_cpu_var(radix_tree_preloads);
		if (rtp->nr) {
			ret = rtp->nodes[rtp->nr - 1];
			rtp->nodes[rtp->nr - 1] = NULL;
			rtp->nr--;
		}
		put_cpu_var(radix_tree_preloads);
	}
	BUG_ON(radix_tree_is_indirect_ptr(ret));
#ifdef CONFIG_RADIX_TREE_CONCURRENT
	spin_lock_init(&ret->lock);
	lockdep_set_class_and_name(&ret->lock,
			&radix_node_class[prefix & RADIX_TREE_MAP_MASK],
			radix_node_key_string[prefix & RADIX_TREE_MAP_MASK]);
#endif
	ret->prefix = prefix;
	return ret;
}

static void radix_tree_node_rcu_free(struct rcu_head *head)
{
	struct radix_tree_node *node =
			container_of(head, struct radix_tree_node, rcu_head);
	kmem_cache_free(radix_tree_node_cachep, node);
	nr_rcu_nodes--;
}

static inline void
radix_tree_node_free(struct radix_tree_node *node)
{
	nr_nodes--;
	nr_rcu_nodes++;
	call_rcu(&node->rcu_head, radix_tree_node_rcu_free);
}

#ifndef CONFIG_PREEMPT_RT

/*
 * Load up this CPU's radix_tree_node buffer with sufficient objects to
 * ensure that the addition of a single element in the tree cannot fail.  On
 * success, return zero, with preemption disabled.  On error, return -ENOMEM
 * with preemption not disabled.
 */
int radix_tree_preload(gfp_t gfp_mask)
{
	struct radix_tree_preload *rtp;
	struct radix_tree_node *node;
	int ret = -ENOMEM;

	preempt_disable();
	rtp = &__get_cpu_var(radix_tree_preloads);
	while (rtp->nr < ARRAY_SIZE(rtp->nodes)) {
		preempt_enable();
		node = kmem_cache_alloc(radix_tree_node_cachep, gfp_mask);
		if (node == NULL)
			goto out;
		preempt_disable();
		rtp = &__get_cpu_var(radix_tree_preloads);
		if (rtp->nr < ARRAY_SIZE(rtp->nodes))
			rtp->nodes[rtp->nr++] = node;
		else
			kmem_cache_free(radix_tree_node_cachep, node);
	}
	ret = 0;
out:
	return ret;
}
EXPORT_SYMBOL(radix_tree_preload);

#endif

static inline void tag_set(struct radix_tree_node *node, unsigned int tag,
		int offset)
{
	__set_bit(offset, node->tags[tag]);
}

static inline void tag_clear(struct radix_tree_node *node, unsigned int tag,
		int offset)
{
	__clear_bit(offset, node->tags[tag]);
}

static inline int tag_get(struct radix_tree_node *node, unsigned int tag,
		int offset)
{
	return test_bit(offset, node->tags[tag]);
}

static inline void root_tag_set(struct radix_tree_root *root, unsigned int tag)
{
	root->gfp_mask |= (__force gfp_t)(1 << (tag + __GFP_BITS_SHIFT));
}


static inline void root_tag_clear(struct radix_tree_root *root, unsigned int tag)
{
	root->gfp_mask &= (__force gfp_t)~(1 << (tag + __GFP_BITS_SHIFT));
}

static inline void root_tag_clear_all(struct radix_tree_root *root)
{
	root->gfp_mask &= __GFP_BITS_MASK;
}

static inline int root_tag_get(struct radix_tree_root *root, unsigned int tag)
{
	return (__force unsigned)root->gfp_mask & (1 << (tag + __GFP_BITS_SHIFT));
}

/*
 * Returns 1 if any slot in the node has this tag set.
 * Otherwise returns 0.
 */
static inline int any_tag_set(struct radix_tree_node *node, unsigned int tag)
{
	int idx;
	for (idx = 0; idx < RADIX_TREE_TAG_LONGS; idx++) {
		if (node->tags[tag][idx])
			return 1;
	}
	return 0;
}

static inline int any_tag_set_but(struct radix_tree_node *node,
		unsigned int tag, int offset)
{
	int idx;
	int offset_idx = offset / BITS_PER_LONG;
	unsigned long offset_mask = ~(1UL << (offset % BITS_PER_LONG));
	for (idx = 0; idx < RADIX_TREE_TAG_LONGS; idx++) {
		unsigned long mask = ~0UL;
		if (idx == offset_idx)
			mask = offset_mask;
		if (node->tags[tag][idx] & mask)
			return 1;
	}
	return 0;
}

/*
 *     Return the maximum key which can be store into a
 *     radix tree with height HEIGHT.
 */
static inline unsigned long radix_tree_maxindex(int height)
{
	int bits = (height + 1) * RADIX_TREE_MAP_SHIFT;

	if (unlikely(bits > BITS_PER_LONG))
		bits = BITS_PER_LONG;

	return ~0UL >> (BITS_PER_LONG - bits);
}

#ifdef CONFIG_RADIX_TREE_CONCURRENT
static inline struct radix_tree_context *
radix_tree_get_context(struct radix_tree_root **rootp)
{
	struct radix_tree_context *context = NULL;
	unsigned long addr = (unsigned long)*rootp;

	if (addr & 1) {
		context = (struct radix_tree_context *)(addr - 1);
		*rootp = context->root;
	}

	return context;
}

#define RADIX_TREE_CONTEXT(context, root) \
	struct radix_tree_context *context =	\
		radix_tree_get_context(&root)

#define ROOT(root) 							\
do {									\
	unsigned long addr = (unsigned long)root;			\
	if (addr & 1) 							\
		root = ((struct radix_tree_context *)(addr - 1))->root;	\
} while (0)

static inline spinlock_t *radix_node_lock(struct radix_tree_root *root,
		struct radix_tree_node *node)
{
	spinlock_t *locked = &node->lock;
	spin_lock(locked);
	return locked;
}

static inline void radix_ladder_lock(struct radix_tree_context *context,
		struct radix_tree_node *node)
{
	if (context) {
		struct radix_tree_root *root = context->root;
		spinlock_t *locked = radix_node_lock(root, node);
		if (locked) {
			spin_unlock(context->locked);
			context->locked = locked;
		}
	}
}

static inline void radix_path_init(struct radix_tree_context *context,
		struct radix_tree_path *pathp)
{
	pathp->locked = context ? context->locked : NULL;
}

static inline void radix_path_lock(struct radix_tree_context *context,
		struct radix_tree_path *pathp, struct radix_tree_node *node)
{
	if (context) {
		struct radix_tree_root *root = context->root;
		spinlock_t *locked = radix_node_lock(root, node);
		if (locked)
			context->locked = locked;
		pathp->locked = locked;
	} else
		pathp->locked = NULL;
}

static inline void radix_path_unlock(struct radix_tree_context *context,
		struct radix_tree_path *punlock)
{
	if (context && punlock->locked &&
			context->locked != punlock->locked)
		spin_unlock(punlock->locked);
}
#else
#define ROOT(root) do { } while (0)
#define RADIX_TREE_CONTEXT(context, root) do { } while (0)
#define radix_ladder_lock(context, node) do { } while (0)
#define radix_path_init(context, pathp) do { } while (0)
#define radix_path_lock(context, pathp, node) do { } while (0)
#define radix_path_unlock(context, punlock) do { } while (0)
#endif

#ifdef CONFIG_RADIX_TREE_OPTIMISTIC
typedef int (*radix_valid_fn)(struct radix_tree_node *, int, int);

static struct radix_tree_node *
radix_optimistic_lookup(struct radix_tree_context *context, unsigned long index,
		int tag, radix_valid_fn valid)
{
	struct radix_tree_node *node, *ret = NULL, **slot;
	struct radix_tree_root *root = context->root;
	int height, shift, pshift;
	int offset;

	node = rcu_dereference(root->rnode);
	if (node == NULL)
		return NULL;

	if (!radix_tree_is_indirect_ptr(node))
			return NULL;

	node = radix_tree_indirect_to_ptr(node);
	do {
		height = node->prefix & RADIX_TREE_MAP_MASK;
		shift = height * RADIX_TREE_MAP_SHIFT;
		pshift = shift + RADIX_TREE_MAP_SHIFT;

		if (pshift < BITS_PER_LONG &&
				(node->prefix >> pshift) != (index >> pshift))
			break;

		offset = (index >> shift) & RADIX_TREE_MAP_MASK;
		if ((*valid)(node, offset, tag))
			ret = node;

		slot = (struct radix_tree_node **)(node->slots + offset);
		node = rcu_dereference(*slot);
		if (!node)
			break;

	} while (height);

	return ret;
}

static struct radix_tree_node *
__radix_optimistic_lock(struct radix_tree_context *context, unsigned long index,
	       	int tag, radix_valid_fn valid)
{
	struct radix_tree_node *node;
	spinlock_t *locked;
	unsigned int shift, offset, height;

	node = radix_optimistic_lookup(context, index, tag, valid);
	if (!node)
		goto out;

	locked = radix_node_lock(context->root, node);
	if (!locked)
		goto out;

	/* check if the node got freed */
	if (!node->count)
		goto out_unlock;

	/* check if the node is still a valid termination point */
	height = node->prefix & RADIX_TREE_MAP_MASK;
	shift = height * RADIX_TREE_MAP_SHIFT;
	offset = (index >> shift) & RADIX_TREE_MAP_MASK;
	if (!(*valid)(node, offset, tag))
		goto out_unlock;

	context->locked = locked;
	return node;

out_unlock:
	spin_unlock(locked);
out:
	return NULL;
}

static struct radix_tree_node *
radix_optimistic_lock(struct radix_tree_context *context, unsigned long index,
		int tag, radix_valid_fn valid)
{
	struct radix_tree_node *node = NULL;

	if (context) {
		node = __radix_optimistic_lock(context, index, tag, valid);
		if (!node) {
			BUG_ON(context->locked);
			spin_lock(&context->root->lock);
			context->locked = &context->root->lock;
			optimistic_hit(RADIX_TREE_MAX_PATH);
		} else
			optimistic_hit(node->prefix & RADIX_TREE_MAP_MASK);
	}
	return node;
}

static int radix_valid_always(struct radix_tree_node *node, int offset, int tag)
{
	return 1;
}

static int radix_valid_tag(struct radix_tree_node *node, int offset, int tag)
{
	return tag_get(node, tag, offset);
}
#else
#define radix_optimistic_lock(context, index, tag, valid) NULL
#endif

static unsigned long radix_tree_extend_prefix(struct radix_tree_node * node,
		unsigned long index)
{
	int height = node->prefix & RADIX_TREE_MAP_MASK;
	int pshift = (height + 1) * RADIX_TREE_MAP_SHIFT;

	while (pshift < BITS_PER_LONG &&
			(node->prefix >> pshift) != (index >> pshift)) {
		height++;
		pshift += RADIX_TREE_MAP_SHIFT;
	}

	if (pshift < BITS_PER_LONG)
		index = (index >> pshift) << pshift;
	else
		index = 0;

	return index + height;
}

/*
 *	Extend a radix tree so it can store key @index
 *
 *   parent       parent
 *	\            \
 *     node   --->   new
 *                     \
 *                    node
 */
static int
radix_tree_extend(struct radix_tree_root *root,
		struct radix_tree_node *parent, unsigned long poffset,
		struct radix_tree_node *node, unsigned long index)
{
	struct radix_tree_node *new;
	unsigned long prefix;
	int height, shift, offset, tag;

	prefix = radix_tree_extend_prefix(node, index);
	if (prefix == node->prefix)
		return 0;

	new = radix_tree_node_alloc(root, prefix);
	if (!new)
		return -ENOMEM;

	height = prefix & RADIX_TREE_MAP_MASK;
	shift = height * RADIX_TREE_MAP_SHIFT;
	offset = (node->prefix >> shift) & RADIX_TREE_MAP_MASK;

	new->slots[offset] = node;
	new->count = 1;

	if (parent) {
		for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++) {
			if (tag_get(parent, tag, poffset))
				tag_set(new, tag, offset);
		}
		rcu_assign_pointer(parent->slots[poffset], new);
	} else {
		for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++) {
			if (root_tag_get(root, tag))
				tag_set(new, tag, offset);
		}
		rcu_assign_pointer(root->rnode,
			       radix_tree_ptr_to_indirect(new));
	}

	return 1;
}

static void radix_tree_print(struct radix_tree_root *root);

/**
 *	radix_tree_insert    -    insert into a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *	@item:		item to insert
 *
 *	Insert an item into the radix tree at position @index.
 */
int __radix_tree_insert(struct radix_tree_root *root,
			unsigned long index, void *item)
{
	struct radix_tree_node *node = NULL, *slot;
	int height, shift, offset;
	int ret, tag;
	RADIX_TREE_CONTEXT(context, root);

	BUG_ON(radix_tree_is_indirect_ptr(item));

	node = radix_optimistic_lock(context, index, 0, radix_valid_always);
	if (node)
		goto optimistic;

	slot = radix_tree_indirect_to_ptr(root->rnode);
	offset = 0;

	if (!slot && !index) {
		rcu_assign_pointer(root->rnode, item);
		for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++)
			BUG_ON(root_tag_get(root, tag));

		return 0;
	}

	if (slot && !radix_tree_is_indirect_ptr(root->rnode)) {
		slot = radix_tree_node_alloc(root, 0);
		if (!slot)
			return -ENOMEM;

		slot->slots[0] = radix_tree_indirect_to_ptr(root->rnode);
		for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++) {
			if (root_tag_get(root, tag))
				tag_set(slot, tag, 0);
		}
		slot->count = 1;
		rcu_assign_pointer(root->rnode,
				radix_tree_ptr_to_indirect(slot));
	}

	do {
		if (slot) {
			ret = radix_tree_extend(root, node, offset, slot, index);
			if (ret < 0)
				return ret;
			if (ret)
				slot = node ? node->slots[offset] :
					radix_tree_indirect_to_ptr(root->rnode);
		}
		if (!slot) {
			slot = radix_tree_node_alloc(root,
					index & ~RADIX_TREE_MAP_MASK);
			if (!slot)
				return -ENOMEM;

			if (node) {
				rcu_assign_pointer(node->slots[offset], slot);
				node->count++;
			} else {
				rcu_assign_pointer(root->rnode,
					radix_tree_ptr_to_indirect(slot));
			}
		}

		/* Go a level down */
		node = slot;
		radix_ladder_lock(context, node);

optimistic:
		height = node->prefix & RADIX_TREE_MAP_MASK;
		shift = height * RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;

		slot = node->slots[offset];
	} while (height);

	if (slot != NULL)
		return -EEXIST;

	BUG_ON(!node);

	node->count++;
	rcu_assign_pointer(node->slots[offset], item);
	for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++)
		BUG_ON(tag_get(node, tag, offset));

	return 0;
}
int radix_tree_insert(struct radix_tree_root *root,
			unsigned long index, void *item)
{
	int ret = __radix_tree_insert(root, index, item);
#ifdef RADIX_TREE_VERBOSE
	ROOT(root);
	printk("radix_tree_insert(%p, %lx, %p): %d\n",
			root, index, item, ret);
	radix_tree_print(root);
#endif
	return ret;
}
EXPORT_SYMBOL(radix_tree_insert);

/**
 *	radix_tree_lookup_slot    -    lookup a slot in a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *
 *	Returns:  the slot corresponding to the position @index in the
 *	radix tree @root. This is useful for update-if-exists operations.
 *
 *	This function can be called under rcu_read_lock iff the slot is not
 *	modified by radix_tree_replace_slot, otherwise it must be called
 *	exclusive from other writers. Any dereference of the slot must be done
 *	using radix_tree_deref_slot.
 */
void **radix_tree_lookup_slot(struct radix_tree_root *root, unsigned long index)
{
	int height, shift, pshift, offset;
	struct radix_tree_node *node, **slot;
	RADIX_TREE_CONTEXT(context, root);

	node = radix_optimistic_lock(context, index, 0, radix_valid_always);
	if (node)
		goto optimistic;

	node = rcu_dereference(root->rnode);
	if (node == NULL)
		return NULL;

	if (!radix_tree_is_indirect_ptr(node)) {
		if (index > 0)
			return NULL;
		return (void **)&root->rnode;
	}
	node = radix_tree_indirect_to_ptr(node);

	do {
		radix_ladder_lock(context, node);

optimistic:
		height = node->prefix & RADIX_TREE_MAP_MASK;
		shift = height * RADIX_TREE_MAP_SHIFT;
		pshift = shift + RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;

		if (pshift < BITS_PER_LONG &&
				(node->prefix >> pshift) != (index >> pshift))
			return NULL;

		slot = (struct radix_tree_node **)(node->slots + offset);
		node = rcu_dereference(*slot);
		if (node == NULL)
			return NULL;

	} while (height);

	return (void **)slot;
}
EXPORT_SYMBOL(radix_tree_lookup_slot);

/**
 *	radix_tree_lookup    -    perform lookup operation on a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *
 *	Lookup the item at the position @index in the radix tree @root.
 *
 *	This function can be called under rcu_read_lock, however the caller
 *	must manage lifetimes of leaf nodes (eg. RCU may also be used to free
 *	them safely). No RCU barriers are required to access or modify the
 *	returned item, however.
 */
void *radix_tree_lookup(struct radix_tree_root *root, unsigned long index)
{
	unsigned int height, shift, pshift, offset;
	struct radix_tree_node *node, **slot;

	node = rcu_dereference(root->rnode);
	if (node == NULL)
		return NULL;

	if (!radix_tree_is_indirect_ptr(node)) {
		if (index > 0)
			return NULL;
		return node;
	}
	node = radix_tree_indirect_to_ptr(node);

	do {
		height = node->prefix & RADIX_TREE_MAP_MASK;
		shift = height * RADIX_TREE_MAP_SHIFT;
		pshift = shift + RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;

		if (pshift < BITS_PER_LONG &&
				(node->prefix >> pshift) != (index >> pshift))
			return NULL;

		slot = (struct radix_tree_node **)(node->slots + offset);
		node = rcu_dereference(*slot);
		if (node == NULL)
			return NULL;
	} while (height);

	return node;
}
EXPORT_SYMBOL(radix_tree_lookup);

/**
 *	radix_tree_tag_set - set a tag on a radix tree node
 *	@root:		radix tree root
 *	@index:		index key
 *	@tag: 		tag index
 *
 *	Set the search tag (which must be < RADIX_TREE_MAX_TAGS)
 *	corresponding to @index in the radix tree.  From
 *	the root all the way down to the leaf node.
 *
 *	Returns the address of the tagged item.   Setting a tag on a not-present
 *	item is a bug.
 */
void *__radix_tree_tag_set(struct radix_tree_root *root,
			unsigned long index, unsigned int tag)
{
	int height, shift, pshift, offset;
	struct radix_tree_node *slot;
	RADIX_TREE_CONTEXT(context, root);

	slot = radix_optimistic_lock(context, index, tag, radix_valid_tag);
	if (slot)
		goto optimistic;

	slot = radix_tree_indirect_to_ptr(root->rnode);

	/* set the root's tag bit */
	if (slot && !root_tag_get(root, tag))
		root_tag_set(root, tag);

	if (!radix_tree_is_indirect_ptr(root->rnode)) {
		BUG_ON(slot && index);
		return slot;
	}

	do {
		radix_ladder_lock(context, slot);

optimistic:
		height = slot->prefix & RADIX_TREE_MAP_MASK;
		shift = height * RADIX_TREE_MAP_SHIFT;
		pshift = shift + RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;

		BUG_ON(pshift < BITS_PER_LONG &&
				(slot->prefix >> pshift) != (index >> pshift));

		if (!tag_get(slot, tag, offset))
			tag_set(slot, tag, offset);
		slot = slot->slots[offset];
		BUG_ON(slot == NULL);
	} while (height);

	return slot;
}
void *radix_tree_tag_set(struct radix_tree_root *root,
			unsigned long index, unsigned int tag)
{
	void *ret = __radix_tree_tag_set(root, index, tag);
#ifdef RADIX_TREE_VERBOSE
	ROOT(root);
	printk("radix_tree_set(%p, %lx, %d): %p\n",
			root, index, tag, ret);
	radix_tree_print(root);
#endif
	return ret;
}

EXPORT_SYMBOL(radix_tree_tag_set);

/*
 * the change can never propagate upwards from here.
 */
static
int radix_valid_tag_clear(struct radix_tree_node *node, int offset, int tag)
{
	int this, other;

	this = tag_get(node, tag, offset);
	other = any_tag_set_but(node, tag, offset);

	return !this || other;
}

/**
 *	radix_tree_tag_clear - clear a tag on a radix tree node
 *	@root:		radix tree root
 *	@index:		index key
 *	@tag: 		tag index
 *
 *	Clear the search tag (which must be < RADIX_TREE_MAX_TAGS)
 *	corresponding to @index in the radix tree.  If
 *	this causes the leaf node to have no tags set then clear the tag in the
 *	next-to-leaf node, etc.
 *
 *	Returns the address of the tagged item on success, else NULL.  ie:
 *	has the same return value and semantics as radix_tree_lookup().
 */
void *__radix_tree_tag_clear(struct radix_tree_root *root,
			unsigned long index, unsigned int tag)
{
	struct radix_tree_path path[RADIX_TREE_MAX_PATH], *pathp = path;
	struct radix_tree_path *punlock = path, *piter;
	struct radix_tree_node *slot = NULL;
	int height, shift, pshift, offset;

	RADIX_TREE_CONTEXT(context, root);

	slot = radix_optimistic_lock(context, index, tag,
			radix_valid_tag_clear);
	if (slot) {
		height = slot->prefix & RADIX_TREE_MAP_MASK;
		shift = height * RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;

		pathp->offset = offset;
		pathp->node = slot;
		radix_path_init(context, pathp);

		goto optimistic;
	}

	pathp->node = NULL;
	radix_path_init(context, pathp);

	if (!radix_tree_is_indirect_ptr(root->rnode)) {
		if (!index) {
			root_tag_clear(root, tag);
			slot = root->rnode;
		}
		goto out;
	}

	slot = radix_tree_indirect_to_ptr(root->rnode);
	do {
		if (!slot)
			goto out;

		height = slot->prefix & RADIX_TREE_MAP_MASK;
		shift = height * RADIX_TREE_MAP_SHIFT;
		pshift = shift + RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;

		if (pshift < BITS_PER_LONG &&
				(slot->prefix >> pshift) != (index >> pshift))
			goto out;

		pathp++;
		pathp->offset = offset;
		pathp->node = slot;
		radix_path_lock(context, pathp, slot);

		if (radix_valid_tag_clear(slot, offset, tag)) {
			for (; punlock < pathp; punlock++)
				radix_path_unlock(context, punlock);
		}

optimistic:
		slot = slot->slots[offset];
	} while (height);

	if (!slot)
		goto out;

	for (piter = pathp; piter >= punlock; piter--) {
		if (piter->node) {
			if (!tag_get(piter->node, tag, piter->offset))
				break;
			tag_clear(piter->node, tag, piter->offset);
			if (any_tag_set(piter->node, tag))
				break;
		} else {
			if (root_tag_get(root, tag))
				root_tag_clear(root, tag);
		}
	}

out:
	for (; punlock < pathp; punlock++)
		radix_path_unlock(context, punlock);
	return slot;
}
void *radix_tree_tag_clear(struct radix_tree_root *root,
			unsigned long index, unsigned int tag)
{
	void *ret = __radix_tree_tag_clear(root, index, tag);
#ifdef RADIX_TREE_VERBOSE
	ROOT(root);
	printk("radix_tree_tag_clear(%p, %lx, %d): %p\n",
			root, index, tag, ret);
	radix_tree_print(root);
#endif
	return ret;
}
EXPORT_SYMBOL(radix_tree_tag_clear);

#ifndef __KERNEL__	/* Only the test harness uses this at present */
/**
 * radix_tree_tag_get - get a tag on a radix tree node
 * @root:		radix tree root
 * @index:		index key
 * @tag: 		tag index (< RADIX_TREE_MAX_TAGS)
 *
 * Return values:
 *
 *  0: tag not present or not set
 *  1: tag set
 */
int radix_tree_tag_get(struct radix_tree_root *root,
			unsigned long index, unsigned int tag)
{
	int height, shift, pshift, offset;
	struct radix_tree_node *node;

	/* check the root's tag bit */
	if (!root_tag_get(root, tag))
		return 0;

	node = rcu_dereference(root->rnode);
	if (node == NULL)
		return 0;

	if (!radix_tree_is_indirect_ptr(node))
		return (index == 0);
	node = radix_tree_indirect_to_ptr(node);

	for (;;) {
		if (node == NULL)
			return 0;

		height = node->prefix & RADIX_TREE_MAP_MASK;
		shift = height * RADIX_TREE_MAP_SHIFT;
		pshift = shift + RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;

		if (pshift < BITS_PER_LONG &&
				(node->prefix >> pshift) != (index >> pshift))
			return 0;

		if (!height)
			return tag_get(node, tag, offset);

		node = rcu_dereference(node->slots[offset]);
	}
}
EXPORT_SYMBOL(radix_tree_tag_get);
#endif

unsigned long __next_index(unsigned long index, int shift)
{
	index &= ~((1UL << shift) - 1);
	index += 1UL << shift;

	return index;
}

static unsigned int
__lookup(struct radix_tree_node *slot, void ***results, unsigned long index,
	unsigned int max_items, unsigned long *next_index)
{
	int height, pshift, shift = 0, offset;
	unsigned int nr_found = 0;
	unsigned long slot_index;

	for (;;) {
		height = slot->prefix & RADIX_TREE_MAP_MASK;
		pshift = (height + 1) * RADIX_TREE_MAP_SHIFT;

		if (pshift < BITS_PER_LONG &&
				(slot->prefix >> pshift) != (index >> pshift)) {
		       	slot_index = slot->prefix & ~RADIX_TREE_MAP_MASK;
			if (shift && index > slot_index) {
				index = __next_index(index, shift);
				goto out;
			}
			index = slot_index;
		}

		shift = height * RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;

		for (;;) {
			if (slot->slots[offset] != NULL)
				break;

			index = __next_index(index, shift);
			if (index == 0)
				goto out; /* wraparound */

			offset++;
			if (offset == RADIX_TREE_MAP_SIZE)
				goto out;
		}

		if (!height)
			break;

		slot = rcu_dereference(slot->slots[offset]);
		if (slot == NULL)
			goto out;
	}

	for (offset = index & RADIX_TREE_MAP_MASK;
			offset < RADIX_TREE_MAP_SIZE; offset++) {
		index++;
		if (slot->slots[offset]) {
			results[nr_found++] = &(slot->slots[offset]);
			if (nr_found == max_items)
				goto out;
		}
	}

out:
	*next_index = index;
	return nr_found;
}

/**
 *	radix_tree_gang_lookup - perform multiple lookup on a radix tree
 *	@root:		radix tree root
 *	@results:	where the results of the lookup are placed
 *	@first_index:	start the lookup from this key
 *	@max_items:	place up to this many items at *results
 *
 *	Performs an index-ascending scan of the tree for present items.  Places
 *	them at *@results and returns the number of items which were placed at
 *	*@results.
 *
 *	The implementation is naive.
 *
 *	Like radix_tree_lookup, radix_tree_gang_lookup may be called under
 *	rcu_read_lock. In this case, rather than the returned results being
 *	an atomic snapshot of the tree at a single point in time, the semantics
 *	of an RCU protected gang lookup are as though multiple radix_tree_lookups
 *	have been issued in individual locks, and results stored in 'results'.
 */
unsigned int
radix_tree_gang_lookup(struct radix_tree_root *root, void **results,
			unsigned long first_index, unsigned int max_items)
{
	unsigned long max_index;
	struct radix_tree_node *node;
	unsigned long cur_index = first_index;
	unsigned int ret;

	node = rcu_dereference(root->rnode);
	if (!node)
		return 0;

	if (!radix_tree_is_indirect_ptr(node)) {
		if (first_index > 0)
			return 0;
		results[0] = node;
		return 1;
	}
	node = radix_tree_indirect_to_ptr(node);

	first_index = node->prefix & ~RADIX_TREE_MAP_MASK;
	if (cur_index < first_index)
		cur_index = first_index;

	max_index = first_index;
	max_index += radix_tree_maxindex(node->prefix & RADIX_TREE_MAP_MASK);

	ret = 0;
	while (ret < max_items) {
		unsigned int nr_found, slots_found, i;
		unsigned long next_index;	/* Index of next search */

		if (cur_index > max_index)
			break;
		slots_found = __lookup(node, (void ***)results + ret, cur_index,
					max_items - ret, &next_index);
		nr_found = 0;
		for (i = 0; i < slots_found; i++) {
			struct radix_tree_node *slot;
			slot = *(((void ***)results)[ret + i]);
			if (!slot)
				continue;
			results[ret + nr_found] = rcu_dereference(slot);
			nr_found++;
		}
		ret += nr_found;
		if (next_index == 0)
			break;
		cur_index = next_index;
	}

	return ret;
}
EXPORT_SYMBOL(radix_tree_gang_lookup);

/**
 *	radix_tree_gang_lookup_slot - perform multiple slot lookup on radix tree
 *	@root:		radix tree root
 *	@results:	where the results of the lookup are placed
 *	@first_index:	start the lookup from this key
 *	@max_items:	place up to this many items at *results
 *
 *	Performs an index-ascending scan of the tree for present items.  Places
 *	their slots at *@results and returns the number of items which were
 *	placed at *@results.
 *
 *	The implementation is naive.
 *
 *	Like radix_tree_gang_lookup as far as RCU and locking goes. Slots must
 *	be dereferenced with radix_tree_deref_slot, and if using only RCU
 *	protection, radix_tree_deref_slot may fail requiring a retry.
 */
unsigned int
radix_tree_gang_lookup_slot(struct radix_tree_root *root, void ***results,
			unsigned long first_index, unsigned int max_items)
{
	unsigned long max_index;
	struct radix_tree_node *node;
	unsigned long cur_index = first_index;
	unsigned int ret;

	node = rcu_dereference(root->rnode);
	if (!node)
		return 0;

	if (!radix_tree_is_indirect_ptr(node)) {
		if (first_index > 0)
			return 0;
		results[0] = (void **)&root->rnode;
		return 1;
	}
	node = radix_tree_indirect_to_ptr(node);

	first_index = node->prefix & ~RADIX_TREE_MAP_MASK;
	if (cur_index < first_index)
		cur_index = first_index;

	max_index = first_index;
	max_index += radix_tree_maxindex(node->prefix & RADIX_TREE_MAP_MASK);

	ret = 0;
	while (ret < max_items) {
		unsigned int slots_found;
		unsigned long next_index;	/* Index of next search */

		if (cur_index > max_index)
			break;
		slots_found = __lookup(node, results + ret, cur_index,
					max_items - ret, &next_index);
		ret += slots_found;
		if (next_index == 0)
			break;
		cur_index = next_index;
	}

	return ret;
}
EXPORT_SYMBOL(radix_tree_gang_lookup_slot);

/*
 * FIXME: the two tag_get()s here should use find_next_bit() instead of
 * open-coding the search.
 */
static unsigned int
__lookup_tag(struct radix_tree_node *slot, void ***results, unsigned long index,
	unsigned int max_items, unsigned long *next_index, unsigned int tag)
{
	int height, pshift, shift = 0, offset;
	unsigned int nr_found = 0;
	unsigned long slot_index;

	for (;;) {
		height = slot->prefix & RADIX_TREE_MAP_MASK;
		pshift = (height + 1) * RADIX_TREE_MAP_SHIFT;

		if (pshift < BITS_PER_LONG &&
				(slot->prefix >> pshift) != (index >> pshift)) {
		       	slot_index = slot->prefix & ~RADIX_TREE_MAP_MASK;
			if (shift && index > slot_index) {
				index = __next_index(index, shift);
				goto out;
			}
			index = slot_index;
		}

		shift = height * RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;

		for (;;) {
			if (tag_get(slot, tag, offset))
				break;

			index = __next_index(index, shift);
			if (index == 0)
				goto out; /* wraparound */

			offset++;
			if (offset == RADIX_TREE_MAP_SIZE)
				goto out;
		}

		if (!height)
			break;

		slot = rcu_dereference(slot->slots[offset]);
		if (slot == NULL)
			goto out;
	}

	for (offset = index & RADIX_TREE_MAP_MASK;
			offset < RADIX_TREE_MAP_SIZE; offset++) {
		index++;
		if (!tag_get(slot, tag, offset))
			continue;

		if (slot->slots[offset]) {
			results[nr_found++] = &(slot->slots[offset]);
			if (nr_found == max_items)
				goto out;
		}
	}

out:
	*next_index = index;
	return nr_found;
}

/**
 *	radix_tree_gang_lookup_tag - perform multiple lookup on a radix tree
 *	                             based on a tag
 *	@root:		radix tree root
 *	@results:	where the results of the lookup are placed
 *	@first_index:	start the lookup from this key
 *	@max_items:	place up to this many items at *results
 *	@tag:		the tag index (< RADIX_TREE_MAX_TAGS)
 *
 *	Performs an index-ascending scan of the tree for present items which
 *	have the tag indexed by @tag set.  Places the items at *@results and
 *	returns the number of items which were placed at *@results.
 */
unsigned int
radix_tree_gang_lookup_tag(struct radix_tree_root *root, void **results,
		unsigned long first_index, unsigned int max_items,
		unsigned int tag)
{
	struct radix_tree_node *node;
	unsigned long max_index;
	unsigned long cur_index = first_index;
	unsigned int ret;

	/* check the root's tag bit */
	if (!root_tag_get(root, tag))
		return 0;

	node = rcu_dereference(root->rnode);
	if (!node)
		return 0;

	if (!radix_tree_is_indirect_ptr(node)) {
		if (first_index > 0)
			return 0;
		results[0] = node;
		return 1;
	}
	node = radix_tree_indirect_to_ptr(node);

	first_index = node->prefix & ~RADIX_TREE_MAP_MASK;
	if (cur_index < first_index)
		cur_index = first_index;

	max_index = first_index;
	max_index += radix_tree_maxindex(node->prefix & RADIX_TREE_MAP_MASK);

	ret = 0;
	while (ret < max_items) {
		unsigned int slots_found, nr_found, i;
		unsigned long next_index;	/* Index of next search */

		if (cur_index > max_index)
			break;
		slots_found = __lookup_tag(node, (void ***)results + ret,
				cur_index, max_items - ret, &next_index, tag);
		nr_found = 0;
		for (i = 0; i < slots_found; i++) {
			struct radix_tree_node *slot;
			slot = *((void ***)results)[ret + i];
			if (!slot)
				continue;
			results[ret + nr_found] = rcu_dereference(slot);
			nr_found++;
		}
		ret += nr_found;
		if (next_index == 0)
			break;
		cur_index = next_index;
	}

	return ret;
}
EXPORT_SYMBOL(radix_tree_gang_lookup_tag);

/**
 *	radix_tree_gang_lookup_tag_slot - perform multiple slot lookup on a
 *					  radix tree based on a tag
 *	@root:		radix tree root
 *	@results:	where the results of the lookup are placed
 *	@first_index:	start the lookup from this key
 *	@max_items:	place up to this many items at *results
 *	@tag:		the tag index (< RADIX_TREE_MAX_TAGS)
 *
 *	Performs an index-ascending scan of the tree for present items which
 *	have the tag indexed by @tag set.  Places the slots at *@results and
 *	returns the number of slots which were placed at *@results.
 */
unsigned int
radix_tree_gang_lookup_tag_slot(struct radix_tree_root *root, void ***results,
		unsigned long first_index, unsigned int max_items,
		unsigned int tag)
{
	struct radix_tree_node *node;
	unsigned long max_index;
	unsigned long cur_index = first_index;
	unsigned int ret;

	/* check the root's tag bit */
	if (!root_tag_get(root, tag))
		return 0;

	node = rcu_dereference(root->rnode);
	if (!node)
		return 0;

	if (!radix_tree_is_indirect_ptr(node)) {
		if (first_index > 0)
			return 0;
		results[0] = (void **)&root->rnode;
		return 1;
	}
	node = radix_tree_indirect_to_ptr(node);

	first_index = node->prefix & ~RADIX_TREE_MAP_MASK;
	if (cur_index < first_index)
		cur_index = first_index;

	max_index = first_index;
	max_index += radix_tree_maxindex(node->prefix & RADIX_TREE_MAP_MASK);

	ret = 0;
	while (ret < max_items) {
		unsigned int slots_found;
		unsigned long next_index;	/* Index of next search */

		if (cur_index > max_index)
			break;
		slots_found = __lookup_tag(node, results + ret,
				cur_index, max_items - ret, &next_index, tag);
		ret += slots_found;
		if (next_index == 0)
			break;
		cur_index = next_index;
	}

	return ret;
}
EXPORT_SYMBOL(radix_tree_gang_lookup_tag_slot);


/*
 *  parent
 *    \            parent
 *   node    --->     \
 *     \             child
 *    child
 *
 */
static int
radix_tree_shrink(struct radix_tree_root *root, struct radix_tree_path *ppath)
{
	int i, tag;
	struct radix_tree_node *node;

	node = ppath->node
		? ppath->node->slots[ppath->offset]
		: radix_tree_indirect_to_ptr(root->rnode);

	if (!(node->prefix & RADIX_TREE_MAP_MASK))
		return 0;

	BUG_ON(!node);
	BUG_ON(node->count != 1);

	for (i = 0; i < RADIX_TREE_MAP_SIZE; i++) {
		if (node->slots[i])
			goto got_it;
	}
	BUG();

got_it:
	if (ppath->node) {
		rcu_assign_pointer(ppath->node->slots[ppath->offset],
				node->slots[i]);
	} else {
		rcu_assign_pointer(root->rnode,
				radix_tree_ptr_to_indirect(node->slots[i]));
	}

	node->slots[i] = NULL;
	node->count--;
	for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++)
		tag_clear(node, tag, i);

	return 1;
}

static
int radix_valid_delete(struct radix_tree_node *node, int offset, int tag)
{
	/*
	 * we need to check for > 2, because nodes with a single child
	 * can still be deleted, see radix_tree_shrink().
	 */
	int unlock = (node->count > 2);

	if (!unlock)
		return unlock;

	for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++) {
		if (!radix_valid_tag_clear(node, offset, tag)) {
			unlock = 0;
			break;
		}
	}

	return unlock;
}

/**
 *	radix_tree_delete    -    delete an item from a radix tree
 *	@root:		radix tree root
 *	@index:		index key
 *
 *	Remove the item at @index from the radix tree rooted at @root.
 *
 *	Returns the address of the deleted item, or NULL if it was not present.
 */
void *__radix_tree_delete(struct radix_tree_root *root, unsigned long index)
{
	struct radix_tree_path path[RADIX_TREE_MAX_PATH], *pathp = path;
	struct radix_tree_path *punlock = path, *piter;
	struct radix_tree_node *slot = NULL, *node;
	int height, shift, pshift, offset;
	int tag;

	RADIX_TREE_CONTEXT(context, root);

	slot = radix_optimistic_lock(context, index, 0, radix_valid_delete);
	if (slot) {
		height = slot->prefix & RADIX_TREE_MAP_MASK;
		shift = height * RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;

		pathp->offset = offset;
		pathp->node = slot;
		radix_path_init(context, pathp);

		goto optimistic;
	}

	pathp->node = NULL;
	radix_path_init(context, pathp);

	if (!radix_tree_is_indirect_ptr(root->rnode)) {
		slot = root->rnode;
		if (slot) {
			root_tag_clear_all(root);
			root->rnode = NULL;
		}
		goto out;
	}

	slot = radix_tree_indirect_to_ptr(root->rnode);
	do {
		if (!slot)
			goto out;

		height = slot->prefix & RADIX_TREE_MAP_MASK;
		shift = height * RADIX_TREE_MAP_SHIFT;
		pshift = shift + RADIX_TREE_MAP_SHIFT;
		offset = (index >> shift) & RADIX_TREE_MAP_MASK;

		if (pshift < BITS_PER_LONG &&
				(slot->prefix >> pshift) != (index >> pshift))
			goto out;

		pathp++;
		pathp->offset = offset;
		pathp->node = slot;
		radix_path_lock(context, pathp, slot);

		if (radix_valid_delete(slot, offset, 0)) {
			for (; punlock < pathp; punlock++)
				radix_path_unlock(context, punlock);
		}

optimistic:
		slot = slot->slots[offset];
	} while (height);

	if (!slot)
		goto out;

	/*
	 * Clear all tags associated with the just-deleted item
	 */
	for (tag = 0; tag < RADIX_TREE_MAX_TAGS; tag++) {
		for (piter = pathp; piter >= punlock; piter--) {
			if (piter->node) {
				if (!tag_get(piter->node, tag, piter->offset))
					break;
				tag_clear(piter->node, tag, piter->offset);
				if (any_tag_set(piter->node, tag))
					break;
			} else {
				if (root_tag_get(root, tag))
					root_tag_clear(root, tag);
			}
		}
	}

	/* Now unhook the nodes we do not need anymore */
	for (piter = pathp; piter >= punlock && piter->node; piter--) {
		piter->node->slots[piter->offset] = NULL;
		piter->node->count--;

		if (piter->node->count == 1) {
			if (radix_tree_shrink(root, piter - 1))
				break;
		}

		if (piter->node->count)
			break;
	}

	/* BUG_ON(piter->node); */

	node = radix_tree_indirect_to_ptr(root->rnode);
	if (!node->count) {
		root_tag_clear_all(root);
		root->rnode = NULL;
	}

out:
	for (; punlock <= pathp; punlock++) {
		radix_path_unlock(context, punlock);
		if (punlock->node && punlock->node->count == 0)
			radix_tree_node_free(punlock->node);
	}
	return slot;
}
void *radix_tree_delete(struct radix_tree_root *root, unsigned long index)
{
	void *ptr = __radix_tree_delete(root, index);
#ifdef RADIX_TREE_VERBOSE
	ROOT(root);
	printk("radix_tree_delete(%p, %lx): %p\n",
			root, index, ptr);
	radix_tree_print(root);
#endif
	return ptr;
}
EXPORT_SYMBOL(radix_tree_delete);

/**
 *	radix_tree_tagged - test whether any items in the tree are tagged
 *	@root:		radix tree root
 *	@tag:		tag to test
 */
int radix_tree_tagged(struct radix_tree_root *root, unsigned int tag)
{
	return root_tag_get(root, tag);
}
EXPORT_SYMBOL(radix_tree_tagged);

static void
radix_tree_node_ctor(void *node, struct kmem_cache *cachep, unsigned long flags)
{
	memset(node, 0, sizeof(struct radix_tree_node));
}

static int radix_tree_callback(struct notifier_block *nfb,
                            unsigned long action,
                            void *hcpu)
{
       int cpu = (long)hcpu;
       struct radix_tree_preload *rtp;

       /* Free per-cpu pool of perloaded nodes */
       if (action == CPU_DEAD || action == CPU_DEAD_FROZEN) {
               rtp = &per_cpu(radix_tree_preloads, cpu);
               while (rtp->nr) {
                       kmem_cache_free(radix_tree_node_cachep,
                                       rtp->nodes[rtp->nr-1]);
                       rtp->nodes[rtp->nr-1] = NULL;
                       rtp->nr--;
               }
       }
       return NOTIFY_OK;
}

void __init radix_tree_init(void)
{
	radix_tree_node_cachep = kmem_cache_create("radix_tree_node",
			sizeof(struct radix_tree_node), 0,
			SLAB_PANIC, radix_tree_node_ctor);
	hotcpu_notifier(radix_tree_callback, 0);
}

static void radix_tree_print_node(struct radix_tree_node *node, int depth)
{
	int i, j;
	int height = node->prefix & RADIX_TREE_MAP_MASK;

	for (j = 0; j < depth; j++)
		printk(" ");
	printk("* node %p count %d height %d prefix %lx\n", node, node->count, height,
			node->prefix & ~RADIX_TREE_MAP_MASK);

	for (i = 0; i < RADIX_TREE_MAP_SIZE; i++) {
		for (j = 0; j < depth; j++)
			printk(" ");
		printk("slot[%d]: %d %d %p\n", i,
				!!tag_get(node, 0, i),
				!!tag_get(node, 1, i),
				node->slots[i]);
		if (height && node->slots[i])
			radix_tree_print_node(node->slots[i], depth+2);
	}
}

static void radix_tree_print(struct radix_tree_root *root)
{
	printk("root: %p\n", root);
	if (!radix_tree_is_indirect_ptr(root->rnode)) {
		printk(" direct: %d %d %p\n", root_tag_get(root, 0),
				root_tag_get(root, 1), root->rnode);
		return;
	}
	printk("rnode: %d %d %p\n", !!root_tag_get(root, 0), !!root_tag_get(root, 1),
			radix_tree_indirect_to_ptr(root->rnode));
	radix_tree_print_node(radix_tree_indirect_to_ptr(root->rnode), 2);
}
