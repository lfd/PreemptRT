/*
 * SLOB Allocator: Simple List Of Blocks
 *
 * Matt Mackall <mpm@selenic.com> 12/30/03
 *
 * How SLOB works:
 *
 * The core of SLOB is a traditional K&R style heap allocator, with
 * support for returning aligned objects. The granularity of this
 * allocator is 8 bytes on x86, though it's perhaps possible to reduce
 * this to 4 if it's deemed worth the effort. The slob heap is a
 * singly-linked list of pages from __get_free_page, grown on demand
 * and allocation from the heap is currently first-fit.
 *
 * Above this is an implementation of kmalloc/kfree. Blocks returned
 * from kmalloc are 8-byte aligned and prepended with a 8-byte header.
 * If kmalloc is asked for objects of PAGE_SIZE or larger, it calls
 * __get_free_pages directly so that it can return page-aligned blocks
 * and keeps a linked list of such pages and their orders. These
 * objects are detected in kfree() by their page alignment.
 *
 * SLAB is emulated on top of SLOB by simply calling constructors and
 * destructors for every SLAB allocation. Objects are returned with
 * the 8-byte alignment unless the SLAB_HWCACHE_ALIGN flag is
 * set, in which case the low-level allocator will fragment blocks to
 * create the proper alignment. Again, objects of page-size or greater
 * are allocated by calling __get_free_pages. As SLAB objects know
 * their size, no separate size bookkeeping is necessary and there is
 * essentially no allocation space overhead.
 *
 * Modified by: Steven Rostedt <rostedt@goodmis.org> 12/20/05
 *
 * Now we take advantage of the kmem_cache usage.  I've removed
 * the global slobfree, and created one for every cache.
 *
 * For kmalloc/kfree I've reintroduced the usage of cache_sizes,
 * but only for sizes 32 through PAGE_SIZE >> 1 by order of 2.
 *
 * Having the SLOB alloc per size of the cache should speed things up
 * greatly, not only by making the search paths smaller, but also by
 * keeping all the caches of similar units.  This way the fragmentation
 * should not be as big of a problem.
 *
 */

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/rcupdate.h>

#undef DEBUG_CACHE

struct slob_block {
	int units;
	struct slob_block *next;
};
typedef struct slob_block slob_t;

#define SLOB_UNIT sizeof(slob_t)
#define SLOB_UNITS(size) (((size) + SLOB_UNIT - 1)/SLOB_UNIT)
#define SLOB_ALIGN L1_CACHE_BYTES

struct bigblock {
	int order;
	void *pages;
};
typedef struct bigblock bigblock_t;

/*
 * struct slob_rcu is inserted at the tail of allocated slob blocks, which
 * were created with a SLAB_DESTROY_BY_RCU slab. slob_rcu is used to free
 * the block using call_rcu.
 */
struct slob_rcu {
	struct rcu_head head;
	int size;
};

struct kmem_cache {
	unsigned int size, align;
	const char *name;
	slob_t *slobfree;
	slob_t arena;
	spinlock_t lock;
	void (*ctor)(void *, struct kmem_cache *, unsigned long);
	void (*dtor)(void *, struct kmem_cache *, unsigned long);
	atomic_t items;
	unsigned int free;
	struct list_head list;
};

#define NR_SLOB_CACHES ((PAGE_SHIFT) - 5) /* 32 to PAGE_SIZE-1 by order of 2 */
#define MAX_SLOB_CACHE_SIZE (PAGE_SIZE >> 1)

static struct kmem_cache *cache_sizes[NR_SLOB_CACHES];
static struct kmem_cache *bb_cache;

static struct semaphore	cache_chain_sem;
static struct list_head cache_chain;

#ifdef DEBUG_CACHE
static void test_cache(kmem_cache_t *c)
{
	slob_t *cur = c->slobfree;
	unsigned int x = -1 >> 2;

	do {
		BUG_ON(!cur->next);
		cur = cur->next;
	} while (cur != c->slobfree && --x);
	BUG_ON(!x);
}
#else
#define test_cache(x) do {} while(0)
#endif

/*
 * Here we take advantage of the lru field of the pages that
 * map to the pages we use in the SLOB.  This is done similar
 * to what is done with SLAB.
 *
 * The lru.next field is used to get the bigblock descriptor
 *    for large blocks larger than PAGE_SIZE >> 1.
 *
 * Set and retrieved by set_slob_block and get_slob_block
 * respectively.
 *
 * The lru.prev field is used to find the cache descriptor
 *   for small blocks smaller than or equal to PAGE_SIZE >> 1.
 *
 * Set and retrieved by set_slob_ptr and get_slob_ptr
 * respectively.
 *
 * The use of lru.next tells us in kmalloc that the page is large.
 */
static inline struct page *get_slob_page(const void *mem)
{
	return virt_to_page(mem);
}

static inline void zero_slob_block(const void *b)
{
	struct page *page;
	page = get_slob_page(b);
	memset(&page->lru, 0, sizeof(page->lru));
}

static inline void *get_slob_block(const void *b)
{
	struct page *page;
	page = get_slob_page(b);
	return page->lru.next;
}

static inline void set_slob_block(const void *b, void *data)
{
	struct page *page;
	page = get_slob_page(b);
	page->lru.next = data;
}

static inline void *get_slob_ptr(const void *b)
{
	struct page *page;
	page = get_slob_page(b);
	return page->lru.prev;
}

static inline void set_slob_ptr(const void *b, void *data)
{
	struct page *page;
	page = get_slob_page(b);
	page->lru.prev = data;
}

static void slob_free(kmem_cache_t *cachep, void *b, int size);

static void *slob_alloc(kmem_cache_t *cachep, gfp_t gfp, int align)
{
	size_t size;
	slob_t *prev, *cur, *aligned = 0;
	int delta = 0, units;
	unsigned long flags;

	size = cachep->size;
	units = SLOB_UNITS(size);
	BUG_ON(!units);

	spin_lock_irqsave(&cachep->lock, flags);
	prev = cachep->slobfree;
	for (cur = prev->next; ; prev = cur, cur = cur->next) {
		if (align) {
			while (align < SLOB_UNIT)
				align <<= 1;
			aligned = (slob_t *)ALIGN((unsigned long)cur, align);
			delta = aligned - cur;
		}
		if (cur->units >= units + delta) { /* room enough? */
			if (delta) { /* need to fragment head to align? */
				aligned->units = cur->units - delta;
				aligned->next = cur->next;
				cur->next = aligned;
				cur->units = delta;
				prev = cur;
				cur = aligned;
			}

			if (cur->units == units) /* exact fit? */
				prev->next = cur->next; /* unlink */
			else { /* fragment */
				prev->next = cur + units;
				prev->next->units = cur->units - units;
				prev->next->next = cur->next;
				cur->units = units;
			}

			cachep->slobfree = prev;
			test_cache(cachep);
			if (prev < prev->next)
				BUG_ON(cur + cur->units > prev->next);
			spin_unlock_irqrestore(&cachep->lock, flags);
			return cur;
		}
		if (cur == cachep->slobfree) {
			test_cache(cachep);
			spin_unlock_irqrestore(&cachep->lock, flags);

			if (size == PAGE_SIZE) /* trying to shrink arena? */
				return 0;

			cur = (slob_t *)__get_free_page(gfp);
			if (!cur)
				return 0;

			zero_slob_block(cur);
			set_slob_ptr(cur, cachep);
			slob_free(cachep, cur, PAGE_SIZE);
			spin_lock_irqsave(&cachep->lock, flags);
			cur = cachep->slobfree;
		}
	}
}

static void slob_free(kmem_cache_t *cachep, void *block, int size)
{
	slob_t *cur, *b = (slob_t *)block;
	unsigned long flags;

	if (!block)
		return;

	if (size)
		b->units = SLOB_UNITS(size);

	/* Find reinsertion point */
	spin_lock_irqsave(&cachep->lock, flags);
	for (cur = cachep->slobfree; !(b > cur && b < cur->next); cur = cur->next)
		if (cur >= cur->next && (b > cur || b < cur->next))
			break;

	if (b + b->units == cur->next) {
		b->units += cur->next->units;
		b->next = cur->next->next;
		BUG_ON(cur->next == &cachep->arena);
	} else
		b->next = cur->next;

	if (cur + cur->units == b) {
		cur->units += b->units;
		cur->next = b->next;
		BUG_ON(b == &cachep->arena);
	} else
		cur->next = b;

	cachep->slobfree = cur;

	test_cache(cachep);
	spin_unlock_irqrestore(&cachep->lock, flags);
}

void *__kmalloc(size_t size, gfp_t gfp)
{
	bigblock_t *bb;

	/*
	 * If the size is less than PAGE_SIZE >> 1 then
	 * we use the generic caches.  Otherwise, we
	 * just allocate the necessary pages.
	 */
	if (size <= MAX_SLOB_CACHE_SIZE) {
		int i;
		int order;
		for (i=0, order=32; i < NR_SLOB_CACHES; i++, order <<= 1)
			if (size <= order)
				break;
		BUG_ON(i == NR_SLOB_CACHES);
		return kmem_cache_alloc(cache_sizes[i], gfp);
	}

	bb = slob_alloc(bb_cache, gfp, 0);
	if (!bb)
		return 0;

	bb->order = get_order(size);
	bb->pages = (void *)__get_free_pages(gfp, bb->order);

	if (bb->pages) {
		set_slob_block(bb->pages, bb);
		return bb->pages;
	}

	slob_free(bb_cache, bb, sizeof(bigblock_t));
	return 0;
}
EXPORT_SYMBOL(__kmalloc);

/**
 * krealloc - reallocate memory. The contents will remain unchanged.
 *
 * @p: object to reallocate memory for.
 * @new_size: how many bytes of memory are required.
 * @flags: the type of memory to allocate.
 *
 * The contents of the object pointed to are preserved up to the
 * lesser of the new and old sizes.  If @p is %NULL, krealloc()
 * behaves exactly like kmalloc().  If @size is 0 and @p is not a
 * %NULL pointer, the object pointed to is freed.
 */
void *krealloc(const void *p, size_t new_size, gfp_t flags)
{
	void *ret;

	if (unlikely(!p))
		return kmalloc_track_caller(new_size, flags);

	if (unlikely(!new_size)) {
		kfree(p);
		return NULL;
	}

	ret = kmalloc_track_caller(new_size, flags);
	if (ret) {
		memcpy(ret, p, min(new_size, ksize(p)));
		kfree(p);
	}
	return ret;
}
EXPORT_SYMBOL(krealloc);

void kfree(const void *block)
{
	kmem_cache_t *c;
	bigblock_t *bb;

	if (!block)
		return;

	/*
	 * look into the page of the allocated block to
	 * see if this is a big allocation or not.
	 */
	bb = get_slob_block(block);
	if (bb) {
		free_pages((unsigned long)block, bb->order);
		slob_free(bb_cache, bb, sizeof(bigblock_t));
		return;
	}

	c = get_slob_ptr(block);
	kmem_cache_free(c, (void *)block);
}

EXPORT_SYMBOL(kfree);

size_t ksize(const void *block)
{
	bigblock_t *bb;
	kmem_cache_t *c;

	if (!block)
		return 0;

	bb = get_slob_block(block);
	if (bb)
		return PAGE_SIZE << bb->order;

	c = get_slob_ptr(block);
	return c->size;
}

static slob_t cache_arena = { .next = &cache_arena, .units = 0 };
struct kmem_cache cache_cache = {
	.name = "cache",
	.slobfree = &cache_cache.arena,
	.arena = { .next = &cache_cache.arena, .units = 0 },
	.lock = SPIN_LOCK_UNLOCKED
};

struct kmem_cache *kmem_cache_create(const char *name, size_t size,
	size_t align, unsigned long flags,
	void (*ctor)(void*, struct kmem_cache *, unsigned long),
	void (*dtor)(void*, struct kmem_cache *, unsigned long))
{
	struct kmem_cache *c;
	void *p;

	c = slob_alloc(&cache_cache, flags, 0);

	memset(c, 0, sizeof(*c));

	c->size = PAGE_SIZE;
	c->arena.next = &c->arena;
	c->arena.units = 0;
	c->slobfree = &c->arena;
	atomic_set(&c->items, 0);
	spin_lock_init(&c->lock);

	p = slob_alloc(c, 0, PAGE_SIZE-1);
	if (p)
		free_page((unsigned long)p);

	if (c) {
		c->name = name;
		c->size = size;
		if (flags & SLAB_DESTROY_BY_RCU) {
			/* leave room for rcu footer at the end of object */
			c->size += sizeof(struct slob_rcu);
		}
		c->flags = flags;
		c->ctor = ctor;
		/* ignore alignment unless it's forced */
		c->align = (flags & SLAB_HWCACHE_ALIGN) ? SLOB_ALIGN : 0;
		if (c->align < align)
			c->align = align;
	} else if (flags & SLAB_PANIC)
		panic("Cannot create slab cache %s\n", name);

	down(&cache_chain_sem);
	list_add_tail(&c->list, &cache_chain);
	up(&cache_chain_sem);

	return c;
}
EXPORT_SYMBOL(kmem_cache_create);

void kmem_cache_destroy(struct kmem_cache *c)
{
	down(&cache_chain_sem);
	list_del(&c->list);
	up(&cache_chain_sem);

	BUG_ON(atomic_read(&c->items));

	/*
	 * WARNING!!! Memory leak!
	 */
	printk("FIX ME: need to free memory\n");
	slob_free(&cache_cache, c, sizeof(struct kmem_cache));
}
EXPORT_SYMBOL(kmem_cache_destroy);

void *kmem_cache_alloc(struct kmem_cache *c, gfp_t flags)
{
	void *b;

	atomic_inc(&c->items);

	if (c->size <= MAX_SLOB_CACHE_SIZE)
		b = slob_alloc(c, flags, c->align);
	else
		b = (void *)__get_free_pages(flags, get_order(c->size));

	if (!b)
		return b;

	if (c->ctor)
		c->ctor(b, c, 0);

	return b;
}
EXPORT_SYMBOL(kmem_cache_alloc);

void *kmem_cache_zalloc(struct kmem_cache *c, gfp_t flags)
{
	void *ret = kmem_cache_alloc(c, flags);
	if (ret)
		memset(ret, 0, c->size);

	return ret;
}
EXPORT_SYMBOL(kmem_cache_zalloc);

static void __kmem_cache_free(void *b, int size)
{
	atomic_dec(&c->items);

	if (c->size <= MAX_SLOB_CACHE_SIZE)
		slob_free(c, b, c->size);
	else
		free_pages((unsigned long)b, get_order(size));
}

static void kmem_rcu_free(struct rcu_head *head)
{
	struct slob_rcu *slob_rcu = (struct slob_rcu *)head;
	void *b = (void *)slob_rcu - (slob_rcu->size - sizeof(struct slob_rcu));

	__kmem_cache_free(b, slob_rcu->size);
}

void kmem_cache_free(struct kmem_cache *c, void *b)
{
	if (unlikely(c->flags & SLAB_DESTROY_BY_RCU)) {
		struct slob_rcu *slob_rcu;
		slob_rcu = b + (c->size - sizeof(struct slob_rcu));
		INIT_RCU_HEAD(&slob_rcu->head);
		slob_rcu->size = c->size;
		call_rcu(&slob_rcu->head, kmem_rcu_free);
	} else {
		__kmem_cache_free(b, c->size);
	}
}
EXPORT_SYMBOL(kmem_cache_free);

unsigned int kmem_cache_size(struct kmem_cache *c)
{
	return c->size;
}
EXPORT_SYMBOL(kmem_cache_size);

const char *kmem_cache_name(struct kmem_cache *c)
{
	return c->name;
}
EXPORT_SYMBOL(kmem_cache_name);

int kmem_cache_shrink(struct kmem_cache *d)
{
	return 0;
}
EXPORT_SYMBOL(kmem_cache_shrink);

int kmem_ptr_validate(struct kmem_cache *a, const void *b)
{
	return 0;
}

static char cache_names[NR_SLOB_CACHES][15];

void kmem_cache_init(void)
{
	static int done;
	void *p;

	if (!done) {
		int i;
		int size = 32;
		done = 1;

		init_MUTEX(&cache_chain_sem);
		INIT_LIST_HEAD(&cache_chain);

		cache_cache.size = PAGE_SIZE;
		p = slob_alloc(&cache_cache, 0, PAGE_SIZE-1);
		if (p)
			free_page((unsigned long)p);
		cache_cache.size = sizeof(struct kmem_cache);

		bb_cache = kmem_cache_create("bb_cache",sizeof(bigblock_t), 0,
					     GFP_KERNEL, NULL, NULL);
		for (i=0; i < NR_SLOB_CACHES; i++, size <<= 1)
			cache_sizes[i] = kmem_cache_create(cache_names[i], size, 0,
							   GFP_KERNEL, NULL, NULL);
	}
}

static void test_slob(slob_t *s)
{
	slob_t *p;
	long x = 0;

	for (p=s->next; p != s && x < 10000; p = p->next, x++)
		printk(".");
}

void print_slobs(void)
{
	struct list_head *curr;

	list_for_each(curr, &cache_chain) {
		kmem_cache_t *c = list_entry(curr, struct kmem_cache, list);

		printk("%s items:%d",
		       c->name?:"<none>",
		       atomic_read(&c->items));
		test_slob(&c->arena);
		printk("\n");
	}
}
