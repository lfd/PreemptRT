/*
 *  linux/fs/file_table.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 1997 David S. Miller (davem@caip.rutgers.edu)
 */

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/eventpoll.h>
#include <linux/rcupdate.h>
#include <linux/mount.h>
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/fsnotify.h>
#include <linux/sysctl.h>
#include <linux/percpu_counter.h>

#include <asm/atomic.h>

/* sysctl tunables... */
struct files_stat_struct files_stat = {
	.max_files = NR_FILE
};

/* public. Not pretty! */
__cacheline_aligned_in_smp DEFINE_SPINLOCK(files_lock);

static struct percpu_counter nr_files __cacheline_aligned_in_smp;

static inline void file_free_rcu(struct rcu_head *head)
{
	struct file *f =  container_of(head, struct file, f_u.fu_rcuhead);
	kmem_cache_free(filp_cachep, f);
}

static inline void file_free(struct file *f)
{
	percpu_counter_dec(&nr_files);
	call_rcu(&f->f_u.fu_rcuhead, file_free_rcu);
}

/*
 * Return the total number of open files in the system
 */
static int get_nr_files(void)
{
	return percpu_counter_read_positive(&nr_files);
}

/*
 * Return the maximum number of open files in the system
 */
int get_max_files(void)
{
	return files_stat.max_files;
}
EXPORT_SYMBOL_GPL(get_max_files);

/*
 * Handle nr_files sysctl
 */
#if defined(CONFIG_SYSCTL) && defined(CONFIG_PROC_FS)
int proc_nr_files(ctl_table *table, int write, struct file *filp,
                     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	files_stat.nr_files = get_nr_files();
	return proc_dointvec(table, write, filp, buffer, lenp, ppos);
}
#else
int proc_nr_files(ctl_table *table, int write, struct file *filp,
                     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}
#endif

/* Find an unused file structure and return a pointer to it.
 * Returns NULL, if there are no more free file structures or
 * we run out of memory.
 */
struct file *get_empty_filp(void)
{
	struct task_struct *tsk;
	static int old_max;
	struct file * f;

	/*
	 * Privileged users can go above max_files
	 */
	if (get_nr_files() >= files_stat.max_files && !capable(CAP_SYS_ADMIN)) {
		/*
		 * percpu_counters are inaccurate.  Do an expensive check before
		 * we go and fail.
		 */
		if (percpu_counter_sum(&nr_files) >= files_stat.max_files)
			goto over;
	}

	f = kmem_cache_alloc(filp_cachep, GFP_KERNEL);
	if (f == NULL)
		goto fail;

	percpu_counter_inc(&nr_files);
	memset(f, 0, sizeof(*f));
	if (security_file_alloc(f))
		goto fail_sec;

	tsk = current;
	INIT_LOCK_LIST_HEAD(&f->f_u.fu_llist);
	atomic_set(&f->f_count, 1);
	rwlock_init(&f->f_owner.lock);
	f->f_uid = tsk->fsuid;
	f->f_gid = tsk->fsgid;
	eventpoll_init_file(f);
	/* f->f_version: 0 */
	return f;

over:
	/* Ran out of filps - report that */
	if (get_nr_files() > old_max) {
		printk(KERN_INFO "VFS: file-max limit %d reached\n",
					get_max_files());
		old_max = get_nr_files();
	}
	goto fail;

fail_sec:
	file_free(f);
fail:
	return NULL;
}

EXPORT_SYMBOL(get_empty_filp);

void fastcall fput(struct file *file)
{
	if (atomic_dec_and_test(&file->f_count))
		__fput(file);
}

EXPORT_SYMBOL(fput);

/* __fput is called from task context when aio completion releases the last
 * last use of a struct file *.  Do not use otherwise.
 */
void fastcall __fput(struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct vfsmount *mnt = file->f_path.mnt;
	struct inode *inode = dentry->d_inode;

	might_sleep();

	fsnotify_close(file);
	/*
	 * The function eventpoll_release() should be the first called
	 * in the file cleanup chain.
	 */
	eventpoll_release(file);
	locks_remove_flock(file);

	if (file->f_op && file->f_op->release)
		file->f_op->release(inode, file);
	security_file_free(file);
	if (unlikely(S_ISCHR(inode->i_mode) && inode->i_cdev != NULL))
		cdev_put(inode->i_cdev);
	fops_put(file->f_op);
	if (file->f_mode & FMODE_WRITE)
		put_write_access(inode);
	put_pid(file->f_owner.pid);
	file_kill(file);
	file->f_path.dentry = NULL;
	file->f_path.mnt = NULL;
	file_free(file);
	dput(dentry);
	mntput(mnt);
}

struct file fastcall *fget(unsigned int fd)
{
	struct file *file;
	struct files_struct *files = current->files;

	rcu_read_lock();
	file = fcheck_files(files, fd);
	if (file) {
		if (!atomic_inc_not_zero(&file->f_count)) {
			/* File object ref couldn't be taken */
			rcu_read_unlock();
			return NULL;
		}
	}
	rcu_read_unlock();

	return file;
}

EXPORT_SYMBOL(fget);

/*
 * Lightweight file lookup - no refcnt increment if fd table isn't shared. 
 * You can use this only if it is guranteed that the current task already 
 * holds a refcnt to that file. That check has to be done at fget() only
 * and a flag is returned to be passed to the corresponding fput_light().
 * There must not be a cloning between an fget_light/fput_light pair.
 */
struct file fastcall *fget_light(unsigned int fd, int *fput_needed)
{
	struct file *file;
	struct files_struct *files = current->files;

	*fput_needed = 0;
	if (likely((atomic_read(&files->count) == 1))) {
		file = fcheck_files(files, fd);
	} else {
		rcu_read_lock();
		file = fcheck_files(files, fd);
		if (file) {
			if (atomic_inc_not_zero(&file->f_count))
				*fput_needed = 1;
			else
				/* Didn't get the reference, someone's freed */
				file = NULL;
		}
		rcu_read_unlock();
	}

	return file;
}


void put_filp(struct file *file)
{
	if (atomic_dec_and_test(&file->f_count)) {
		security_file_free(file);
		file_kill(file);
		file_free(file);
	}
}

enum {
	FILEVEC_SIZE = 15
};

struct filevec {
	unsigned long nr;
	struct file *files[FILEVEC_SIZE];
};

static DEFINE_PER_CPU(struct filevec, sb_fvec);

static inline unsigned int filevec_size(struct filevec *fvec)
{
	return FILEVEC_SIZE - fvec->nr;
}

static inline unsigned int filevec_count(struct filevec *fvec)
{
	return fvec->nr;
}

static inline void filevec_reinit(struct filevec *fvec)
{
	fvec->nr = 0;
}

static inline unsigned int filevec_add(struct filevec *fvec, struct file *filp)
{
	rcu_assign_pointer(fvec->files[fvec->nr], filp);

	/*
	 * Here we do icky stuff in order to avoid flushing the per cpu filevec
	 * on list removal.
	 *
	 * We store the location on the per cpu filevec in the as of yet unused
	 * fu_llist.next field and toggle bit 0 to indicate we done so. This
	 * allows the removal code to set the filevec entry to NULL, thereby
	 * avoiding the list add.
	 *
	 * Abuse the fu_llist.lock for protection.
	 */
	spin_lock(&filp->f_u.fu_llist.lock);
	filp->f_u.fu_llist.next = (void *)&fvec->files[fvec->nr];
	__set_bit(0, (void *)&filp->f_u.fu_llist.next);
	spin_unlock(&filp->f_u.fu_llist.lock);

	fvec->nr++;
	return filevec_size(fvec);
}

static void __filevec_add(struct filevec *fvec)
{
	int i;

	for (i = 0; i < filevec_count(fvec); i++) {
		struct file *filp;

		/*
		 * see the comment in filevec_add();
		 * need RCU because a concurrent remove might have deleted
		 * the entry from under us.
		 */
		rcu_read_lock();
		filp = rcu_dereference(fvec->files[i]);
		/*
		 * the simple case, its gone - NEXT!
		 */
		if (!filp) {
			rcu_read_unlock();
			continue;
		}

		spin_lock(&filp->f_u.fu_llist.lock);
		/*
		 * If the entry really is still there, add it!
		 */
		if (rcu_dereference(fvec->files[i])) {
			struct super_block *sb =
				filp->f_mapping->host->i_sb;

			__lock_list_add(&filp->f_u.fu_llist, &sb->s_files);
		}
		spin_unlock(&filp->f_u.fu_llist.lock);
		rcu_read_unlock();
	}
	filevec_reinit(fvec);
}

static void filevec_add_drain(void)
{
	struct filevec *fvec = &get_cpu_var(sb_fvec, &cpu);
	if (filevec_count(fvec))
		__filevec_add(fvec);
	put_cpu_var(sb_fvec, cpu);
}

static void filevec_add_drain_per_cpu(struct work_struct *dummy)
{
	filevec_add_drain();
}

int filevec_add_drain_all(void)
{
	return schedule_on_each_cpu(filevec_add_drain_per_cpu);
}
EXPORT_SYMBOL_GPL(filevec_add_drain_all);

void file_kill(struct file *file)
{
	if (file && file->f_mapping && file->f_mapping->host) {
		struct super_block *sb = file->f_mapping->host->i_sb;
		if (sb)
			barrier_sync(&sb->s_barrier);
	}

	if (file_flag(file, F_SUPERBLOCK)) {
		void **ptr;

		file_flag_clear(file, F_SUPERBLOCK);

		/*
		 * If bit 0 of the fu_llist.next pointer is set we're still
		 * enqueued on a per cpu filevec, in that case clear the entry
		 * and we're done.
		 */
		spin_lock(&file->f_u.fu_llist.lock);
		ptr = (void **)file->f_u.fu_llist.next;
		if (__test_and_clear_bit(0, (void *)&ptr)) {
			rcu_assign_pointer(*ptr, NULL);
			INIT_LIST_HEAD(&file->f_u.fu_llist.head);
			spin_unlock(&file->f_u.fu_llist.lock);
			return;
		}
		spin_unlock(&file->f_u.fu_llist.lock);

		if (!list_empty(&file->f_u.fu_list))
			lock_list_del_init(&file->f_u.fu_llist);

	} else if (!list_empty(&file->f_u.fu_list)) {
		file_list_lock();
		list_del_init(&file->f_u.fu_list);
		file_list_unlock();
	}
}

void file_move(struct file *file, struct list_head *list)
{
	struct super_block *sb;

	if (!list)
		return;

	file_kill(file);

	sb = file->f_mapping->host->i_sb;
	if (list == &sb->s_files.head) {
		struct filevec *fvec = &get_cpu_var(sb_fvec, &cpu);
		file_flag_set(file, F_SUPERBLOCK);
		if (!filevec_add(fvec, file))
			__filevec_add(fvec);
		put_cpu_var(sb_fvec, cpu);
	} else {
		file_list_lock();
		list_add(&file->f_u.fu_list, list);
		file_list_unlock();
	}
}

int fs_may_remount_ro(struct super_block *sb)
{
	struct file *file;

	/* Check that no files are currently opened for writing. */
	barrier_lock(&sb->s_barrier);
	filevec_add_drain_all();
	lock_list_for_each_entry(file, &sb->s_files, f_u.fu_llist) {
		struct inode *inode = file->f_path.dentry->d_inode;

		/* File with pending delete? */
		if (inode->i_nlink == 0)
			goto too_bad;

		/* Writeable file? */
		if (S_ISREG(inode->i_mode) && (file->f_mode & FMODE_WRITE))
			goto too_bad;
	}
	barrier_unlock(&sb->s_barrier);
	return 1; /* Tis' cool bro. */
too_bad:
	lock_list_for_each_entry_stop(file, f_u.fu_llist);
	barrier_unlock(&sb->s_barrier);
	return 0;
}

void __init files_init(unsigned long mempages)
{ 
	int n; 
	/* One file with associated inode and dcache is very roughly 1K. 
	 * Per default don't use more than 10% of our memory for files. 
	 */ 

	n = (mempages * (PAGE_SIZE / 1024)) / 10;
	files_stat.max_files = n; 
	if (files_stat.max_files < NR_FILE)
		files_stat.max_files = NR_FILE;
	files_defer_init();
	percpu_counter_init(&nr_files, 0);
} 
