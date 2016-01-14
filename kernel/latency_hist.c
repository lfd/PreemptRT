/*
 * kernel/latency_hist.c
 *
 * Add support for histograms of preemption-off latency and
 * interrupt-off latency and wakeup latency, it depends on
 * Real-Time Preemption Support.
 *
 *  Copyright (C) 2005 MontaVista Software, Inc.
 *  Yi Yang <yyang@ch.mvista.com>
 *
 */
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>
#include <linux/latency_hist.h>
#include <asm/atomic.h>

typedef struct hist_data_struct {
	atomic_t hist_mode; /* 0 log, 1 don't log */
	unsigned long min_lat;
	unsigned long avg_lat;
	unsigned long max_lat;
	unsigned long long beyond_hist_bound_samples;
	unsigned long long accumulate_lat;
	unsigned long long total_samples;
	unsigned long long hist_array[MAX_ENTRY_NUM];
} hist_data_t;

static struct proc_dir_entry * latency_hist_root = NULL;
static char * latency_hist_proc_dir_root = "latency_hist";

static char * percpu_proc_name = "CPU";

#ifdef CONFIG_INTERRUPT_OFF_HIST
static DEFINE_PER_CPU(hist_data_t, interrupt_off_hist);
static char * interrupt_off_hist_proc_dir = "interrupt_off_latency";
#endif

#ifdef CONFIG_PREEMPT_OFF_HIST
static DEFINE_PER_CPU(hist_data_t, preempt_off_hist);
static char * preempt_off_hist_proc_dir = "preempt_off_latency";
#endif

#ifdef CONFIG_WAKEUP_LATENCY_HIST
static DEFINE_PER_CPU(hist_data_t, wakeup_latency_hist);
static char * wakeup_latency_hist_proc_dir = "wakeup_latency";
#endif

static struct proc_dir_entry *entry[LATENCY_TYPE_NUM][NR_CPUS];

static inline u64 u64_div(u64 x, u64 y)
{
        do_div(x, y);
        return x;
}

void latency_hist(int latency_type, int cpu, unsigned long latency)
{
	hist_data_t * my_hist;

	if ((cpu < 0) || (cpu >= NR_CPUS) || (latency_type < INTERRUPT_LATENCY)
			|| (latency_type > WAKEUP_LATENCY) || (latency < 0))
		return;

	switch(latency_type) {
#ifdef CONFIG_INTERRUPT_OFF_HIST
	case INTERRUPT_LATENCY:
		my_hist = (hist_data_t *)&per_cpu(interrupt_off_hist, cpu);
		break;
#endif

#ifdef CONFIG_PREEMPT_OFF_HIST
	case PREEMPT_LATENCY:
		my_hist = (hist_data_t *)&per_cpu(preempt_off_hist, cpu);
		break;
#endif

#ifdef CONFIG_WAKEUP_LATENCY_HIST
	case WAKEUP_LATENCY:
		my_hist = (hist_data_t *)&per_cpu(wakeup_latency_hist, cpu);
		break;
#endif
	default:
		return;
	}

	if (atomic_read(&my_hist->hist_mode) == 0)
		return;

	if (latency >= MAX_ENTRY_NUM)
		my_hist->beyond_hist_bound_samples++;
	else
		my_hist->hist_array[latency]++;

	if (latency < my_hist->min_lat)
		my_hist->min_lat = latency;
	else if (latency > my_hist->max_lat)
		my_hist->max_lat = latency;

	my_hist->total_samples++;
	my_hist->accumulate_lat += latency;
	my_hist->avg_lat = (unsigned long) u64_div(my_hist->accumulate_lat,
						  my_hist->total_samples);
	return;
}

static void *l_start(struct seq_file *m, loff_t * pos)
{
	loff_t *index_ptr = kmalloc(sizeof(loff_t), GFP_KERNEL);
	loff_t index = *pos;
	hist_data_t *my_hist = (hist_data_t *) m->private;

	if (!index_ptr)
		return NULL;

	if (index == 0) {
		atomic_dec(&my_hist->hist_mode);
		seq_printf(m, "#Minimum latency: %lu microseconds.\n"
			   "#Average latency: %lu microseconds.\n"
			   "#Maximum latency: %lu microseconds.\n"
			   "#Total samples: %llu\n"
			   "#There are %llu samples greater or equal than %d microseconds\n"
			   "#usecs\t%16s\n"
			   , my_hist->min_lat
			   , my_hist->avg_lat
			   , my_hist->max_lat
			   , my_hist->total_samples
			   , my_hist->beyond_hist_bound_samples
			   , MAX_ENTRY_NUM, "samples");
	}
	if (index >= MAX_ENTRY_NUM)
		return NULL;

	*index_ptr = index;
	return index_ptr;
}

static void *l_next(struct seq_file *m, void *p, loff_t * pos)
{
	loff_t *index_ptr = p;
	hist_data_t *my_hist = (hist_data_t *) m->private;

	if (++*pos >= MAX_ENTRY_NUM) {
		atomic_inc(&my_hist->hist_mode);
		return NULL;
	}
	*index_ptr = *pos;
	return index_ptr;
}

static void l_stop(struct seq_file *m, void *p)
{
	kfree(p);
}

static int l_show(struct seq_file *m, void *p)
{
	int index = *(loff_t *) p;
	hist_data_t *my_hist = (hist_data_t *) m->private;

	seq_printf(m, "%5d\t%16llu\n", index, my_hist->hist_array[index]);
	return 0;
}

static struct seq_operations latency_hist_seq_op = {
	.start = l_start,
	.next  = l_next,
	.stop  = l_stop,
	.show  = l_show
};

static int latency_hist_seq_open(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *entry_ptr = NULL;
	int ret, i, j, break_flags = 0;
	struct seq_file *seq;

	entry_ptr = PDE(file->f_dentry->d_inode);
	for (i = 0; i < LATENCY_TYPE_NUM; i++) {
		for (j = 0; j < NR_CPUS; j++) {
			if (entry[i][j] == NULL)
				continue;
			if (entry_ptr->low_ino == entry[i][j]->low_ino) {
				break_flags = 1;
				break;
			}
		}
		if (break_flags == 1)
			break;
	}
	ret = seq_open(file, &latency_hist_seq_op);
	if (break_flags == 1) {
		seq = (struct seq_file *)file->private_data;
		seq->private = entry[i][j]->data;
	}
	return ret;
}

static struct file_operations latency_hist_seq_fops = {
	.open = latency_hist_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static __init int latency_hist_init(void)
{
	struct proc_dir_entry *tmp_parent_proc_dir;
	int i = 0, len = 0;
	hist_data_t *my_hist;
	char procname[64];

	latency_hist_root = proc_mkdir(latency_hist_proc_dir_root, NULL);


#ifdef CONFIG_INTERRUPT_OFF_HIST
	tmp_parent_proc_dir = proc_mkdir(interrupt_off_hist_proc_dir, latency_hist_root);
	for (i = 0; i < NR_CPUS; i++) {
		len = sprintf(procname, "%s%d", percpu_proc_name, i);
		procname[len] = '\0';
		entry[INTERRUPT_LATENCY][i] =
			create_proc_entry(procname, 0, tmp_parent_proc_dir);
		entry[INTERRUPT_LATENCY][i]->data = (void *)&per_cpu(interrupt_off_hist, i);
		entry[INTERRUPT_LATENCY][i]->proc_fops = &latency_hist_seq_fops;
		my_hist = (hist_data_t *) entry[INTERRUPT_LATENCY][i]->data;
		atomic_set(&my_hist->hist_mode,1);
		my_hist->min_lat = 0xFFFFFFFFUL;
	}
#endif

#ifdef CONFIG_PREEMPT_OFF_HIST
	tmp_parent_proc_dir = proc_mkdir(preempt_off_hist_proc_dir, latency_hist_root);
	for (i = 0; i < NR_CPUS; i++) {
		len = sprintf(procname, "%s%d", percpu_proc_name, i);
		procname[len] = '\0';
		entry[PREEMPT_LATENCY][i] =
			create_proc_entry(procname, 0, tmp_parent_proc_dir);
		entry[PREEMPT_LATENCY][i]->data = (void *)&per_cpu(preempt_off_hist, i);
		entry[PREEMPT_LATENCY][i]->proc_fops = &latency_hist_seq_fops;
		my_hist = (hist_data_t *) entry[PREEMPT_LATENCY][i]->data;
		atomic_set(&my_hist->hist_mode,1);
		my_hist->min_lat = 0xFFFFFFFFUL;
	}
#endif

#ifdef CONFIG_WAKEUP_LATENCY_HIST
	tmp_parent_proc_dir = proc_mkdir(wakeup_latency_hist_proc_dir, latency_hist_root);
	for (i = 0; i < NR_CPUS; i++) {
		len = sprintf(procname, "%s%d", percpu_proc_name, i);
		procname[len] = '\0';
		entry[WAKEUP_LATENCY][i] =
			create_proc_entry(procname, 0, tmp_parent_proc_dir);
		entry[WAKEUP_LATENCY][i]->data = (void *)&per_cpu(wakeup_latency_hist, i);
		entry[WAKEUP_LATENCY][i]->proc_fops = &latency_hist_seq_fops;
		my_hist = (hist_data_t *) entry[WAKEUP_LATENCY][i]->data;
		atomic_set(&my_hist->hist_mode,1);
		my_hist->min_lat = 0xFFFFFFFFUL;
	}
#endif
	return 0;

}

__initcall(latency_hist_init);


#ifdef CONFIG_WAKEUP_LATENCY_HIST
static void hist_reset(hist_data_t *hist)
{
	atomic_dec(&hist->hist_mode);

	memset(hist->hist_array, 0, sizeof(hist->hist_array));
	hist->beyond_hist_bound_samples = 0UL;
	hist->min_lat = 0xFFFFFFFFUL;
	hist->max_lat = 0UL;
	hist->total_samples = 0UL;
	hist->accumulate_lat = 0UL;
	hist->avg_lat = 0UL;

	atomic_inc(&hist->hist_mode);
}

void latency_hist_reset(void)
{
	int cpu;
	hist_data_t *hist;

	for_each_online_cpu(cpu) {
		hist = &per_cpu(wakeup_latency_hist, cpu);
		hist_reset(hist);
	}
}
#endif
