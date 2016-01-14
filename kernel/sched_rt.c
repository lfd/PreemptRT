/*
 * Real-Time Scheduling Class (mapped to the SCHED_FIFO and SCHED_RR
 * policies)
 */

#ifdef CONFIG_SMP
/* Is this defined somewhere? */
#define CACHE_ALIGN_SPACE(sz)  (L1_CACHE_ALIGN(sz) - (sz))

static struct {
	cpumask_t rt_overload;
	char space[CACHE_ALIGN_SPACE(sizeof(cpumask_t))];
} rt_overload_masks[MAX_NUMNODES] __cacheline_aligned_in_smp;

static inline cpumask_t *rt_overload_mask(int cpu)
{
	return &rt_overload_masks[cpu_to_node(cpu)].rt_overload;
}

static inline int rt_overloaded(struct rq *rq)
{
	return !cpus_empty(*rt_overload_mask(rq->cpu));
}
static inline cpumask_t *rt_overload(struct rq *rq)
{
	return rt_overload_mask(rq->cpu);
}
static inline void rt_set_overload(struct rq *rq)
{
	cpu_set(rq->cpu, *rt_overload_mask(rq->cpu));
	rq->rt.overloaded = 1;
}
static inline void rt_clear_overload(struct rq *rq)
{
	cpu_clear(rq->cpu, *rt_overload_mask(rq->cpu));
	rq->rt.overloaded = 0;
}

static void update_rt_migration(struct task_struct *p, struct rq *rq)
{
	if (rq->rt.rt_nr_migratory && (rq->rt.rt_nr_running > 1))
		rt_set_overload(rq);
	else
		rt_clear_overload(rq);
}
#endif /* CONFIG_SMP */

/*
 * Update the current task's runtime statistics. Skip current tasks that
 * are not in our scheduling class.
 */
static inline void update_curr_rt(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	u64 delta_exec;

	if (!task_has_rt_policy(curr))
		return;

	delta_exec = rq->clock - curr->se.exec_start;
	if (unlikely((s64)delta_exec < 0))
		delta_exec = 0;

	schedstat_set(curr->se.exec_max, max(curr->se.exec_max, delta_exec));

	curr->se.sum_exec_runtime += delta_exec;
	curr->se.exec_start = rq->clock;
}

static inline void inc_rt_tasks(struct task_struct *p, struct rq *rq)
{
	WARN_ON(!rt_task(p));
	rq->rt.rt_nr_running++;
#ifdef CONFIG_SMP
	if (p->prio < rq->rt.highest_prio) {
		rq->rt.highest_prio = p->prio;
		cpupri_set(rq->cpu, p->prio);
	}
	if (p->nr_cpus_allowed > 1)
		rq->rt.rt_nr_migratory++;

	update_rt_migration(p, rq);
#endif /* CONFIG_SMP */
}

static inline void dec_rt_tasks(struct task_struct *p, struct rq *rq)
{
	WARN_ON(!rt_task(p));
	WARN_ON(!rq->rt.rt_nr_running);
	rq->rt.rt_nr_running--;
#ifdef CONFIG_SMP
	if (rq->rt.rt_nr_running) {
		struct rt_prio_array *array;

		WARN_ON(p->prio < rq->rt.highest_prio);
		if (p->prio == rq->rt.highest_prio) {
			/* recalculate */
			array = &rq->rt.active;
			rq->rt.highest_prio =
				sched_find_first_bit(array->bitmap);
			cpupri_set(rq->cpu, rq->rt.highest_prio);
		} /* otherwise leave rq->highest prio alone */
	} else
		rq->rt.highest_prio = MAX_RT_PRIO;
	if (p->nr_cpus_allowed > 1)
		rq->rt.rt_nr_migratory--;

	update_rt_migration(p, rq);
#endif /* CONFIG_SMP */
}

static inline void incr_rt_nr_uninterruptible(struct task_struct *p,
					      struct rq *rq)
{
	rq->rt.rt_nr_uninterruptible++;
}

static inline void decr_rt_nr_uninterruptible(struct task_struct *p,
					      struct rq *rq)
{
	rq->rt.rt_nr_uninterruptible--;
}

unsigned long rt_nr_running(void)
{
	unsigned long i, sum = 0;

	for_each_online_cpu(i)
		sum += cpu_rq(i)->rt.rt_nr_running;

	return sum;
}

unsigned long rt_nr_running_cpu(int cpu)
{
	return cpu_rq(cpu)->rt.rt_nr_running;
}

unsigned long rt_nr_uninterruptible(void)
{
	unsigned long i, sum = 0;

	for_each_online_cpu(i)
		sum += cpu_rq(i)->rt.rt_nr_uninterruptible;

	return sum;
}

unsigned long rt_nr_uninterruptible_cpu(int cpu)
{
	return cpu_rq(cpu)->rt.rt_nr_uninterruptible;
}

static void enqueue_task_rt(struct rq *rq, struct task_struct *p, int wakeup)
{
	struct rt_prio_array *array = &rq->rt.active;

	list_add_tail(&p->run_list, array->queue + p->prio);
	__set_bit(p->prio, array->bitmap);

	inc_rt_tasks(p, rq);

	if (p->state == TASK_UNINTERRUPTIBLE)
		decr_rt_nr_uninterruptible(p, rq);
}

/*
 * Adding/removing a task to/from a priority array:
 */
static void dequeue_task_rt(struct rq *rq, struct task_struct *p, int sleep)
{
	struct rt_prio_array *array = &rq->rt.active;

	update_curr_rt(rq);

	if (p->state == TASK_UNINTERRUPTIBLE)
		incr_rt_nr_uninterruptible(p, rq);

	list_del(&p->run_list);
	if (list_empty(array->queue + p->prio))
		__clear_bit(p->prio, array->bitmap);

	dec_rt_tasks(p, rq);
}

/*
 * Put task to the end of the run list without the overhead of dequeue
 * followed by enqueue.
 */
static void requeue_task_rt(struct rq *rq, struct task_struct *p)
{
	struct rt_prio_array *array = &rq->rt.active;

	list_move_tail(&p->run_list, array->queue + p->prio);
}

static void
yield_task_rt(struct rq *rq, struct task_struct *p)
{
	requeue_task_rt(rq, p);
}

#ifdef CONFIG_SMP
static int find_lowest_rq(struct task_struct *task);

static int select_task_rq_rt(struct task_struct *p, int sync)
{
	struct rq *rq = task_rq(p);

	/*
	 * If the task will not preempt the RQ, try to find a better RQ
	 * before we even activate the task
	 */
	if ((p->prio >= rq->rt.highest_prio)
	    && (p->nr_cpus_allowed > 1)) {
		int cpu = find_lowest_rq(p);

		return (cpu == -1) ? task_cpu(p) : cpu;
	}

	/*
	 * Otherwise, just let it ride on the affined RQ and the
	 * post-schedule router will push the preempted task away
	 */
	return task_cpu(p);
}
#endif /* CONFIG_SMP */

/*
 * Preempt the current task with a newly woken task if needed:
 */
static void check_preempt_curr_rt(struct rq *rq, struct task_struct *p)
{
	if (p->prio < rq->curr->prio)
		resched_task(rq->curr);
}

static struct task_struct *pick_next_task_rt(struct rq *rq)
{
	struct rt_prio_array *array = &rq->rt.active;
	struct task_struct *next;
	struct list_head *queue;
	int idx;

	idx = sched_find_first_bit(array->bitmap);
	if (idx >= MAX_RT_PRIO)
		return NULL;

	queue = array->queue + idx;
	next = list_entry(queue->next, struct task_struct, run_list);

	next->se.exec_start = rq->clock;

	return next;
}

static void put_prev_task_rt(struct rq *rq, struct task_struct *p)
{
	update_curr_rt(rq);
	p->se.exec_start = 0;
}
#ifdef CONFIG_SMP
/* Only try algorithms three times */
#define RT_MAX_TRIES 3

static int double_lock_balance(struct rq *this_rq, struct rq *busiest);
static void deactivate_task(struct rq *rq, struct task_struct *p, int sleep);

static int pick_rt_task(struct rq *rq, struct task_struct *p, int cpu)
{
	if (!task_running(rq, p) &&
	    (cpu < 0 || cpu_isset(cpu, p->cpus_allowed)) &&
	    (p->nr_cpus_allowed > 1))
		return 1;
	return 0;
}

/* Return the second highest RT task, NULL otherwise */
static struct task_struct *pick_next_highest_task_rt(struct rq *rq,
						     int cpu)
{
	struct rt_prio_array *array = &rq->rt.active;
	struct task_struct *next;
	struct list_head *queue;
	int idx;

	assert_spin_locked(&rq->lock);

	if (likely(rq->rt.rt_nr_running < 2))
		return NULL;

	idx = sched_find_first_bit(array->bitmap);
	if (unlikely(idx >= MAX_RT_PRIO)) {
		WARN_ON(1); /* rt_nr_running is bad */
		return NULL;
	}

	queue = array->queue + idx;
	BUG_ON(list_empty(queue));

	next = list_entry(queue->next, struct task_struct, run_list);
	if (unlikely(pick_rt_task(rq, next, cpu)))
		goto out;

	if (queue->next->next != queue) {
		/* same prio task */
		next = list_entry(queue->next->next, struct task_struct, run_list);
		if (pick_rt_task(rq, next, cpu))
			goto out;
	}

 retry:
	/* slower, but more flexible */
	idx = find_next_bit(array->bitmap, MAX_RT_PRIO, idx+1);
	if (unlikely(idx >= MAX_RT_PRIO))
		return NULL;

	queue = array->queue + idx;
	BUG_ON(list_empty(queue));

	list_for_each_entry(next, queue, run_list) {
		if (pick_rt_task(rq, next, cpu))
			goto out;
	}

	goto retry;

 out:
	return next;
}

static inline int pick_optimal_cpu(int this_cpu, cpumask_t *mask)
{
	int first;

	/* "this_cpu" is cheaper to preempt than a remote processor */
	if ((this_cpu != -1) && cpu_isset(this_cpu, *mask))
		return this_cpu;

	first = first_cpu(*mask);
	if (first != NR_CPUS)
		return first;

	return -1;
}

static int find_lowest_rq(struct task_struct *task)
{
	struct sched_domain *sd;
	cpumask_t lowest_mask;
	int this_cpu = smp_processor_id();
	int cpu      = task_cpu(task);

	if (task->nr_cpus_allowed == 1)
		return -1; /* No other targets possible */

	if (!cpupri_find(task, &lowest_mask))
		return -1; /* No better targets found */

	/*
	 * At this point we have built a mask of cpus representing the
	 * lowest priority tasks in the system.  Now we want to elect
	 * the best one based on our affinity and topology.
	 *
	 * We prioritize the last cpu that the task executed on since
	 * it is most likely cache-hot in that location.
	 */
	if (cpu_isset(cpu, lowest_mask))
		return cpu;

	/*
	 * Otherwise, we consult the sched_domains span maps to figure
	 * out which cpu is logically closest to our hot cache data.
	 */
	if (this_cpu == cpu)
		this_cpu = -1; /* Skip this_cpu opt if the same */

	for_each_domain(cpu, sd) {
		if (sd->flags & SD_WAKE_AFFINE) {
			cpumask_t domain_mask;
			int       best_cpu;

			cpus_and(domain_mask, sd->span, lowest_mask);

			best_cpu = pick_optimal_cpu(this_cpu,
						    &domain_mask);
			if (best_cpu != -1)
				return best_cpu;
		}
	}

	/*
	 * And finally, if there were no matches within the domains
	 * just give the caller *something* to work with from the compatible
	 * locations.
	 */
	return pick_optimal_cpu(this_cpu, &lowest_mask);
}

/* Will lock the rq it finds */
static struct rq *find_lock_lowest_rq(struct task_struct *task,
				      struct rq *rq)
{
	struct rq *lowest_rq = NULL;
	int cpu;
	int tries;

	for (tries = 0; tries < RT_MAX_TRIES; tries++) {
		cpu = find_lowest_rq(task);

		if ((cpu == -1) || (cpu == rq->cpu))
			break;

		lowest_rq = cpu_rq(cpu);

		/* if the prio of this runqueue changed, try again */
		if (double_lock_balance(rq, lowest_rq)) {
			/*
			 * We had to unlock the run queue. In
			 * the mean time, task could have
			 * migrated already or had its affinity changed.
			 * Also make sure that it wasn't scheduled on its rq.
			 */
			if (unlikely(task_rq(task) != rq ||
				     !cpu_isset(lowest_rq->cpu, task->cpus_allowed) ||
				     task_running(rq, task) ||
				     !task->se.on_rq)) {
				spin_unlock(&lowest_rq->lock);
				lowest_rq = NULL;
				break;
			}
		}

		/* If this rq is still suitable use it. */
		if (lowest_rq->rt.highest_prio > task->prio)
			break;

		/* try again */
		spin_unlock(&lowest_rq->lock);
		lowest_rq = NULL;
	}

	return lowest_rq;
}

/*
 * If the current CPU has more than one RT task, see if the non
 * running task can migrate over to a CPU that is running a task
 * of lesser priority.
 */
static int push_rt_task(struct rq *rq)
{
	struct task_struct *next_task;
	struct rq *lowest_rq;
	int ret = 0;
	int paranoid = RT_MAX_TRIES;

	assert_spin_locked(&rq->lock);

	if (!rq->rt.overloaded)
		return 0;

	next_task = pick_next_highest_task_rt(rq, -1);
	if (!next_task)
		return 0;

 retry:
	if (unlikely(next_task == rq->curr)) {
		WARN_ON(1);
		return 0;
	}

	/*
	 * It's possible that the next_task slipped in of
	 * higher priority than current. If that's the case
	 * just reschedule current.
	 */
	if (unlikely(next_task->prio < rq->curr->prio)) {
		resched_task(rq->curr);
		return 0;
	}

	/* We might release rq lock */
	get_task_struct(next_task);

	/* find_lock_lowest_rq locks the rq if found */
	lowest_rq = find_lock_lowest_rq(next_task, rq);
	if (!lowest_rq) {
		struct task_struct *task;
		/*
		 * find lock_lowest_rq releases rq->lock
		 * so it is possible that next_task has changed.
		 * If it has, then try again.
		 */
		task = pick_next_highest_task_rt(rq, -1);
		if (unlikely(task != next_task) && task && paranoid--) {
			put_task_struct(next_task);
			next_task = task;
			goto retry;
		}
		goto out;
	}

	assert_spin_locked(&lowest_rq->lock);

	deactivate_task(rq, next_task, 0);
	set_task_cpu(next_task, lowest_rq->cpu);
	activate_task(lowest_rq, next_task, 0);

	resched_task(lowest_rq->curr);

	schedstat_inc(rq, rto_pushed);

	spin_unlock(&lowest_rq->lock);

	ret = 1;
out:
	put_task_struct(next_task);

	return ret;
}

/*
 * TODO: Currently we just use the second highest prio task on
 *       the queue, and stop when it can't migrate (or there's
 *       no more RT tasks).  There may be a case where a lower
 *       priority RT task has a different affinity than the
 *       higher RT task. In this case the lower RT task could
 *       possibly be able to migrate where as the higher priority
 *       RT task could not.  We currently ignore this issue.
 *       Enhancements are welcome!
 */
static void push_rt_tasks(struct rq *rq)
{
	/* push_rt_task will return true if it moved an RT */
	while (push_rt_task(rq))
		;
}

static int pull_rt_task(struct rq *this_rq)
{
	struct task_struct *next;
	struct task_struct *p;
	struct rq *src_rq;
	cpumask_t *rto_cpumask;
	int this_cpu = this_rq->cpu;
	int cpu;
	int ret = 0;

	assert_spin_locked(&this_rq->lock);

	/*
	 * If cpusets are used, and we have overlapping
	 * run queue cpusets, then this algorithm may not catch all.
	 * This is just the price you pay on trying to keep
	 * dirtying caches down on large SMP machines.
	 */
	if (likely(!rt_overloaded(this_rq)))
		return 0;

	next = pick_next_task_rt(this_rq);

	rto_cpumask = rt_overload(this_rq);

	for_each_cpu_mask(cpu, *rto_cpumask) {
		if (this_cpu == cpu)
			continue;

		src_rq = cpu_rq(cpu);
		if (unlikely(src_rq->rt.rt_nr_running <= 1)) {
			/*
			 * It is possible that overlapping cpusets
			 * will miss clearing a non overloaded runqueue.
			 * Clear it now.
			 */
			if (double_lock_balance(this_rq, src_rq)) {
				/* unlocked our runqueue lock */
				struct task_struct *old_next = next;
				next = pick_next_task_rt(this_rq);
				if (next != old_next)
					ret = 1;
			}
			if (likely(src_rq->rt.rt_nr_running <= 1))
				/*
				 * Small chance that this_rq->curr changed
				 * but it's really harmless here.
				 */
				rt_clear_overload(this_rq);
			else
				/*
				 * Heh, the src_rq is now overloaded, since
				 * we already have the src_rq lock, go straight
				 * to pulling tasks from it.
				 */
				goto try_pulling;
			spin_unlock(&src_rq->lock);
			continue;
		}

		/*
		 * We can potentially drop this_rq's lock in
		 * double_lock_balance, and another CPU could
		 * steal our next task - hence we must cause
		 * the caller to recalculate the next task
		 * in that case:
		 */
		if (double_lock_balance(this_rq, src_rq)) {
			struct task_struct *old_next = next;
			next = pick_next_task_rt(this_rq);
			if (next != old_next)
				ret = 1;
		}

		/*
		 * Are there still pullable RT tasks?
		 */
		if (src_rq->rt.rt_nr_running <= 1) {
			spin_unlock(&src_rq->lock);
			continue;
		}

 try_pulling:
		p = pick_next_highest_task_rt(src_rq, this_cpu);

		/*
		 * Do we have an RT task that preempts
		 * the to-be-scheduled task?
		 */
		if (p && (!next || (p->prio < next->prio))) {
			WARN_ON(p == src_rq->curr);
			WARN_ON(!p->se.on_rq);

			/*
			 * There's a chance that p is higher in priority
			 * than what's currently running on its cpu.
			 * This is just that p is wakeing up and hasn't
			 * had a chance to schedule. We only pull
			 * p if it is lower in priority than the
			 * current task on the run queue or
			 * this_rq next task is lower in prio than
			 * the current task on that rq.
			 */
			if (p->prio < src_rq->curr->prio ||
			    (next && next->prio < src_rq->curr->prio))
				goto bail;

			ret = 1;

			deactivate_task(src_rq, p, 0);
			set_task_cpu(p, this_cpu);
			activate_task(this_rq, p, 0);
			/*
			 * We continue with the search, just in
			 * case there's an even higher prio task
			 * in another runqueue. (low likelyhood
			 * but possible)
			 */

			/*
			 * Update next so that we won't pick a task
			 * on another cpu with a priority lower (or equal)
			 * than the one we just picked.
			 */
			next = p;

			schedstat_inc(src_rq, rto_pulled);
		}
 bail:
		spin_unlock(&src_rq->lock);
	}

	return ret;
}

static void schedule_balance_rt(struct rq *rq,
				struct task_struct *prev)
{
	struct rt_prio_array *array;
	int next_prio;

	/* Try to pull RT tasks here if we lower this rq's prio */
	if (unlikely(rt_task(prev))) {
		next_prio = MAX_RT_PRIO;
		if (rq->rt.rt_nr_running) {
			array = &rq->rt.active;
			next_prio = sched_find_first_bit(array->bitmap);
		}
		if (next_prio > prev->prio) {
			pull_rt_task(rq);
			schedstat_inc(rq, rto_schedule);
		}
	}
}

static void schedule_tail_balance_rt(struct rq *rq)
{
	/*
	 * If we have more than one rt_task queued, then
	 * see if we can push the other rt_tasks off to other CPUS.
	 * Note we may release the rq lock, and since
	 * the lock was owned by prev, we need to release it
	 * first via finish_lock_switch and then reaquire it here.
	 */
	if (unlikely(rq->rt.overloaded)) {
		spin_lock(&rq->lock);
		push_rt_tasks(rq);
		schedstat_inc(rq, rto_schedule_tail);
		spin_unlock(&rq->lock);
	}
}

static void wakeup_balance_rt(struct rq *rq, struct task_struct *p)
{
	if (unlikely(rt_task(p)) &&
	    !task_running(rq, p) &&
	    (p->prio >= rq->rt.highest_prio) &&
	    rq->rt.overloaded) {
		push_rt_tasks(rq);
 		schedstat_inc(rq, rto_wakeup);
	}
}

#else /* CONFIG_SMP */
# define schedule_tail_balance_rt(rq)	do { } while (0)
# define schedule_balance_rt(rq, prev)	do { } while (0)
# define wakeup_balance_rt(rq, p)	do { } while (0)
#endif /* CONFIG_SMP */

static unsigned long
load_balance_rt(struct rq *this_rq, int this_cpu, struct rq *busiest,
			unsigned long max_nr_move, unsigned long max_load_move,
			struct sched_domain *sd, enum cpu_idle_type idle,
			int *all_pinned, int *this_best_prio)
{
	/* don't touch RT tasks */
	return 0;
}

static void task_tick_rt(struct rq *rq, struct task_struct *p)
{
	/*
	 * RR tasks need a special form of timeslice management.
	 * FIFO tasks have no timeslices.
	 */
	if (p->policy != SCHED_RR)
		return;

	if (--p->time_slice)
		return;

	p->time_slice = static_prio_timeslice(p->static_prio);

	/*
	 * Requeue to the end of queue if we are not the only element
	 * on the queue:
	 */
	if (p->run_list.prev != p->run_list.next) {
		requeue_task_rt(rq, p);
		set_tsk_need_resched(p);
	}
}

#ifdef CONFIG_SMP
static void set_cpus_allowed_rt(struct task_struct *p, cpumask_t new_mask)
{
	int weight = cpus_weight(new_mask);

	BUG_ON(!rt_task(p));

	/*
	 * Update the migration status of the RQ if we have an RT task
	 * which is running AND changing its weight value.
	 */
	if (p->se.on_rq && (weight != p->nr_cpus_allowed)) {
		struct rq *rq = task_rq(p);

		if ((p->nr_cpus_allowed <= 1) && (weight > 1))
			rq->rt.rt_nr_migratory++;
		else if((p->nr_cpus_allowed > 1) && (weight <= 1)) {
			BUG_ON(!rq->rt.rt_nr_migratory);
			rq->rt.rt_nr_migratory--;
		}

		update_rt_migration(p, rq);
	}

	p->cpus_allowed    = new_mask;
	p->nr_cpus_allowed = weight;
}
#endif

static struct sched_class rt_sched_class __read_mostly = {
	.enqueue_task		= enqueue_task_rt,
	.dequeue_task		= dequeue_task_rt,
	.yield_task		= yield_task_rt,
#ifdef CONFIG_SMP
	.select_task_rq		= select_task_rq_rt,
#endif /* CONFIG_SMP */

	.check_preempt_curr	= check_preempt_curr_rt,

	.pick_next_task		= pick_next_task_rt,
	.put_prev_task		= put_prev_task_rt,

	.load_balance		= load_balance_rt,

	.task_tick		= task_tick_rt,

#ifdef CONFIG_SMP
	.set_cpus_allowed       = set_cpus_allowed_rt,
#endif
};
