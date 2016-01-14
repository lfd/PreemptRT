/*
 * Read-Copy Update tracing for realtime implementation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Papers:  http://www.rdrop.com/users/paulmck/RCU
 *
 * For detailed explanation of Read-Copy Update mechanism see -
 * 		Documentation/RCU/ *.txt
 *
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/rcupdate.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <asm/atomic.h>
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/moduleparam.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/rcupdate.h>
#include <linux/cpu.h>
#include <linux/mutex.h>
#include <linux/rcupreempt_trace.h>

void rcupreempt_trace_move2done(struct rcupreempt_trace *trace)
{
	trace->done_length += trace->wait_length;
	trace->done_add += trace->wait_length;
	trace->wait_length = 0;
}
void rcupreempt_trace_move2wait(struct rcupreempt_trace *trace)
{
	trace->wait_length += trace->next_length;
	trace->wait_add += trace->next_length;
	trace->next_length = 0;
}
void rcupreempt_trace_try_flip1(struct rcupreempt_trace *trace)
{
	atomic_inc(&trace->rcu_try_flip1);
}
void rcupreempt_trace_try_flip_e1(struct rcupreempt_trace *trace)
{
	atomic_inc(&trace->rcu_try_flip_e1);
}
void rcupreempt_trace_try_flip_e2(struct rcupreempt_trace *trace)
{
	trace->rcu_try_flip_e2++;
}
void rcupreempt_trace_try_flip_e3(struct rcupreempt_trace *trace)
{
	trace->rcu_try_flip_e3++;
}
void rcupreempt_trace_try_flip2(struct rcupreempt_trace *trace)
{
	trace->rcu_try_flip2++;
}
void rcupreempt_trace_try_flip3(struct rcupreempt_trace *trace)
{
	trace->rcu_try_flip3++;
}
void rcupreempt_trace_check_callbacks(struct rcupreempt_trace *trace)
{
	trace->rcu_check_callbacks++;
}
void rcupreempt_trace_done_remove(struct rcupreempt_trace *trace)
{
	trace->done_remove += trace->done_length;
	trace->done_length = 0;
}
void rcupreempt_trace_invoke(struct rcupreempt_trace *trace)
{
	atomic_inc(&trace->done_invoked);
}
void rcupreempt_trace_next_add(struct rcupreempt_trace *trace)
{
        trace->next_add++;
        trace->next_length++;
}
