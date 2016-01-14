/*
 *  Copyright (C) 2001 Andrea Arcangeli <andrea@suse.de> SuSE
 *  Copyright 2003 Andi Kleen, SuSE Labs.
 *
 *  [ NOTE: this mechanism is now deprecated in favor of the vDSO. ]
 *
 *  Thanks to hpa@transmeta.com for some useful hint.
 *  Special thanks to Ingo Molnar for his early experience with
 *  a different vsyscall implementation for Linux/IA32 and for the name.
 *
 *  vsyscall 1 is located at -10Mbyte, vsyscall 2 is located
 *  at virtual address -10Mbyte+1024bytes etc... There are at max 4
 *  vsyscalls. One vsyscall can reserve more than 1 slot to avoid
 *  jumping out of line if necessary. We cannot add more with this
 *  mechanism because older kernels won't return -ENOSYS.
 *
 *  Note: the concept clashes with user mode linux.  UML users should
 *  use the vDSO.
 */

/* Disable profiling for userspace code: */
#define DISABLE_BRANCH_PROFILING

#include <linux/time.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/seqlock.h>
#include <linux/jiffies.h>
#include <linux/sysctl.h>
#include <linux/clocksource.h>
#include <linux/getcpu.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/notifier.h>
#include <linux/syscalls.h>
#include <linux/ratelimit.h>

#include <asm/vsyscall.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/unistd.h>
#include <asm/fixmap.h>
#include <asm/errno.h>
#include <asm/io.h>
#include <asm/segment.h>
#include <asm/desc.h>
#include <asm/topology.h>
#include <asm/vgtod.h>
#include <asm/traps.h>

DEFINE_VVAR(int, vgetcpu_mode);
DEFINE_VVAR(struct vsyscall_gtod_data, vsyscall_gtod_data);

void update_vsyscall_tz(void)
{
	vsyscall_gtod_data.sys_tz = sys_tz;
}

void update_vsyscall(struct timespec *wall_time, struct timespec *wtm,
			struct clocksource *clock, u32 mult)
{
	write_seqcount_begin(&vsyscall_gtod_data.seq);


	/* copy vsyscall data */
	vsyscall_gtod_data.clock.vread		= clock->vread;
	vsyscall_gtod_data.clock.cycle_last	= clock->cycle_last;
	vsyscall_gtod_data.clock.mask		= clock->mask;
	vsyscall_gtod_data.clock.mult		= mult;
	vsyscall_gtod_data.clock.shift		= clock->shift;
	vsyscall_gtod_data.wall_time_sec	= wall_time->tv_sec;
	vsyscall_gtod_data.wall_time_nsec	= wall_time->tv_nsec;
	vsyscall_gtod_data.wall_to_monotonic	= *wtm;
	vsyscall_gtod_data.wall_time_coarse	= __current_kernel_time();

	write_seqcount_end(&vsyscall_gtod_data.seq);
}

static void warn_bad_vsyscall(const char *level, struct pt_regs *regs,
			      const char *message)
{
	static DEFINE_RATELIMIT_STATE(rs, DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);
	struct task_struct *tsk;

	if (!show_unhandled_signals || !__ratelimit(&rs))
		return;

	tsk = current;

	printk("%s%s[%d] %s ip:%lx sp:%lx ax:%lx si:%lx di:%lx\n",
	       level, tsk->comm, task_pid_nr(tsk),
	       message, regs->ip - 2, regs->sp, regs->ax, regs->si, regs->di);
}

void dotraplinkage do_emulate_vsyscall(struct pt_regs *regs, long error_code)
{
	const char *vsyscall_name;
	struct task_struct *tsk;
	unsigned long caller;
	int vsyscall_nr;
	long ret;

	/* Kernel code must never get here. */
	BUG_ON(!user_mode(regs));

	local_irq_enable();

	/*
	 * x86-ism here: regs->ip points to the instruction after the int 0xcc,
	 * and int 0xcc is two bytes long.
	 */
	if (!is_vsyscall_entry(regs->ip - 2)) {
		warn_bad_vsyscall(KERN_WARNING, regs, "illegal int 0xcc (exploit attempt?)");
		goto sigsegv;
	}
	vsyscall_nr = vsyscall_entry_nr(regs->ip - 2);

	if (get_user(caller, (unsigned long __user *)regs->sp) != 0) {
		warn_bad_vsyscall(KERN_WARNING, regs, "int 0xcc with bad stack (exploit attempt?)");
		goto sigsegv;
	}

	tsk = current;
	if (seccomp_mode(&tsk->seccomp))
		do_exit(SIGKILL);

	switch (vsyscall_nr) {
	case 0:
		vsyscall_name = "gettimeofday";
		ret = sys_gettimeofday(
			(struct timeval __user *)regs->di,
			(struct timezone __user *)regs->si);
		break;

	case 1:
		vsyscall_name = "time";
		ret = sys_time((time_t __user *)regs->di);
		break;

	case 2:
		vsyscall_name = "getcpu";
		ret = sys_getcpu((unsigned __user *)regs->di,
				 (unsigned __user *)regs->si,
				 0);
		break;

	default:
		/*
		 * If we get here, then vsyscall_nr indicates that int 0xcc
		 * happened at an address in the vsyscall page that doesn't
		 * contain int 0xcc.  That can't happen.
		 */
		BUG();
	}

	if (ret == -EFAULT) {
		/*
		 * Bad news -- userspace fed a bad pointer to a vsyscall.
		 *
		 * With a real vsyscall, that would have caused SIGSEGV.
		 * To make writing reliable exploits using the emulated
		 * vsyscalls harder, generate SIGSEGV here as well.
		 */
		warn_bad_vsyscall(KERN_INFO, regs,
				  "vsyscall fault (exploit attempt?)");
		goto sigsegv;
	}

	regs->ax = ret;

	/* Emulate a ret instruction. */
	regs->ip = caller;
	regs->sp += 8;

	local_irq_disable();
	return;

sigsegv:
	regs->ip -= 2;  /* The faulting instruction should be the int 0xcc. */
	force_sig(SIGSEGV, current);
}

#ifdef CONFIG_SYSCTL
static ctl_table kernel_table2[] = {
	{ .procname = "vsyscall64",
	  .data = &vsyscall_gtod_data.sysctl_enabled, .maxlen = sizeof(int),
	  .mode = 0644,
	  .proc_handler = proc_dointvec },
	{}
};

static ctl_table kernel_root_table2[] = {
	{ .procname = "kernel", .mode = 0555,
	  .child = kernel_table2 },
	{}
};
#endif

/*
 * Assume __initcall executes before all user space. Hopefully kmod
 * doesn't violate that. We'll find out if it does.
 */
static void __cpuinit vsyscall_set_cpu(int cpu)
{
	unsigned long d;
	unsigned long node = 0;
#ifdef CONFIG_NUMA
	node = cpu_to_node(cpu);
#endif
	if (cpu_has(&cpu_data(cpu), X86_FEATURE_RDTSCP))
		write_rdtscp_aux((node << 12) | cpu);

	/*
	 * Store cpu number in limit so that it can be loaded quickly
	 * in user space in vgetcpu. (12 bits for the CPU and 8 bits for the node)
	 */
	d = 0x0f40000000000ULL;
	d |= cpu;
	d |= (node & 0xf) << 12;
	d |= (node >> 4) << 48;

	write_gdt_entry(get_cpu_gdt_table(cpu), GDT_ENTRY_PER_CPU, &d, DESCTYPE_S);
}

static void __cpuinit cpu_vsyscall_init(void *arg)
{
	/* preemption should be already off */
	vsyscall_set_cpu(raw_smp_processor_id());
}

static int __cpuinit
cpu_vsyscall_notifier(struct notifier_block *n, unsigned long action, void *arg)
{
	long cpu = (long)arg;

	if (action == CPU_ONLINE || action == CPU_ONLINE_FROZEN)
		smp_call_function_single(cpu, cpu_vsyscall_init, NULL, 1);

	return NOTIFY_DONE;
}

void __init map_vsyscall(void)
{
	extern char __vsyscall_0;
	unsigned long physaddr_page0 = __pa_symbol(&__vsyscall_0);

	/* Note that VSYSCALL_MAPPED_PAGES must agree with the code below. */
	__set_fixmap(VSYSCALL_FIRST_PAGE, physaddr_page0, PAGE_KERNEL_VSYSCALL);
}

static int __init vsyscall_init(void)
{
	BUG_ON(VSYSCALL_ADDR(0) != __fix_to_virt(VSYSCALL_FIRST_PAGE));

#ifdef CONFIG_SYSCTL
	register_sysctl_table(kernel_root_table2);
#endif
	on_each_cpu(cpu_vsyscall_init, NULL, 1);
	/* notifier priority > KVM */
	hotcpu_notifier(cpu_vsyscall_notifier, 30);

	return 0;
}
__initcall(vsyscall_init);
