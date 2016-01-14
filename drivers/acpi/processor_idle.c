/*
 * processor_idle - idle state submodule to the ACPI processor driver
 *
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2004, 2005 Dominik Brodowski <linux@brodo.de>
 *  Copyright (C) 2004  Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>
 *  			- Added processor hotplug support
 *  Copyright (C) 2005  Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *  			- Added support for C3 on SMP
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpufreq.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/acpi.h>
#include <linux/dmi.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>	/* need_resched() */
#include <linux/latency.h>
#include <linux/clockchips.h>
#include <linux/cpuidle.h>

/*
 * Include the apic definitions for x86 to have the APIC timer related defines
 * available also for UP (on SMP it gets magically included via linux/smp.h).
 * asm/acpi.h is not an option, as it would require more include magic. Also
 * creating an empty asm-ia64/apic.h would just trade pest vs. cholera.
 */
#ifdef CONFIG_X86
#include <asm/apic.h>
#endif

#include <asm/io.h>
#include <asm/uaccess.h>

#include <acpi/acpi_bus.h>
#include <acpi/processor.h>

#define ACPI_PROCESSOR_COMPONENT        0x01000000
#define ACPI_PROCESSOR_CLASS            "processor"
#define _COMPONENT              ACPI_PROCESSOR_COMPONENT
ACPI_MODULE_NAME("processor_idle");
#define ACPI_PROCESSOR_FILE_POWER	"power"
#define PM_TIMER_TICKS_TO_US(p)		(((p) * 1000)/(PM_TIMER_FREQUENCY/1000))
#define C2_OVERHEAD			1	/* 1us */
#define C3_OVERHEAD			1	/* 1us */

void acpi_max_cstate_changed(void)
{
	/* Driver will reset devices' max cstate limit */
	cpuidle_force_redetect_devices(&acpi_idle_driver);
}

static int change_max_cstate(const char *val, struct kernel_param *kp)
{
	int max;

	max = simple_strtol(val, NULL, 0);
	if (!max)
		return -EINVAL;
	max_cstate = max;
	if (acpi_do_set_cstate_limit)
		acpi_do_set_cstate_limit();
	return 0;
}

module_param_call(max_cstate, change_max_cstate, param_get_uint, &max_cstate, 0644);

static unsigned int nocst __read_mostly;
module_param(nocst, uint, 0000);

/* --------------------------------------------------------------------------
                                Power Management
   -------------------------------------------------------------------------- */

/*
 * IBM ThinkPad R40e crashes mysteriously when going into C2 or C3.
 * For now disable this. Probably a bug somewhere else.
 *
 * To skip this limit, boot/load with a large max_cstate limit.
 */
static int set_max_cstate(struct dmi_system_id *id)
{
	if (max_cstate > ACPI_PROCESSOR_MAX_POWER)
		return 0;

	printk(KERN_NOTICE PREFIX "%s detected - limiting to C%ld max_cstate."
	       " Override with \"processor.max_cstate=%d\"\n", id->ident,
	       (long)id->driver_data, ACPI_PROCESSOR_MAX_POWER + 1);

	max_cstate = (long)id->driver_data;

	return 0;
}

/* Actually this shouldn't be __cpuinitdata, would be better to fix the
   callers to only run once -AK */
static struct dmi_system_id __cpuinitdata processor_power_dmi_table[] = {
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET70WW")}, (void *)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET60WW")}, (void *)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET43WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET45WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET47WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET50WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET52WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET55WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET56WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET59WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET60WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET61WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET62WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET64WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET65WW") }, (void*)1},
	{ set_max_cstate, "IBM ThinkPad R40e", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"IBM"),
	  DMI_MATCH(DMI_BIOS_VERSION,"1SET68WW") }, (void*)1},
	{ set_max_cstate, "Medion 41700", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"Phoenix Technologies LTD"),
	  DMI_MATCH(DMI_BIOS_VERSION,"R01-A1J")}, (void *)1},
	{ set_max_cstate, "Clevo 5600D", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"Phoenix Technologies LTD"),
	  DMI_MATCH(DMI_BIOS_VERSION,"SHE845M0.86C.0013.D.0302131307")},
	 (void *)2},
	{},
};

#ifdef ARCH_APICTIMER_STOPS_ON_C3

/*
 * Some BIOS implementations switch to C3 in the published C2 state.
 * This seems to be a common problem on AMD boxen, but other vendors
 * are affected too. We pick the most conservative approach: we assume
 * that the local APIC stops in both C2 and C3.
 */
static void acpi_timer_check_state(int state, struct acpi_processor *pr,
				   struct acpi_processor_cx *cx)
{
	struct acpi_processor_power *pwr = &pr->power;
	u8 type = local_apic_timer_c2_ok ? ACPI_STATE_C3 : ACPI_STATE_C2;

	/*
	 * Check, if one of the previous states already marked the lapic
	 * unstable
	 */
	if (pwr->timer_broadcast_on_state < state)
		return;

	if (cx->type >= type)
		pr->power.timer_broadcast_on_state = state;
}

static void acpi_propagate_timer_broadcast(struct acpi_processor *pr)
{
#ifdef CONFIG_GENERIC_CLOCKEVENTS
	unsigned long reason;

	reason = pr->power.timer_broadcast_on_state < INT_MAX ?
		CLOCK_EVT_NOTIFY_BROADCAST_ON : CLOCK_EVT_NOTIFY_BROADCAST_OFF;

	clockevents_notify(reason, &pr->id);
#else
	cpumask_t mask = cpumask_of_cpu(pr->id);

	if (pr->power.timer_broadcast_on_state < INT_MAX)
		on_each_cpu(switch_APIC_timer_to_ipi, &mask, 1, 1);
	else
		on_each_cpu(switch_ipi_to_APIC_timer, &mask, 1, 1);
#endif
}

/* Power(C) State timer broadcast control */
static void acpi_state_timer_broadcast(struct acpi_processor *pr,
				       struct acpi_processor_cx *cx,
				       int broadcast)
{
#ifdef CONFIG_GENERIC_CLOCKEVENTS

	int state = cx - pr->power.states;

	if (state >= pr->power.timer_broadcast_on_state) {
		unsigned long reason;

		reason = broadcast ?  CLOCK_EVT_NOTIFY_BROADCAST_ENTER :
			CLOCK_EVT_NOTIFY_BROADCAST_EXIT;
		clockevents_notify(reason, &pr->id);
	}
#endif
}

#else

static void acpi_timer_check_state(int state, struct acpi_processor *pr,
				   struct acpi_processor_cx *cstate) { }
static void acpi_propagate_timer_broadcast(struct acpi_processor *pr) { }
static void acpi_state_timer_broadcast(struct acpi_processor *pr,
				       struct acpi_processor_cx *cx,
				       int broadcast)
{
}

#endif

static int acpi_processor_get_power_info_fadt(struct acpi_processor *pr)
{

	if (!pr)
		return -EINVAL;

	if (!pr->pblk)
		return -ENODEV;

	/* if info is obtained from pblk/fadt, type equals state */
	pr->power.states[ACPI_STATE_C2].type = ACPI_STATE_C2;
	pr->power.states[ACPI_STATE_C3].type = ACPI_STATE_C3;

#ifndef CONFIG_HOTPLUG_CPU
	/*
	 * Check for P_LVL2_UP flag before entering C2 and above on
	 * an SMP system. 
	 */
	if ((num_online_cpus() > 1) &&
	    !(acpi_gbl_FADT.flags & ACPI_FADT_C2_MP_SUPPORTED))
		return -ENODEV;
#endif

	/* determine C2 and C3 address from pblk */
	pr->power.states[ACPI_STATE_C2].address = pr->pblk + 4;
	pr->power.states[ACPI_STATE_C3].address = pr->pblk + 5;

	/* determine latencies from FADT */
	pr->power.states[ACPI_STATE_C2].latency = acpi_gbl_FADT.C2latency;
	pr->power.states[ACPI_STATE_C3].latency = acpi_gbl_FADT.C3latency;

	ACPI_DEBUG_PRINT((ACPI_DB_INFO,
			  "lvl2[0x%08x] lvl3[0x%08x]\n",
			  pr->power.states[ACPI_STATE_C2].address,
			  pr->power.states[ACPI_STATE_C3].address));

	return 0;
}

static int acpi_processor_get_power_info_default(struct acpi_processor *pr)
{
	if (!pr->power.states[ACPI_STATE_C1].valid) {
		/* set the first C-State to C1 */
		/* all processors need to support C1 */
		pr->power.states[ACPI_STATE_C1].type = ACPI_STATE_C1;
		pr->power.states[ACPI_STATE_C1].valid = 1;
	}
	/* the C0 state only exists as a filler in our array */
	pr->power.states[ACPI_STATE_C0].valid = 1;
	return 0;
}

static int acpi_processor_get_power_info_cst(struct acpi_processor *pr)
{
	acpi_status status = 0;
	acpi_integer count;
	int current_count;
	int i;
	struct acpi_buffer buffer = { ACPI_ALLOCATE_BUFFER, NULL };
	union acpi_object *cst;


	if (nocst)
		return -ENODEV;

	current_count = 0;

	status = acpi_evaluate_object(pr->handle, "_CST", NULL, &buffer);
	if (ACPI_FAILURE(status)) {
		ACPI_DEBUG_PRINT((ACPI_DB_INFO, "No _CST, giving up\n"));
		return -ENODEV;
	}

	cst = buffer.pointer;

	/* There must be at least 2 elements */
	if (!cst || (cst->type != ACPI_TYPE_PACKAGE) || cst->package.count < 2) {
		printk(KERN_ERR PREFIX "not enough elements in _CST\n");
		status = -EFAULT;
		goto end;
	}

	count = cst->package.elements[0].integer.value;

	/* Validate number of power states. */
	if (count < 1 || count != cst->package.count - 1) {
		printk(KERN_ERR PREFIX "count given by _CST is not valid\n");
		status = -EFAULT;
		goto end;
	}

	/* Tell driver that at least _CST is supported. */
	pr->flags.has_cst = 1;

	for (i = 1; i <= count; i++) {
		union acpi_object *element;
		union acpi_object *obj;
		struct acpi_power_register *reg;
		struct acpi_processor_cx cx;

		memset(&cx, 0, sizeof(cx));

		element = &(cst->package.elements[i]);
		if (element->type != ACPI_TYPE_PACKAGE)
			continue;

		if (element->package.count != 4)
			continue;

		obj = &(element->package.elements[0]);

		if (obj->type != ACPI_TYPE_BUFFER)
			continue;

		reg = (struct acpi_power_register *)obj->buffer.pointer;

		if (reg->space_id != ACPI_ADR_SPACE_SYSTEM_IO &&
		    (reg->space_id != ACPI_ADR_SPACE_FIXED_HARDWARE))
			continue;

		/* There should be an easy way to extract an integer... */
		obj = &(element->package.elements[1]);
		if (obj->type != ACPI_TYPE_INTEGER)
			continue;

		cx.type = obj->integer.value;
		/*
		 * Some buggy BIOSes won't list C1 in _CST -
		 * Let acpi_processor_get_power_info_default() handle them later
		 */
		if (i == 1 && cx.type != ACPI_STATE_C1)
			current_count++;

		cx.address = reg->address;
		cx.index = current_count + 1;

		cx.space_id = ACPI_CSTATE_SYSTEMIO;
		if (reg->space_id == ACPI_ADR_SPACE_FIXED_HARDWARE) {
			if (acpi_processor_ffh_cstate_probe
					(pr->id, &cx, reg) == 0) {
				cx.space_id = ACPI_CSTATE_FFH;
			} else if (cx.type != ACPI_STATE_C1) {
				/*
				 * C1 is a special case where FIXED_HARDWARE
				 * can be handled in non-MWAIT way as well.
				 * In that case, save this _CST entry info.
				 * That is, we retain space_id of SYSTEM_IO for
				 * halt based C1.
				 * Otherwise, ignore this info and continue.
				 */
				continue;
			}
		}

		obj = &(element->package.elements[2]);
		if (obj->type != ACPI_TYPE_INTEGER)
			continue;

		cx.latency = obj->integer.value;

		obj = &(element->package.elements[3]);
		if (obj->type != ACPI_TYPE_INTEGER)
			continue;

		cx.power = obj->integer.value;

		current_count++;
		memcpy(&(pr->power.states[current_count]), &cx, sizeof(cx));

		/*
		 * We support total ACPI_PROCESSOR_MAX_POWER - 1
		 * (From 1 through ACPI_PROCESSOR_MAX_POWER - 1)
		 */
		if (current_count >= (ACPI_PROCESSOR_MAX_POWER - 1)) {
			printk(KERN_WARNING
			       "Limiting number of power states to max (%d)\n",
			       ACPI_PROCESSOR_MAX_POWER);
			printk(KERN_WARNING
			       "Please increase ACPI_PROCESSOR_MAX_POWER if needed.\n");
			break;
		}
	}

	ACPI_DEBUG_PRINT((ACPI_DB_INFO, "Found %d power states\n",
			  current_count));

	/* Validate number of power states discovered */
	if (current_count < 2)
		status = -EFAULT;

      end:
	kfree(buffer.pointer);

	return status;
}

static void acpi_processor_power_verify_c2(struct acpi_processor_cx *cx)
{

	if (!cx->address)
		return;

	/*
	 * C2 latency must be less than or equal to 100
	 * microseconds.
	 */
	else if (cx->latency > ACPI_PROCESSOR_MAX_C2_LATENCY) {
		ACPI_DEBUG_PRINT((ACPI_DB_INFO,
				  "latency too large [%d]\n", cx->latency));
		return;
	}

	/*
	 * Otherwise we've met all of our C2 requirements.
	 * Normalize the C2 latency to expidite policy
	 */
	cx->valid = 1;
	cx->latency_ticks = cx->latency;

	return;
}

static void acpi_processor_power_verify_c3(struct acpi_processor *pr,
					   struct acpi_processor_cx *cx)
{
	static int bm_check_flag;


	if (!cx->address)
		return;

	/*
	 * C3 latency must be less than or equal to 1000
	 * microseconds.
	 */
	else if (cx->latency > ACPI_PROCESSOR_MAX_C3_LATENCY) {
		ACPI_DEBUG_PRINT((ACPI_DB_INFO,
				  "latency too large [%d]\n", cx->latency));
		return;
	}

	/*
	 * PIIX4 Erratum #18: We don't support C3 when Type-F (fast)
	 * DMA transfers are used by any ISA device to avoid livelock.
	 * Note that we could disable Type-F DMA (as recommended by
	 * the erratum), but this is known to disrupt certain ISA
	 * devices thus we take the conservative approach.
	 */
	else if (errata.piix4.fdma) {
		ACPI_DEBUG_PRINT((ACPI_DB_INFO,
				  "C3 not supported on PIIX4 with Type-F DMA\n"));
		return;
	}

	/* All the logic here assumes flags.bm_check is same across all CPUs */
	if (!bm_check_flag) {
		/* Determine whether bm_check is needed based on CPU  */
		acpi_processor_power_init_bm_check(&(pr->flags), pr->id);
		bm_check_flag = pr->flags.bm_check;
	} else {
		pr->flags.bm_check = bm_check_flag;
	}

	if (pr->flags.bm_check) {
		/* bus mastering control is necessary */
		if (!pr->flags.bm_control) {
			/* In this case we enter C3 without bus mastering */
			ACPI_DEBUG_PRINT((ACPI_DB_INFO,
				"C3 support without bus mastering control\n"));
		}
	} else {
		/*
		 * WBINVD should be set in fadt, for C3 state to be
		 * supported on when bm_check is not required.
		 */
		if (!(acpi_gbl_FADT.flags & ACPI_FADT_WBINVD)) {
			ACPI_DEBUG_PRINT((ACPI_DB_INFO,
					  "Cache invalidation should work properly"
					  " for C3 to be enabled on SMP systems\n"));
			return;
		}
		acpi_set_register(ACPI_BITREG_BUS_MASTER_RLD, 0);
	}

	/*
	 * Otherwise we've met all of our C3 requirements.
	 * Normalize the C3 latency to expidite policy.  Enable
	 * checking of bus mastering status (bm_check) so we can
	 * use this in our C3 policy
	 */
	cx->valid = 1;
	cx->latency_ticks = cx->latency;

	return;
}

static int acpi_processor_power_verify(struct acpi_processor *pr)
{
	unsigned int i;
	unsigned int working = 0;

	pr->power.timer_broadcast_on_state = INT_MAX;

	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER; i++) {
		struct acpi_processor_cx *cx = &pr->power.states[i];

		switch (cx->type) {
		case ACPI_STATE_C1:
			cx->valid = 1;
			break;

		case ACPI_STATE_C2:
			acpi_processor_power_verify_c2(cx);
			if (cx->valid)
				acpi_timer_check_state(i, pr, cx);
			break;

		case ACPI_STATE_C3:
			acpi_processor_power_verify_c3(pr, cx);
			if (cx->valid)
				acpi_timer_check_state(i, pr, cx);
			break;
		}

		if (cx->valid)
			working++;
	}

	acpi_propagate_timer_broadcast(pr);

	return (working);
}

static int acpi_processor_get_power_info(struct acpi_processor *pr)
{
	unsigned int i;
	int result;


	/* NOTE: the idle thread may not be running while calling
	 * this function */

	/* Zero initialize all the C-states info. */
	memset(pr->power.states, 0, sizeof(pr->power.states));

	result = acpi_processor_get_power_info_cst(pr);
	if (result == -ENODEV)
		result = acpi_processor_get_power_info_fadt(pr);

	if (result)
		return result;

	acpi_processor_get_power_info_default(pr);

	pr->power.count = acpi_processor_power_verify(pr);

	/*
	 * if one state of type C2 or C3 is available, mark this
	 * CPU as being "idle manageable"
	 */
	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER; i++) {
		if (pr->power.states[i].valid) {
			pr->power.count = i;
			if (pr->power.states[i].type >= ACPI_STATE_C2)
				pr->flags.power = 1;
		}
	}

	return 0;
}

int acpi_processor_cst_has_changed(struct acpi_processor *pr)
{
	if (!pr)
		return -EINVAL;

	if (nocst) {
		return -ENODEV;
	}

	if (!pr->flags.power_setup_done)
		return -ENODEV;

	acpi_processor_get_power_info(pr);
	return cpuidle_force_redetect(per_cpu(cpuidle_devices, pr->id),
		&acpi_idle_driver);
}

/* proc interface */

static int acpi_processor_power_seq_show(struct seq_file *seq, void *offset)
{
	struct acpi_processor *pr = seq->private;
	unsigned int i;


	if (!pr)
		goto end;

	seq_printf(seq, "active state:            C%zd\n"
		   "max_cstate:              C%d\n"
		   "bus master activity:     %08x\n"
		   "maximum allowed latency: %d usec\n",
		   pr->power.state ? pr->power.state - pr->power.states : 0,
		   max_cstate, (unsigned)pr->power.bm_activity,
		   system_latency_constraint());

	seq_puts(seq, "states:\n");

	for (i = 1; i <= pr->power.count; i++) {
		seq_printf(seq, "   %cC%d:                  ",
			   (&pr->power.states[i] ==
			    pr->power.state ? '*' : ' '), i);

		if (!pr->power.states[i].valid) {
			seq_puts(seq, "<not supported>\n");
			continue;
		}

		switch (pr->power.states[i].type) {
		case ACPI_STATE_C1:
			seq_printf(seq, "type[C1] ");
			break;
		case ACPI_STATE_C2:
			seq_printf(seq, "type[C2] ");
			break;
		case ACPI_STATE_C3:
			seq_printf(seq, "type[C3] ");
			break;
		default:
			seq_printf(seq, "type[--] ");
			break;
		}

		if (pr->power.states[i].promotion.state)
			seq_printf(seq, "promotion[C%zd] ",
				   (pr->power.states[i].promotion.state -
				    pr->power.states));
		else
			seq_puts(seq, "promotion[--] ");

		if (pr->power.states[i].demotion.state)
			seq_printf(seq, "demotion[C%zd] ",
				   (pr->power.states[i].demotion.state -
				    pr->power.states));
		else
			seq_puts(seq, "demotion[--] ");

		seq_printf(seq, "latency[%03d] usage[%08d] duration[%020llu]\n",
			   pr->power.states[i].latency,
			   pr->power.states[i].usage,
			   (unsigned long long)pr->power.states[i].time);
	}

      end:
	return 0;
}

static int acpi_processor_power_open_fs(struct inode *inode, struct file *file)
{
	return single_open(file, acpi_processor_power_seq_show,
			   PDE(inode)->data);
}

static const struct file_operations acpi_processor_power_fops = {
	.open = acpi_processor_power_open_fs,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

int __cpuinit acpi_processor_power_init(struct acpi_processor *pr,
			      struct acpi_device *device)
{
	acpi_status status = 0;
	static int first_run;
	struct proc_dir_entry *entry = NULL;
	unsigned int i;


	if (!first_run) {
		dmi_check_system(processor_power_dmi_table);
		if (max_cstate < ACPI_C_STATES_MAX)
			printk(KERN_NOTICE
			       "ACPI: processor limited to max C-state %d\n",
			       max_cstate);
		first_run++;
	}

	if (!pr)
		return -EINVAL;

	if (acpi_gbl_FADT.cst_control && !nocst) {
		status =
		    acpi_os_write_port(acpi_gbl_FADT.smi_command, acpi_gbl_FADT.cst_control, 8);
		if (ACPI_FAILURE(status)) {
			ACPI_EXCEPTION((AE_INFO, status,
					"Notifying BIOS of _CST ability failed"));
		}
	}

	acpi_processor_get_power_info(pr);


	/*
	 * Install the idle handler if processor power management is supported.
	 * Note that we use previously set idle handler will be used on
	 * platforms that only support C1.
	 */
	if ((pr->flags.power) && (!boot_option_idle_override)) {
		printk(KERN_INFO PREFIX "CPU%d (power states:", pr->id);
		for (i = 1; i <= pr->power.count; i++)
			if (pr->power.states[i].valid)
				printk(" C%d[C%d]", i,
				       pr->power.states[i].type);
		printk(")\n");
	}

	/* 'power' [R] */
	entry = create_proc_entry(ACPI_PROCESSOR_FILE_POWER,
				  S_IRUGO, acpi_device_dir(device));
	if (!entry)
		return -EIO;
	else {
		entry->proc_fops = &acpi_processor_power_fops;
		entry->data = acpi_driver_data(device);
		entry->owner = THIS_MODULE;
	}

	pr->flags.power_setup_done = 1;

	return 0;
}

int acpi_processor_power_exit(struct acpi_processor *pr,
			      struct acpi_device *device)
{

	pr->flags.power_setup_done = 0;

	if (acpi_device_dir(device))
		remove_proc_entry(ACPI_PROCESSOR_FILE_POWER,
				  acpi_device_dir(device));
	return 0;
}

/**
 * ticks_elapsed - a helper function that determines how many ticks (in US)
 *		   have elapsed between two PM Timer timestamps
 * @t1: the start time
 * @t2: the end time
 */
static inline u32 ticks_elapsed_in_us(u32 t1, u32 t2)
{
	if (t2 >= t1)
		return PM_TIMER_TICKS_TO_US(t2 - t1);
	else if (!(acpi_gbl_FADT.flags & ACPI_FADT_32BIT_TIMER))
		return PM_TIMER_TICKS_TO_US(((0x00FFFFFF - t1) + t2) & 0x00FFFFFF);
	else
		return PM_TIMER_TICKS_TO_US((0xFFFFFFFF - t1) + t2);
}

static inline u32 ticks_elapsed(u32 t1, u32 t2)
{
	if (t2 >= t1)
		return (t2 - t1);
	else if (!(acpi_gbl_FADT.flags & ACPI_FADT_32BIT_TIMER))
		return (((0x00FFFFFF - t1) + t2) & 0x00FFFFFF);
	else
		return ((0xFFFFFFFF - t1) + t2);
}

/**
 * acpi_idle_update_bm_rld - updates the BM_RLD bit depending on target state
 * @pr: the processor
 * @target: the new target state
 */
static inline void acpi_idle_update_bm_rld(struct acpi_processor *pr,
					   struct acpi_processor_cx *target)
{
	if (pr->flags.bm_rld_set && target->type != ACPI_STATE_C3) {
		acpi_set_register(ACPI_BITREG_BUS_MASTER_RLD, 0);
		pr->flags.bm_rld_set = 0;
	}

	if (!pr->flags.bm_rld_set && target->type == ACPI_STATE_C3) {
		acpi_set_register(ACPI_BITREG_BUS_MASTER_RLD, 1);
		pr->flags.bm_rld_set = 1;
	}
}

/**
 * acpi_idle_do_entry - a helper function that does C2 and C3 type entry
 * @cx: cstate data
 */
static inline void acpi_idle_do_entry(struct acpi_processor_cx *cx)
{
	if (cx->space_id == ACPI_CSTATE_FFH) {
		/* Call into architectural FFH based C-state */
		acpi_processor_ffh_cstate_enter(cx);
	} else {
		int unused;
		/* IO port based C-state */
		inb(cx->address);
		/* Dummy wait op - must do something useless after P_LVL2 read
		   because chipsets cannot guarantee that STPCLK# signal
		   gets asserted in time to freeze execution properly. */
		unused = inl(acpi_gbl_FADT.xpm_timer_block.address);
	}
}

/**
 * acpi_idle_enter_c1 - enters an ACPI C1 state-type
 * @dev: the target CPU
 * @state: the state data
 *
 * This is equivalent to the HALT instruction.
 */
static int acpi_idle_enter_c1(struct cpuidle_device *dev,
			      struct cpuidle_state *state)
{
	struct acpi_processor *pr;
	struct acpi_processor_cx *cx = cpuidle_get_statedata(state);
	pr = processors[smp_processor_id()];

	if (unlikely(!pr))
		return 0;

	if (pr->flags.bm_check)
		acpi_idle_update_bm_rld(pr, cx);

	current_thread_info()->status &= ~TS_POLLING;
	/*
	 * TS_POLLING-cleared state must be visible before we test
	 * NEED_RESCHED:
	 */
	smp_mb();
	if (!need_resched())
		safe_halt();
	current_thread_info()->status |= TS_POLLING;

	cx->usage++;

	return 0;
}

/**
 * acpi_idle_enter_c2 - enters an ACPI C2 state-type
 * @dev: the target CPU
 * @state: the state data
 */
static int acpi_idle_enter_c2(struct cpuidle_device *dev,
			      struct cpuidle_state *state)
{
	struct acpi_processor *pr;
	struct acpi_processor_cx *cx = cpuidle_get_statedata(state);
	u32 t1, t2;
	pr = processors[smp_processor_id()];

	if (unlikely(!pr))
		return 0;

	if (pr->flags.bm_check)
		acpi_idle_update_bm_rld(pr, cx);

	local_irq_disable();
	current_thread_info()->status &= ~TS_POLLING;
	/*
	 * TS_POLLING-cleared state must be visible before we test
	 * NEED_RESCHED:
	 */
	smp_mb();

	if (unlikely(need_resched())) {
		current_thread_info()->status |= TS_POLLING;
		local_irq_enable();
		return 0;
	}

	t1 = inl(acpi_gbl_FADT.xpm_timer_block.address);
	acpi_state_timer_broadcast(pr, cx, 1);
	acpi_idle_do_entry(cx);
	t2 = inl(acpi_gbl_FADT.xpm_timer_block.address);

#if defined(CONFIG_GENERIC_TIME) && defined(CONFIG_X86)
	/* TSC halts in C2, so notify users */
	mark_tsc_unstable("possible TSC halt in C2");
#endif

	local_irq_enable();
	current_thread_info()->status |= TS_POLLING;

	cx->usage++;

	acpi_state_timer_broadcast(pr, cx, 0);
	cx->time += ticks_elapsed(t1, t2);
	return ticks_elapsed_in_us(t1, t2);
}

static int c3_cpu_count;
static DEFINE_SPINLOCK(c3_lock);

/**
 * acpi_idle_enter_c3 - enters an ACPI C3 state-type
 * @dev: the target CPU
 * @state: the state data
 *
 * Similar to C2 entry, except special bus master handling is needed.
 */
static int acpi_idle_enter_c3(struct cpuidle_device *dev,
			      struct cpuidle_state *state)
{
	struct acpi_processor *pr;
	struct acpi_processor_cx *cx = cpuidle_get_statedata(state);
	u32 t1, t2;
	pr = processors[smp_processor_id()];

	if (unlikely(!pr))
		return 0;

	if (pr->flags.bm_check)
		acpi_idle_update_bm_rld(pr, cx);

	local_irq_disable();
	current_thread_info()->status &= ~TS_POLLING;
	/*
	 * TS_POLLING-cleared state must be visible before we test
	 * NEED_RESCHED:
	 */
	smp_mb();

	if (unlikely(need_resched())) {
		current_thread_info()->status |= TS_POLLING;
		local_irq_enable();
		return 0;
	}

	/* disable bus master */
	if (pr->flags.bm_check) {
		spin_lock(&c3_lock);
			c3_cpu_count++;
		if (c3_cpu_count == num_online_cpus()) {
			/*
			 * All CPUs are trying to go to C3
			 * Disable bus master arbitration
			 */
			acpi_set_register(ACPI_BITREG_ARB_DISABLE, 1);
		}
		spin_unlock(&c3_lock);
	} else {
		/* SMP with no shared cache... Invalidate cache  */
		ACPI_FLUSH_CPU_CACHE();
	}

	/* Get start time (ticks) */
	t1 = inl(acpi_gbl_FADT.xpm_timer_block.address);
	acpi_state_timer_broadcast(pr, cx, 1);
	acpi_idle_do_entry(cx);
	t2 = inl(acpi_gbl_FADT.xpm_timer_block.address);

	if (pr->flags.bm_check) {
		spin_lock(&c3_lock);
		/* Enable bus master arbitration */
		if (c3_cpu_count == num_online_cpus())
			acpi_set_register(ACPI_BITREG_ARB_DISABLE, 0);
		c3_cpu_count--;
		spin_unlock(&c3_lock);
	}

#if defined(CONFIG_GENERIC_TIME) && defined(CONFIG_X86)
	/* TSC halts in C3, so notify users */
	mark_tsc_unstable("TSC halts in C3");
#endif

	local_irq_enable();
	current_thread_info()->status |= TS_POLLING;

	cx->usage++;

	acpi_state_timer_broadcast(pr, cx, 0);
	cx->time += ticks_elapsed(t1, t2);
	return ticks_elapsed_in_us(t1, t2);
}

/**
 * acpi_idle_bm_check - checks if bus master activity was detected
 */
static int acpi_idle_bm_check(void)
{
	u32 bm_status = 0;

	acpi_get_register(ACPI_BITREG_BUS_MASTER_STATUS, &bm_status);
	if (bm_status)
		acpi_set_register(ACPI_BITREG_BUS_MASTER_STATUS, 1);
	/*
	 * PIIX4 Erratum #18: Note that BM_STS doesn't always reflect
	 * the true state of bus mastering activity; forcing us to
	 * manually check the BMIDEA bit of each IDE channel.
	 */
	else if (errata.piix4.bmisx) {
		if ((inb_p(errata.piix4.bmisx + 0x02) & 0x01)
		    || (inb_p(errata.piix4.bmisx + 0x0A) & 0x01))
			bm_status = 1;
	}
	return bm_status;
}

/**
 * acpi_idle_init - attaches the driver to a CPU
 * @dev: the CPU
 */
static int acpi_idle_init(struct cpuidle_device *dev)
{
	int cpu = dev->cpu;
	int i, count = 0;
	struct acpi_processor_cx *cx;
	struct cpuidle_state *state;

	struct acpi_processor *pr = processors[cpu];

	if (!pr->flags.power_setup_done)
		return -EINVAL;

	if (pr->flags.power == 0) {
		return -EINVAL;
	}

	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER && i <= max_cstate; i++) {
		cx = &pr->power.states[i];
		state = &dev->states[count];

		if (!cx->valid)
			continue;

#ifdef CONFIG_HOTPLUG_CPU
		if ((cx->type != ACPI_STATE_C1) && (num_online_cpus() > 1) &&
		    !pr->flags.has_cst &&
		    !(acpi_gbl_FADT.flags & ACPI_FADT_C2_MP_SUPPORTED))
			continue;
#endif
		cpuidle_set_statedata(state, cx);

		state->exit_latency = cx->latency;
		state->target_residency = cx->latency * 6;
		state->power_usage = cx->power;

		state->flags = 0;
		switch (cx->type) {
			case ACPI_STATE_C1:
			state->flags |= CPUIDLE_FLAG_SHALLOW;
			state->enter = acpi_idle_enter_c1;
			break;

			case ACPI_STATE_C2:
			state->flags |= CPUIDLE_FLAG_BALANCED;
			state->flags |= CPUIDLE_FLAG_TIME_VALID;
			state->enter = acpi_idle_enter_c2;
			break;

			case ACPI_STATE_C3:
			state->flags |= CPUIDLE_FLAG_DEEP;
			state->flags |= CPUIDLE_FLAG_TIME_VALID;
			state->flags |= CPUIDLE_FLAG_CHECK_BM;
			state->enter = acpi_idle_enter_c3;
			break;
		}

		count++;
	}

	if (!count)
		return -EINVAL;

	dev->state_count = count;
	return 0;
}

struct cpuidle_driver acpi_idle_driver = {
	.name =		"acpi_idle",
	.init =		acpi_idle_init,
	.redetect =	acpi_idle_init,
	.bm_check =	acpi_idle_bm_check,
	.owner =	THIS_MODULE,
};
