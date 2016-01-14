/*
 * Copyright 2004 James Cleverdon, IBM.
 * Subject to the GNU Public License, v.2
 *
 * Generic APIC sub-arch probe layer.
 *
 * Hacked for x86-64 by James Cleverdon from i386 architecture code by
 * Martin Bligh, Andi Kleen, James Bottomley, John Stultz, and
 * James Cleverdon.
 */
#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/hardirq.h>
#include <linux/dmar.h>

#include <asm/smp.h>
#include <asm/ipi.h>
#include <asm/genapic.h>
#include <asm/setup.h>

extern struct genapic apic_flat;
extern struct genapic apic_physflat;
extern struct genapic apic_x2xpic_uv_x;
extern struct genapic apic_x2apic_phys;
extern struct genapic apic_x2apic_cluster;

struct genapic __read_mostly *apic = &apic_flat;

static struct genapic *apic_probe[] __initdata = {
#ifdef CONFIG_X86_UV
	&apic_x2apic_uv_x,
#endif
	&apic_x2apic_phys,
	&apic_x2apic_cluster,
	&apic_physflat,
	NULL,
};

/*
 * Check the APIC IDs in bios_cpu_apicid and choose the APIC mode.
 */
void __init default_setup_apic_routing(void)
{
	if (apic == &apic_x2apic_phys || apic == &apic_x2apic_cluster) {
		if (!intr_remapping_enabled)
			apic = &apic_flat;
	}

	if (apic == &apic_flat) {
		if (max_physical_apicid >= 8)
			apic = &apic_physflat;
		printk(KERN_INFO "Setting APIC routing to %s\n", apic->name);
	}

	if (x86_quirks->update_genapic)
		x86_quirks->update_genapic();
}

/* Same for both flat and physical. */

void apic_send_IPI_self(int vector)
{
	__default_send_IPI_shortcut(APIC_DEST_SELF, vector, APIC_DEST_PHYSICAL);
}

int __init default_acpi_madt_oem_check(char *oem_id, char *oem_table_id)
{
	int i;

	for (i = 0; apic_probe[i]; ++i) {
		if (apic_probe[i]->acpi_madt_oem_check(oem_id, oem_table_id)) {
			apic = apic_probe[i];
			printk(KERN_INFO "Setting APIC routing to %s.\n",
				apic->name);
			return 1;
		}
	}
	return 0;
}
