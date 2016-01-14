#ifndef __ASM_I8253_H__
#define __ASM_I8253_H__

/* i8253A PIT registers */
#define PIT_MODE		0x43
#define PIT_CH0			0x40
#define PIT_CH2			0x42

extern spinlock_t i8253_lock;

#ifdef CONFIG_GENERIC_CLOCKEVENTS

#include <linux/clockchips.h>

extern struct clock_event_device *global_clock_event;

/**
 * pit_interrupt_hook - hook into timer tick
 * @regs:	standard registers from interrupt
 *
 * Call the global clock event handler.
 **/
static inline void pit_interrupt_hook(void)
{
	global_clock_event->event_handler(global_clock_event);
}

#endif

extern void setup_pit_timer(void);

#endif	/* __ASM_I8253_H__ */
