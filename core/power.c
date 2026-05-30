#include <power.h>
#include <acpi_powerbtn.h>
#include <klog.h>
#include <serial.h>
#include <string.h>
#include <pit.h>
#include <vga.h>

/*
 * Very small "graceful" power control:
 * - IRQ handlers only request an action
 * - the idle thread executes the action in normal thread context
 *
 * This avoids doing complex work from interrupt context.
 */

typedef enum {
	POWER_ACT_NONE = 0,
	POWER_ACT_SHUTDOWN = 1,
	POWER_ACT_REBOOT = 2,
} power_action_t;

static volatile power_action_t g_power_action;
static const char *g_power_reason;

int power_is_pending(void) {
	return g_power_action != POWER_ACT_NONE;
}

void power_request_shutdown(const char *reason) {
	g_power_reason = reason ? reason : "unspecified";
	g_power_action = POWER_ACT_SHUTDOWN;
}

void power_request_reboot(const char *reason) {
	g_power_reason = reason ? reason : "unspecified";
	g_power_action = POWER_ACT_REBOOT;
}

void power_poll(void) {
	power_action_t act = g_power_action;
	if (act == POWER_ACT_NONE)
		return;

	/* One-shot: prevent repeated triggers. */
	g_power_action = POWER_ACT_NONE;

	const char *why = g_power_reason ? g_power_reason : "unspecified";
	if (act == POWER_ACT_SHUTDOWN) {
		klogprintf("power: shutdown requested (%s)\n", why);
		kprintf("\n[power] shutdown requested (%s)\n", why);

		/* Give the operator time to see the message and allow klog file appends. */
		apic_timer_sleep_ms(1500);

		acpi_try_power_off();
	} else if (act == POWER_ACT_REBOOT) {
		klogprintf("power: reboot requested (%s)\n", why);
		kprintf("\n[power] reboot requested (%s)\n", why);
		reboot_system();
	}
}

