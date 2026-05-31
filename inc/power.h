#pragma once

#include <stdint.h>

/* Request a graceful shutdown (executed from idle thread context). */
void power_request_shutdown(const char *reason);

/* Request a graceful reboot (executed from idle thread context). */
void power_request_reboot(const char *reason);

/* Called from idle loop to perform requested action. */
void power_poll(void);

/* Minimal helper for timer/IRQ paths: returns non-zero if an action is pending. */
int power_is_pending(void);

