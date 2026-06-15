#pragma once

#include <stddef.h>
#include <stdint.h>

/* After ramfs_register(): create /var/log and flush buffered pre-init lines to /var/log/kernel. */
void klog_init(void);

/* Kernel printf that appends to /var/log/kernel (best-effort) and to qemu debug. */
void klogprintf(const char *fmt, ...);

/* Calibrate TSC-based high-resolution timestamping (non-blocking if APIC not ready). */
void klog_calibrate_tsc(void);

/* Set by klog_calibrate_tsc(); 0 until calibrated. Used for CLI-safe busy waits (e.g. SMP INIT/SIPI). */
extern uint64_t klog_tsc_per_us;
extern uint64_t klog_tsc_hz;

/* Monotonic time (us/ms) — same source as kernel log timestamps (TSC when calibrated). */
uint64_t time_monotonic_us(void);
uint64_t time_monotonic_ms(void);


