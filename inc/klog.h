#pragma once

#include <stddef.h>

/* Initialize kernel logging subsystem (create /var/log if needed). */
void klog_init(void);

/* Kernel printf that appends to /var/log/kernel (best-effort) and to qemu debug. */
void klogprintf(const char *fmt, ...);

/* Calibrate TSC-based high-resolution timestamping (non-blocking if APIC not ready). */
void klog_calibrate_tsc(void);


