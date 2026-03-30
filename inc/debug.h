#pragma once

void qemu_debug_printf(const char *format, ...);
/* OOM notify: uses only stack + write_serial, no kmalloc. Safe to call when heap exhausted. */
void oom_serial_notify(unsigned long long syscall_num, const char *name);