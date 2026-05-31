#pragma once

#include <stdint.h>

struct thread;
typedef struct thread thread_t;

#ifndef AXON_FORK_DEBUG
#define AXON_FORK_DEBUG 1
#endif

void qemu_debug_printf(const char *format, ...);
/* User-visible trace: writes to cur->fds[1] (stdout) and qemu_debug_printf. */
void axon_user_dbg(thread_t *cur, const char *tag, int step, const char *msg,
    unsigned long long a, unsigned long long b, unsigned long long c);
/* OOM notify: uses only stack + write_serial, no kmalloc. Safe to call when heap exhausted. */
void oom_serial_notify(unsigned long long syscall_num, const char *name);