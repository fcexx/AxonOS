#pragma once

#include <stdint.h>

/* User stack constants for simple exec (must be below identity limit) */
#define USER_STACK_TOP ((uintptr_t)0x03000000ULL) /* 48MiB (must be in RAM on small QEMU configs) */
#define USER_STACK_SIZE (2 * 1024 * 1024) /* 2MiB */

/* Reserve a separate user TLS region just below the stack guard area.
   This prevents brk()/mmap() from overwriting TLS canary at fs:0x28 which would trigger
   false "*** stack smashing detected ***" in libc/busybox. */
#define USER_TLS_SIZE  (2 * 1024 * 1024) /* 2MiB reserved (we currently use only 4KiB) */
#define USER_TLS_BASE  ((uintptr_t)USER_STACK_TOP - USER_STACK_SIZE - USER_TLS_SIZE) /* 44MiB */

/* Execute ELF at path: loads ELF, prepares user stack (argv/envp) and transfers
   execution into user mode. This function does not return on success.
   Returns 0 on success (does not return), negative on error. */
int kernel_execve_from_path(const char *path, const char *const argv[], const char *const envp[]);


