#pragma once

#include <stdint.h>

/* User stack constants for simple exec (must be below identity limit) */
#define USER_STACK_TOP ((uintptr_t)0x3FF00000ULL) /* ~1GiB */
#define USER_STACK_SIZE (2 * 1024 * 1024) /* 2MiB */

/* Execute ELF at path: loads ELF, prepares user stack (argv/envp) and transfers
   execution into user mode. This function does not return on success.
   Returns 0 on success (does not return), negative on error. */
int kernel_execve_from_path(const char *path, const char *const argv[], const char *const envp[]);


