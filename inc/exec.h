#pragma once

#include <stdint.h>

/* User stack constants for simple exec (must be below identity limit) */
/* User virtual memory ceiling for mmap/brk (AxonOS exec layout).
 * Keep it below the 4GiB identity window, but leave enough room for large static
 * glibc binaries (OpenSSL reaches ~192MiB) plus per-tid stack/TLS slots. */
#define USER_STACK_TOP ((uintptr_t)0x40000000ULL) /* 1GiB */
#define USER_STACK_SIZE (8 * 1024 * 1024) /* 8MiB; linuxrc/glibc need >2MiB stack */

/* Reserve a separate user TLS region just below the stack guard area.
   This prevents brk()/mmap() from overwriting TLS canary at fs:0x28 which would trigger
   false "*** stack smashing detected ***" in libc/busybox. */
#define USER_TLS_SIZE  (2 * 1024 * 1024) /* 2MiB reserved (we currently use only 4KiB) */
#define USER_TLS_BASE  ((uintptr_t)USER_STACK_TOP - USER_STACK_SIZE - USER_TLS_SIZE)

/* Execute ELF at path: loads ELF, prepares user stack (argv/envp) and transfers
   execution into user mode. This function does not return on success.
   Returns 0 on success (does not return), negative on error. */
int kernel_execve_from_path(const char *path, const char *const argv[], const char *const envp[]);

/* Fixed user-space trampoline for safe vfork child entry (must be in low identity map). */
#define USER_VFORK_TRAMP ((uintptr_t)0x00201000ULL) /* 2MiB + 4KiB */

/* ET_DYN (PIE) load base: 2MiB-aligned above kernel _end (grows with BSS e.g. kstack pool). */
uint64_t elf_et_dyn_base(void);

/* Default ET_DYN interpreter base. The exec path may move it upward to avoid the main image. */
uint64_t elf_interp_base(void);

/* Ensure user mappings (PG_US) for low memory and GOT region before entering user mode.
   Must be called from user_thread_entry for init path (elf exec path may skip it). */
void exec_ensure_user_mappings(void);


