#pragma once

#include <stdint.h>

#define OS_NAME "AxonOS"
#define OS_VERSION "2.2"
#define OS_AUTHORS "AxonOS Team"

/* Syscall globals (defined in syscall64/syscall.c). */
extern uint64_t syscall_kernel_rsp0;
extern uint64_t syscall_user_return_rip;
void syscall_set_user_brk(uintptr_t base);

/* Populate default sysfs tree and /etc (called from SYS_mount when userspace mounts sysfs). */
void kernel_sysfs_populate_default(void);