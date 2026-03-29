#pragma once

#include <stdint.h>

#define OS_NAME "AxonOS"
#define OS_VERSION "3.2.0"
#define OS_AUTHORS "AxonOS Team"

/* Syscall globals (defined in syscall64/syscall.c). */
extern uint64_t syscall_kernel_rsp0;
extern uint64_t syscall_user_return_rip;
extern uint64_t syscall_user_return_rax;
void syscall_set_user_brk(uintptr_t base);

/* Try to handle user page fault by growing heap. Returns 1 if fault was handled. */
int fault_try_grow_user_heap(uint64_t cr2);
int syscall_try_handle_uaccess_fault(uint64_t fault_addr, uint64_t *resume_rip_out);

/* Populate default sysfs tree and /etc (called from SYS_mount when userspace mounts sysfs). */
void kernel_sysfs_populate_default(void);

/* Re-create /etc/resolv.conf and /etc/hosts from current net config. */
void syscall_net_ensure_resolv(void);

/* SYS_resolve (1000): resolve hostname via DNS. See inc/syscall.h. */
