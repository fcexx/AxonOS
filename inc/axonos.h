#pragma once

#include <stdint.h>

#define OS_NAME "AxonOS"
#define OS_VERSION "4.0.1"
#define OS_AUTHORS "Axon Team"

/* Syscall globals (defined in syscall64/syscall.c). */
extern uint64_t syscall_kernel_rsp0;
extern uint64_t syscall_user_rsp_saved;
extern uint64_t syscall_user_return_rip;
extern uint64_t syscall_user_return_rax;
void syscall_set_user_brk(uintptr_t base);

/* Try to handle user page fault by growing heap. Returns 1 if fault was handled. */
int fault_try_grow_user_heap(uint64_t cr2);
/* Demand-fill + zero one 2MiB page for a large MAP_ANONYMOUS lazy mmap. */
int fault_try_mmap_lazy_anon(uint64_t cr2);
/* Demand-materialize a non-present page covered by a user VMA if access is allowed. */
int fault_try_user_vma_nonpresent(uint64_t cr2, uint64_t err);
int syscall_try_handle_uaccess_fault(uint64_t fault_addr, uint64_t *resume_rip_out);

/* Populate default sysfs tree and /etc (called from SYS_mount when userspace mounts sysfs). */
void kernel_sysfs_populate_default(void);

/* Write /etc/resolv.conf from current kernel net config (DHCP DNS or gateway). */
void syscall_net_ensure_resolv(void);

/* SYS_resolve (1000): resolve hostname via DNS. See inc/syscall.h. */
