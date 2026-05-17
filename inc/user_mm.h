#pragma once

#include <stdint.h>
#include <stddef.h>

/* Linux-compatible errno values used by user memory syscalls. */
#ifndef USER_MM_EINVAL
#define USER_MM_EINVAL  22
#define USER_MM_ENOMEM  12
#define USER_MM_EFAULT  14
#define USER_MM_ENOSYS   38
#define USER_MM_EBADF    9
#define USER_MM_ENODEV  19
#define USER_MM_ENOSPC  28
#endif

/* Syscall return encoding: negative int64_t errno. */
static inline uint64_t user_mm_ret_err(int e) {
    return (uint64_t)(-(int64_t)e);
}

static inline uintptr_t user_mm_align_up(uintptr_t v, uintptr_t a) {
    return (v + (a - 1)) & ~(a - 1);
}

/* Single anonymous/file mmap must fit below this VA (matches exec.h USER_STACK_TOP). */
#define USER_MM_SINGLE_MAP_CAP 0x10000000ULL

static inline int user_mm_len_exceeds_cap(uint64_t len) {
    return len >= USER_MM_SINGLE_MAP_CAP;
}

/* [addr, addr+len) ⊆ [0, top_exclusive)? */
int user_mm_range_fits(uintptr_t addr, uint64_t len, uintptr_t top_exclusive);
