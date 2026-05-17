#pragma once

#include <stdint.h>

void syscall_set_user_brk(uintptr_t base);
int fault_try_grow_user_heap(uint64_t cr2);
uint64_t user_syscall_brk(uint64_t req);
