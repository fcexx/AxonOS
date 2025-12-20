#pragma once

#include <stdint.h>

#define OS_NAME "AxonOS"
#define OS_VERSION "2.2"
#define OS_AUTHORS "AxonOS Team"

uint64_t syscall_kernel_rsp0 = 0;
uint64_t syscall_user_return_rip = 0;