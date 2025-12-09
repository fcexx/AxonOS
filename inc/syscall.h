#pragma once

#include <stdint.h>
#include "idt.h"

/* Minimal syscall numbers (Linux-compatible where convenient) */
#define SYS_read    0
#define SYS_write   1
#define SYS_open    2
#define SYS_close   3
#define SYS_exit    60
#define SYS_execve  59

/* initialize syscall subsystem (register handler) */
void syscall_init(void);

/* ISR-compatible handler (called by IDT dispatcher) */
void isr_syscall(cpu_registers_t* regs);


