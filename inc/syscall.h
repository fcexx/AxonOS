#pragma once

#include <stdint.h>
#include <idt.h>

/* Minimal syscall numbers (Linux-compatible where convenient) */
#define SYS_read    0
#define SYS_write   1
#define SYS_open    2
#define SYS_close   3
#define SYS_stat    4
#define SYS_fstat   5
#define SYS_lstat   6
#define SYS_lseek   8
#define SYS_writev  20
#define SYS_getrandom 318
#define SYS_clock_gettime 228
#define SYS_uname   63
#define SYS_getcwd  79
#define SYS_chdir   80
#define SYS_readlink 89
#define SYS_set_tid_address 218
#define SYS_prlimit64 302
#define SYS_set_robust_list 273
#define SYS_rseq 334
#define SYS_futex 202
#define SYS_rt_sigaction 13
#define SYS_rt_sigprocmask 14
#define SYS_ioctl   16
#define SYS_getdents64 217
#define SYS_getdents 78
#define SYS_getpid  39
#define SYS_getppid 110
#define SYS_getuid  102
#define SYS_getgid  104
#define SYS_geteuid 107
#define SYS_getegid 108
#define SYS_setsid  112
#define SYS_getpgrp 111
#define SYS_setpgid 109
#define SYS_gettid  186
#define SYS_mmap    9
#define SYS_munmap  11
#define SYS_brk     12
#define SYS_poll    7
#define SYS_mprotect 10
#define SYS_arch_prctl 158
#define SYS_exit    60
#define SYS_execve  59
#define SYS_vfork   58
#define SYS_fork    57
#define SYS_clone   56
#define SYS_wait4   61
#define SYS_exit_group 231
#define SYS_openat  257
#define SYS_newfstatat 262
#define SYS_tgkill  234
#define SYS_sendfile 40

/* initialize syscall subsystem (register handler) */
void syscall_init(void);

/* ISR-compatible handler (called by IDT dispatcher) */
void isr_syscall(cpu_registers_t* regs);

/* Common syscall dispatcher used by both int0x80 and SYSCALL entry. */
uint64_t syscall_do(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6);

/* Control flag and helper for syscall_entry64. */
extern uint64_t syscall_exit_to_shell_flag;
__attribute__((noreturn)) void syscall_return_to_shell(void);


