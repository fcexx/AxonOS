.global syscall_entry64

.extern syscall_do
.extern syscall_kernel_rsp0
.extern syscall_user_rsp_saved
.extern syscall_user_saved_rbx
.extern syscall_user_saved_rbp
.extern syscall_user_saved_r12
.extern syscall_user_saved_r13
.extern syscall_user_saved_r14
.extern syscall_user_saved_r15
.extern syscall_user_saved_rdi
.extern syscall_user_saved_rsi
.extern syscall_user_saved_rdx
.extern syscall_user_saved_r8
.extern syscall_user_saved_r9
.extern syscall_user_saved_r10
.extern syscall_user_saved_rcx
.extern syscall_user_saved_r11
.extern syscall_exit_to_shell_flag
.extern syscall_return_to_shell
.extern syscall_exec_trampoline_active
.extern syscall_snapshot_user_regs

// x86_64 SYSCALL entry point
// Assumptions/constraints (current AxonOS design):
// - Kernel and user share one address space (identity-mapped below 4GiB)
// - We return to ring3 via IRETQ (not SYSRET), so we can use existing USER_CS/USER_DS
// - syscall_kernel_rsp0 is maintained by tss_set_rsp0() before entering user mode
//
// Syscall ABI:
//   rax = nr
//   rdi,rsi,rdx,r10,r8,r9 = args 1..6
//   rcx,r11 are clobbered by the SYSCALL instruction (rcx=return RIP, r11=return RFLAGS)
//
// We preserve all GPRs and only change rax (return value), rcx/r11 are restored and used for iret frame
//
// NOTE: This is single-core / non-reentrant with respect to syscall_user_rsp_saved
//       Good enough for current AxonOS; we can make it per-thread/per-cpu later
syscall_entry64:
    cld
    // Save user RIP (return address) for SYSCALL path (rcx contains return RIP)
    movq    %rcx, syscall_user_return_rip(%rip)
    // Save user RSP and switch to kernel syscall stack (only if set).
    movq    %rsp, syscall_user_rsp_saved(%rip)
    // Check syscall_kernel_rsp0 without clobbering registers and switch if non-zero.
    cmpq    $0, syscall_kernel_rsp0(%rip)
    je      .no_switch_syscall_stack
    movq    syscall_kernel_rsp0(%rip), %rsp
.no_switch_syscall_stack:

    // Store this syscall's user RSP on the kernel stack too.
    // Using a global is racy when multiple user threads make syscalls (vfork/exec),
    // but storing it on each thread's kernel stack keeps it per-thread.
    pushq   syscall_user_rsp_saved(%rip)

    // Save registers (order matches our offset math below).
    pushq   %rax
    pushq   %rcx
    pushq   %rdx
    pushq   %rbx
    pushq   %rbp
    pushq   %rsi
    pushq   %rdi
    pushq   %r8
    pushq   %r9
    pushq   %r10
    pushq   %r11
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    // Capture callee-saved user registers from the saved frame (needed for vfork).
    // Frame base: rsp points to saved r15; offsets match the comment below.
    movq    88(%rsp), %rax      // rbx
    movq    %rax, syscall_user_saved_rbx(%rip)
    movq    80(%rsp), %rax      // rbp
    movq    %rax, syscall_user_saved_rbp(%rip)
    movq    24(%rsp), %rax      // r12
    movq    %rax, syscall_user_saved_r12(%rip)
    movq    16(%rsp), %rax      // r13
    movq    %rax, syscall_user_saved_r13(%rip)
    movq    8(%rsp),  %rax      // r14
    movq    %rax, syscall_user_saved_r14(%rip)
    movq    0(%rsp),  %rax      // r15
    movq    %rax, syscall_user_saved_r15(%rip)

    // Capture caller-saved regs as well (to emulate a real SYSCALL return in vfork child).
    movq    64(%rsp), %rax      // rdi
    movq    %rax, syscall_user_saved_rdi(%rip)
    movq    72(%rsp), %rax      // rsi
    movq    %rax, syscall_user_saved_rsi(%rip)
    movq    96(%rsp), %rax      // rdx
    movq    %rax, syscall_user_saved_rdx(%rip)
    movq    56(%rsp), %rax      // r8
    movq    %rax, syscall_user_saved_r8(%rip)
    movq    48(%rsp), %rax      // r9
    movq    %rax, syscall_user_saved_r9(%rip)
    movq    40(%rsp), %rax      // r10
    movq    %rax, syscall_user_saved_r10(%rip)
    movq    104(%rsp), %rax     // rcx (return RIP)
    movq    %rax, syscall_user_saved_rcx(%rip)
    movq    32(%rsp), %rax      // r11 (saved RFLAGS from SYSCALL)
    movq    %rax, syscall_user_saved_r11(%rip)

    // Snapshot saved user regs into current thread (per-thread, avoids globals).
    // Pass pointer to saved frame (rsp points to r15).
    movq    %rsp, %rdi
    call    syscall_snapshot_user_regs

    // Stack layout at this point (rsp points to r15):
    //  0   r15
    //  8   r14
    // 16   r13
    // 24   r12
    // 32   r11 (user RFLAGS)
    // 40   r10 (arg4)
    // 48   r9  (arg5)
    // 56   r8  (arg6)
    // 64   rdi (arg1)
    // 72   rsi (arg2)
    // 80   rbp
    // 88   rbx
    // 96   rdx (arg3)
    // 104  rcx (return RIP)
    // 112  rax (syscall nr)

    // Setup arguments for syscall_do(num, a1, a2, a3, a4, a5, a6)
    movq    112(%rsp), %rdi     // num
    movq    64(%rsp),  %rsi     // a1
    movq    72(%rsp),  %rdx     // a2
    movq    96(%rsp),  %rcx     // a3
    movq    40(%rsp),  %r8      // a4
    /* Linux x86_64 syscall ABI: args 1..6 = rdi,rsi,rdx,r10,r8,r9.
       Here: a4 is saved r10. a5 must be saved r8, a6 must be saved r9. */
    movq    56(%rsp),  %r9      // a5 = user r8
    pushq   48(%rsp)            // a6 = user r9 (7th arg on stack)
    call    syscall_do
    addq    $8, %rsp


    // If userspace requested exit(), do not return back to ring3.
    // Jump back to kernel shell loop instead.
    movq    syscall_exit_to_shell_flag(%rip), %r12
    testq   %r12, %r12
    jz      .ret_to_user
    // reset stack to top and tail-call kernel helper (noreturn)
    movq    syscall_kernel_rsp0(%rip), %rsp
    call    syscall_return_to_shell

.ret_to_user:

    // Store return value into saved rax slot so final pop restores it.
    // If a trampoline was applied by kernel, assembly should not overwrite the patched
    // saved-rax slot. Check global flag syscall_exec_trampoline_active.
    movq    syscall_exec_trampoline_active(%rip), %rdx
    testq   %rdx, %rdx
    jz      .L_do_write_rax
    // clear flag and skip writing rax (preserve patched slot)
    movq    $0, syscall_exec_trampoline_active(%rip)
    jmp     .L_skip_write_rax
.L_do_write_rax:
    movq    %rax, 112(%rsp)
.L_skip_write_rax:

    // Restore registers.
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %r11
    popq    %r10
    popq    %r9
    popq    %r8
    popq    %rdi
    popq    %rsi
    popq    %rbp
    popq    %rbx
    popq    %rdx
    popq    %rcx
    popq    %rax

    // Return to user with IRETQ using the saved return RIP (rcx), flags (r11) and user RSP.
    // USER_DS = 0x23, USER_CS = 0x1B (see cpu/gdt.c)
    pushq   $0x23
    // push saved user RSP from our per-syscall stack slot (just above this SS)
    pushq   8(%rsp)
    /* Ensure user returns with interrupts enabled (IF=1).
       Some implementations of SYSCALL may present masked RFLAGS in r11
       (per MSR_FMASK), and restoring them verbatim would leave user mode
       with IF=0, effectively "disabling interrupts" for the user process. */
    orq     $0x200, %r11
    pushq   %r11
    pushq   $0x1B
    pushq   %rcx
    iretq


