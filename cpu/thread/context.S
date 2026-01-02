.global context_switch
// void context_switch(context_t *old context_t *new)
// old: rdi, new: rsi
context_switch:
        // saving only callee-saved registers
        movq %rbx, 0x68(%rdi)
        movq %rbp, 0x50(%rdi)
        movq %r12, 0x18(%rdi)
        movq %r13, 0x10(%rdi)
        movq %r14, 0x08(%rdi)
        movq %r15, 0x00(%rdi)
        movq %rsp, 0x80(%rdi)
        pushfq
        popq %rax
        /* Ensure IF (bit 9) is set in saved RFLAGS so resumed threads have interrupts enabled */
        orq $0x200, %rax
        movq %rax, 0x88(%rdi)

        // restoring!!
        movq 0x68(%rsi), %rbx
        movq 0x50(%rsi), %rbp
        movq 0x18(%rsi), %r12
        movq 0x10(%rsi), %r13
        movq 0x08(%rsi), %r14
        movq 0x00(%rsi), %r15
        movq 0x80(%rsi), %rsp
        pushq 0x88(%rsi)
        popfq
        // my favorite 'ret'
        ret

/* Restore volatile (caller-saved) registers from a context_t pointer.
   Prototype: void restore_volatile_regs(context_t *ctx)
   This will load rdx,rcx,rax,r8,r9,r10,r11 from the memory image pointed by ctx.
   IMPORTANT: it does NOT touch rdi/rsi so callers can set up function arguments
   after restore (enter_user_mode will be called with correct args). */
.global restore_volatile_regs
restore_volatile_regs:
        // rdi == ctx pointer
        // load values via rax temp and push in order so pops set registers correctly
        movq    32(%rdi), %rax      // r11
        pushq   %rax
        movq    40(%rdi), %rax      // r10
        pushq   %rax
        movq    48(%rdi), %rax      // r9
        pushq   %rax
        movq    56(%rdi), %rax      // r8
        pushq   %rax
        movq    112(%rdi), %rax     // rax
        pushq   %rax
        movq    96(%rdi), %rax      // rcx
        pushq   %rax
        movq    88(%rdi), %rax      // rdx
        pushq   %rax

        // Now pop into registers in reverse order
        popq    %rdx
        popq    %rcx
        popq    %rax
        popq    %r8
        popq    %r9
        popq    %r10
        popq    %r11
        ret