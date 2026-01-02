.global lgdt_load
.global ltr_load
.global enter_user_mode_asm

lgdt_load:
        lgdt (%rdi)
        ret

ltr_load:
        mov %di, %ax
        ltr %ax
        ret

// void enter_user_mode_asm(uint64_t entry, uint64_t user_stack, uint16_t user_ds, uint16_t user_cs)
enter_user_mode_asm:
        // rdi=entry, rsi=user_stack, rdx=user_ds, rcx=user_cs
        // force RPL=3 on selectors
        or $3, %rdx
        or $3, %rcx

        // Prepare RFLAGS with IF=1 and build IRET frame
        pushfq
        pop %rax
        or $0x200, %rax                  // IF=1 in user image
        cli
        // Preserve iret-frame values into callee-saved registers so they survive the call.
        // rdi=entry, rsi=user_stack, rdx=user_ds, rcx=user_cs, rax=rflags
        mov %rdi, %r12
        mov %rsi, %r13
        mov %rdx, %r14
        mov %rcx, %r15
        mov %rax, %rbx
        call enter_user_pre_iret

        // Build ONE IRET frame using preserved callee-saved regs.
        // Mask selectors to 16-bit and set RPL=3 to avoid upper-bit garbage.
        mov %r14, %rax
        and $0xffff, %rax
        or $3, %rax
        pushq %rax                           // SS (user_ds|3)

        pushq %r13                           // RSP (user stack) - full 64-bit

        pushq %rbx                           // RFLAGS (with IF)

        mov %r15, %rax
        and $0xffff, %rax
        or $3, %rax
        pushq %rax                           // CS (user_cs|3)

        pushq %r12                           // RIP (entry)

        // Now call post-iret diagnostic with the words we just pushed.
        // Stack layout at %rsp: [RIP][CS][RFLAGS][RSP][SS]
        movq %rsp, %r9
        movq 32(%r9), %rdi     // SS
        movq 24(%r9), %rsi     // RSP
        movq 16(%r9), %rdx     // RFLAGS
        movq 8(%r9), %rcx      // CS
        movq 0(%r9), %r8       // RIP
        call enter_user_post_iret

        /* Userspace entry registers:
           On Linux x86_64, %rdx is used to pass rtld_fini from the dynamic loader.
           For static executables (our current target), it must be 0. If we leave
           kernel garbage (or our user_ds selector) in %rdx, libc may later call it
           during exit and jump into low memory (e.g. RIP=0x3d5). */
        xor %rdx, %rdx

        cld
        iretq
// ensure newline at end of file