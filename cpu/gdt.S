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

        // IRET frame: SS, RSP, RFLAGS, CS, RIP
        pushq %rdx                           // SS (user_ds|3)
        pushq %rsi                           // RSP (user stack)
        pushq %rax                           // RFLAGS (with IF)
        pushq %rcx                           // CS (user_cs|3)
        pushq %rdi                           // RIP (entry)

        // use preserved callee-saved regs to push the iret frame values
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
        movq %rsp, %r9
        movq (%r9), %rdi      // SS
        movq 8(%r9), %rsi     // RSP
        movq 16(%r9), %rdx    // RFLAGS
        movq 24(%r9), %rcx    // CS
        movq 32(%r9), %r8     // RIP
        call enter_user_post_iret

        cld
        iretq
// ensure newline at end of file