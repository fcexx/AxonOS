#ifndef GDT_H
#define GDT_H

#include <stdint.h>

// gdt is an important shi

void gdt_init();
void tss_set_rsp0(uint64_t rsp0);
// when we returning to ring3 we need to switch to user mode
void enter_user_mode(uint64_t user_entry, uint64_t user_stack_top);
// set IST stack pointer (idx 1..7)
void tss_set_ist(int idx, uint64_t rsp_top);

// expose user segment selectors (ts always has been in asm)
extern uint16_t KERNEL_CS;  // kernel code selector
extern uint16_t KERNEL_DS;  // Kernel data selector
extern uint16_t USER_CS;    // user code selector (Ring 3)
extern uint16_t USER_DS;    // user data selector (Ring3)

/* Diagnostic hook called from assembly trampoline just before iret frame is pushed.
   Parameters: rdi=entry, rsi=user_stack, rdx=user_ds, rcx=user_cs, r8=rflags */
void enter_user_pre_iret(uint64_t entry, uint64_t user_stack, uint16_t user_ds, uint16_t user_cs, uint64_t rflags);
/* Diagnostic hook called after iret-frame is pushed but before iretq.
   Parameters: rdi=ss, rsi=rsp, rdx=rflags, rcx=cs, r8=rip */
void enter_user_post_iret(uint64_t ss, uint64_t user_rsp, uint64_t rflags, uint16_t user_cs, uint64_t rip);

#endif