#ifndef CONTEXT_H
#define CONTEXT_H
#include <stdint.h>

typedef struct context {
        uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
        uint64_t rsi, rdi, rbp, rdx, rcx, rbx, rax;
        uint64_t rip, rsp;
        uint64_t rflags;
} context_t;

#ifdef __cplusplus
extern "C" {
#endif

void context_switch(context_t *old_ctx, context_t *new_ctx);
/* Save old, then unlock sched_lock (IF stays off); caller must restore_irqflags(irq_f) after return. */
void context_switch_with_prev(context_t *old_ctx, context_t *new_ctx, void *prev_thread);

#ifdef __cplusplus
}
#endif

#endif // CONTEXT_H 