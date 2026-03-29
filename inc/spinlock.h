#ifndef SPINLOCK_H
#define SPINLOCK_H

#include <stdint.h>

typedef struct {
        volatile uint32_t lock;
} spinlock_t;

// WARNING: ATOMIC
void acquire(spinlock_t* lock);
void release(spinlock_t* lock);
// Try acquire without blocking (for use in ISR)
int try_acquire(spinlock_t* lock);
// IRQ-save variants: disable interrupts while holding the lock; flags saved to *rflags
void acquire_irqsave(spinlock_t* lock, unsigned long* rflags);
void release_irqrestore(spinlock_t* lock, unsigned long rflags);
/* Restore IF only (no lock). Use after context_switch_with_prev returns — lock already released. */
void restore_irqflags(unsigned long rflags);
// Попытка захватить спинлок без ожидания: возвращает 1 при успехе, 0 при неудаче
int try_acquire(spinlock_t* lock);

#endif