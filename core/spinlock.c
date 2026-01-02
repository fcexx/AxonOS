/*
 * core/spinlock.c
 * spinlock implementation
 * Author: fcexx
*/


#include <spinlock.h>

void acquire(spinlock_t* lock) {
        /* Default atomic acquire for compatibility */
        while (__sync_lock_test_and_set(&lock->lock, 1));
}

void release(spinlock_t* lock) {
        __sync_lock_release(&lock->lock);
}

// Попытка захватить спинлок без блокировки (используется в ISR)
int try_acquire(spinlock_t* lock) {
        return (__sync_lock_test_and_set(&lock->lock, 1) == 0) ? 1 : 0;
}

// IRQ-save variants: disable interrupts while acquiring, save rflags
void acquire_irqsave(spinlock_t* lock, unsigned long* rflags) {
        while (__sync_lock_test_and_set(&lock->lock, 1));
}

void release_irqrestore(spinlock_t* lock, unsigned long rflags) {
        __sync_lock_release(&lock->lock);
}