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

// IRQ-save variants: save RFLAGS, CLI, then take lock. Prevents deadlock when
// the same CPU takes this lock in thread context and timer IRQ calls code
// that tries to take it again (e.g. thread_schedule from pit_handler).
void acquire_irqsave(spinlock_t* lock, unsigned long* rflags) {
        unsigned long f;
        asm volatile(
                "pushfq\n\t"
                "pop %0\n\t"
                "cli"
                : "=r"(f)
                :
                : "memory");
        *rflags = f;
        while (__sync_lock_test_and_set(&lock->lock, 1))
                asm volatile("pause" ::: "memory");
}

void release_irqrestore(spinlock_t* lock, unsigned long rflags) {
        __sync_lock_release(&lock->lock);
        asm volatile("push %0; popfq" :: "r"(rflags) : "memory", "cc");
}

void restore_irqflags(unsigned long rflags) {
        asm volatile("push %0; popfq" :: "r"(rflags) : "memory", "cc");
}