
/*
 * syscall64/futex/futex.c
 * Minimal futex implementation: support FUTEX_WAIT and FUTEX_WAKE (private).
 * This is intentionally small: it provides basic wait/wake semantics for
 * userland pthread/mutex usage. Not feature-complete (no robust lists,
 * no FUTEX_WAIT_BITSET timeout semantics).
 * Author: fcexx
*/

#include <axonos.h>
#include <stdint.h>
#include <stddef.h>
#include <thread.h>
#include <heap.h>
#include <spinlock.h>
#include <mmio.h>
#include <syscall.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_PRIVATE_FLAG 128

/* Minimal errno set (same values as used by syscall dispatcher) */
#define EPERM   1
#define ENOENT  2
#define EFAULT  14
#define EINVAL  22
#define ENOMEM  12
#define EAGAIN  11
#define ENOSYS  38

/* Simple hash table of wait queues keyed by user address. */
#define FUTEX_BUCKETS 256

typedef struct futex_waiter {
    int tid;
    struct futex_waiter *next;
} futex_waiter_t;

typedef struct futex_node {
    uintptr_t key;
    futex_waiter_t *waiters;
    struct futex_node *next;
} futex_node_t;

static futex_node_t *futex_table[FUTEX_BUCKETS];
static spinlock_t futex_lock = { 0 };

static inline int futex_hash(uintptr_t key) {
    return (int)((key >> 3) & (FUTEX_BUCKETS - 1));
}

static futex_node_t *futex_find_node(uintptr_t key, int create) {
    int h = futex_hash(key);
    futex_node_t *n = futex_table[h];
    while (n) {
        if (n->key == key) return n;
        n = n->next;
    }
    if (!create) return NULL;
    n = (futex_node_t*)kmalloc(sizeof(futex_node_t));
    if (!n) return NULL;
    memset(n, 0, sizeof(*n));
    n->key = key;
    n->next = futex_table[h];
    futex_table[h] = n;
    return n;
}

/* Copy 32-bit value from user; return 0 on success, -EFAULT on error. */
static int read_u32_user(uint32_t *out, uintptr_t uaddr) {
    if (!out) return -EINVAL;
    if (uaddr + sizeof(uint32_t) > (uintptr_t)MMIO_IDENTITY_LIMIT) return -EFAULT;
    /* assume identity mapping and accessible */
    *out = *(volatile uint32_t*)(uintptr_t)uaddr;
    return 0;
}

/* Minimal futex syscall backend.
   Returns 0..n on success or negative errno on failure. */
int futex_syscall(uintptr_t uaddr, int op, int val, const void *timeout, uintptr_t uaddr2, int val3) {
    (void)uaddr2; (void)val3; (void)timeout;
    int private = !!(op & FUTEX_PRIVATE_FLAG);
    int cmd = op & (~FUTEX_PRIVATE_FLAG);
    thread_t *cur = thread_get_current_user();
    if (!cur) cur = thread_current();
    if (!cur) return -EPERM;

    if (cmd == FUTEX_WAIT) {
        uint32_t curv = 0;
        if (read_u32_user(&curv, uaddr) < 0) return -EFAULT;
        if ((int)curv != val) return -EAGAIN; /* value changed, do not block */

        /* enqueue */
        acquire(&futex_lock);
        futex_node_t *node = futex_find_node(uaddr, 1);
        if (!node) { release(&futex_lock); return -ENOMEM; }
        futex_waiter_t *w = (futex_waiter_t*)kmalloc(sizeof(futex_waiter_t));
        if (!w) { release(&futex_lock); return -ENOMEM; }
        w->tid = (int)(cur->tid ? cur->tid : 1);
        w->next = node->waiters;
        node->waiters = w;
        release(&futex_lock);

        /* block current thread until woken */
        thread_block((int)cur->tid);
        thread_yield();

        /* when woken, return 0 */
        return 0;
    } else if (cmd == FUTEX_WAKE) {
        int to_wake = val;
        if (to_wake <= 0) return 0;
        int woke = 0;
        acquire(&futex_lock);
        futex_node_t *node = futex_find_node(uaddr, 0);
        if (node && node->waiters) {
            futex_waiter_t *w = node->waiters;
            futex_waiter_t *prev = NULL;
            while (w && to_wake > 0) {
                /* pop from head for simplicity */
                futex_waiter_t *next = w->next;
                /* remove w from list */
                if (prev) prev->next = next;
                else node->waiters = next;
                /* wake thread */
                thread_unblock(w->tid);
                kfree(w);
                woke++;
                to_wake--;
                /* continue from head */
                w = node->waiters;
            }
        }
        release(&futex_lock);
        return woke;
    } else {
        return -ENOSYS;
    }
}


