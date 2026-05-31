#include <user_vma.h>
#include <user_as.h>
#include <user_mm.h>
#include <exec.h>
#include <mm.h>
#include <mmio.h>
#include <paging.h>
#include <spinlock.h>
#include <string.h>
#include <thread.h>

static user_vma_t g_user_vmas[USER_VMA_MAX];
static spinlock_t g_user_vma_lock;

static user_vma_t *user_vma_find_containing_nolock(uint64_t tid, uintptr_t va) {
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid) continue;
        uintptr_t a = g_user_vmas[i].addr;
        uintptr_t e = a + g_user_vmas[i].len;
        if (va >= a && va < e) return &g_user_vmas[i];
    }
    return NULL;
}

static int user_vma_add_nolock(uint64_t tid, uintptr_t addr, size_t len, int prot, int kind) {
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid) continue;
        if (g_user_vmas[i].addr == addr && g_user_vmas[i].len == len && g_user_vmas[i].kind == kind) {
            g_user_vmas[i].prot = prot;
            return 0;
        }
    }
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) {
            g_user_vmas[i].used = 1;
            g_user_vmas[i].tid = tid;
            g_user_vmas[i].addr = addr;
            g_user_vmas[i].len = len;
            g_user_vmas[i].prot = prot;
            g_user_vmas[i].kind = kind;
            return 0;
        }
    }
    return -1;
}

static int user_vma_split_at_nolock(uint64_t tid, uintptr_t split_va) {
    user_vma_t *v = user_vma_find_containing_nolock(tid, split_va);
    if (!v) return 0;
    if (split_va == v->addr || split_va >= v->addr + v->len) return 0;
    size_t left_len = (size_t)(split_va - v->addr);
    size_t right_len = v->len - left_len;
    uintptr_t right_addr = split_va;
    int prot = v->prot;
    int kind = v->kind;
    if (user_vma_add_nolock(tid, right_addr, right_len, prot, kind) != 0) return -1;
    v->len = left_len;
    return 0;
}

static int user_vma_tid_matches_runner_mm_nolock(thread_t *runner, uint64_t record_tid) {
    if (!runner)
        return record_tid == 1u;
    if (!runner->mm)
        return (uint64_t)(runner->tid ? runner->tid : 1) == record_tid;
    int n = thread_get_count();
    for (int j = 0; j < n; j++) {
        thread_t *u = thread_get_by_index(j);
        if (!u || u->ring != 3) continue;
        if (u->mm != runner->mm) continue;
        if ((uint64_t)(u->tid ? u->tid : 1) == record_tid)
            return 1;
    }
    return 0;
}

int user_vma_add(uint64_t tid, uintptr_t addr, size_t len, int prot, int kind) {
    unsigned long fl = 0;
    int rc;
    acquire_irqsave(&g_user_vma_lock, &fl);
    rc = user_vma_add_nolock(tid, addr, len, prot, kind);
    release_irqrestore(&g_user_vma_lock, fl);
    return rc;
}

void user_vma_unmap_range(uint64_t tid, uintptr_t addr, size_t len) {
    uintptr_t end = addr + len;
    unsigned long fl = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    (void)user_vma_split_at_nolock(tid, addr);
    (void)user_vma_split_at_nolock(tid, end);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid) continue;
        uintptr_t a = g_user_vmas[i].addr;
        uintptr_t e = a + g_user_vmas[i].len;
        if (e <= addr || a >= end) continue;
        g_user_vmas[i].used = 0;
    }
    release_irqrestore(&g_user_vma_lock, fl);
}

int user_vma_set_prot(uint64_t tid, uintptr_t addr, size_t len, int prot) {
    unsigned long fl = 0;
    int rc = 0;
    uintptr_t end = addr + len;
    acquire_irqsave(&g_user_vma_lock, &fl);
    if (user_vma_split_at_nolock(tid, addr) != 0) rc = -1;
    else if (user_vma_split_at_nolock(tid, end) != 0) rc = -1;
    else {
        for (int i = 0; i < USER_VMA_MAX; i++) {
            if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid) continue;
            uintptr_t a = g_user_vmas[i].addr;
            uintptr_t e = a + g_user_vmas[i].len;
            if (e <= addr || a >= end) continue;
            g_user_vmas[i].prot = prot;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return rc;
}

int user_vma_is_fully_mapped(uint64_t tid, uintptr_t addr, size_t len) {
    uintptr_t end = addr + len;
    uintptr_t cur = addr;
    unsigned long fl = 0;
    int ok = 1;
    acquire_irqsave(&g_user_vma_lock, &fl);
    while (cur < end) {
        user_vma_t *v = user_vma_find_containing_nolock(tid, cur);
        if (!v) { ok = 0; break; }
        uintptr_t ve = v->addr + v->len;
        if (ve <= cur) { ok = 0; break; }
        cur = ve;
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return ok;
}

uintptr_t user_vma_max_mmap_like_end_nolock(uint64_t tid) {
    uintptr_t mx = 0;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != tid) continue;
        int k = g_user_vmas[i].kind;
        if (k != USER_VMA_KIND_MMAP && k != USER_VMA_KIND_MMAP_LAZY) continue;
        uintptr_t e = g_user_vmas[i].addr + g_user_vmas[i].len;
        if (e > mx) mx = e;
    }
    return mx;
}

uintptr_t user_vma_max_mmap_like_end(uint64_t tid) {
    unsigned long fl = 0;
    uintptr_t mx;
    acquire_irqsave(&g_user_vma_lock, &fl);
    mx = user_vma_max_mmap_like_end_nolock(tid);
    release_irqrestore(&g_user_vma_lock, fl);
    return mx;
}

uintptr_t user_vma_max_mmap_like_end_for_mm_nolock(thread_t *runner) {
    uintptr_t mx = 0;
    if (!runner) return 0;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) continue;
        int k = g_user_vmas[i].kind;
        if (k != USER_VMA_KIND_MMAP && k != USER_VMA_KIND_MMAP_LAZY) continue;
        if (!user_vma_tid_matches_runner_mm_nolock(runner, (uint64_t)g_user_vmas[i].tid))
            continue;
        uintptr_t e = g_user_vmas[i].addr + g_user_vmas[i].len;
        if (e > mx) mx = e;
    }
    return mx;
}

uintptr_t user_vma_max_mmap_like_end_for_mm(thread_t *runner) {
    unsigned long fl = 0;
    uintptr_t mx;
    acquire_irqsave(&g_user_vma_lock, &fl);
    mx = user_vma_max_mmap_like_end_for_mm_nolock(runner);
    release_irqrestore(&g_user_vma_lock, fl);
    return mx;
}

uintptr_t user_vma_min_mmap_like_for_thread_nolock(thread_t *tcur, uintptr_t brk_base) {
    uintptr_t best = (uintptr_t)-1;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) continue;
        int k = g_user_vmas[i].kind;
        if (k != USER_VMA_KIND_MMAP && k != USER_VMA_KIND_MMAP_LAZY) continue;
        if (!user_vma_tid_matches_runner_mm_nolock(tcur, (uint64_t)g_user_vmas[i].tid)) continue;
        uintptr_t a = g_user_vmas[i].addr;
        if (a < 0x200000u) continue;
        if (a >= brk_base && a < best) best = a;
    }
    return best;
}

uintptr_t user_vma_min_mmap_like_for_thread(thread_t *tcur, uintptr_t brk_base) {
    unsigned long fl = 0;
    uintptr_t v;
    acquire_irqsave(&g_user_vma_lock, &fl);
    v = user_vma_min_mmap_like_for_thread_nolock(tcur, brk_base);
    release_irqrestore(&g_user_vma_lock, fl);
    return v;
}

int user_vma_mmap_range_overlaps_nolock(thread_t *runner, uintptr_t addr, size_t len) {
    if (len == 0 || !runner) return 0;
    uint64_t a0 = (uint64_t)addr;
    uint64_t a1 = a0 + (uint64_t)len;
    if (a1 < a0) return 1;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) continue;
        int k = g_user_vmas[i].kind;
        if (k != USER_VMA_KIND_MMAP && k != USER_VMA_KIND_MMAP_LAZY) continue;
        if (!user_vma_tid_matches_runner_mm_nolock(runner, (uint64_t)g_user_vmas[i].tid))
            continue;
        uint64_t b0 = (uint64_t)g_user_vmas[i].addr;
        uint64_t b1 = b0 + (uint64_t)g_user_vmas[i].len;
        if (b1 < b0) continue;
        if (!(a1 <= b0 || a0 >= b1)) return 1;
    }
    return 0;
}

int user_vma_mmap_range_overlaps(thread_t *runner, uintptr_t addr, size_t len) {
    unsigned long fl = 0;
    int rc;
    acquire_irqsave(&g_user_vma_lock, &fl);
    rc = user_vma_mmap_range_overlaps_nolock(runner, addr, len);
    release_irqrestore(&g_user_vma_lock, fl);
    return rc;
}

void user_vma_remove_all_for_tid(uint64_t tid) {
    unsigned long fl = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (g_user_vmas[i].used && g_user_vmas[i].tid == tid) g_user_vmas[i].used = 0;
    }
    release_irqrestore(&g_user_vma_lock, fl);
}

int user_vma_fork_privatize_mapped(mm_t *child_mm, uint64_t from_tid) {
    if (!child_mm) return -1;
    /* Linux COW: only materialize modest anon mmap regions at fork. Copying multi-MiB
       test mappings (axon-harness mmap-large) exhausts kernel heap and breaks fork. */
    enum { FORK_VMA_PRIV_PER_MAX = 256u * 1024u };
    unsigned long fl = 0;
    int rc = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != from_tid) continue;
        if (g_user_vmas[i].kind == USER_VMA_KIND_MMAP_LAZY) continue;
        if (g_user_vmas[i].len > FORK_VMA_PRIV_PER_MAX) continue;
        uintptr_t a = g_user_vmas[i].addr;
        uintptr_t e = a + g_user_vmas[i].len;
        if (e <= a || e > (uintptr_t)MMIO_IDENTITY_LIMIT) {
            rc = -1;
            break;
        }
        if (mm_cow_private_writable(child_mm, (uint64_t)a, (uint64_t)e) != 0) {
            rc = -1;
            break;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return rc;
}

int user_vma_clone_for_tid(uint64_t from_tid, uint64_t to_tid) {
    unsigned long fl = 0;
    int rc = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used || g_user_vmas[i].tid != from_tid) continue;
        if (user_vma_add_nolock(to_tid, g_user_vmas[i].addr, g_user_vmas[i].len,
                g_user_vmas[i].prot, g_user_vmas[i].kind) != 0) {
            for (int j = 0; j < USER_VMA_MAX; j++) {
                if (g_user_vmas[j].used && g_user_vmas[j].tid == to_tid) g_user_vmas[j].used = 0;
            }
            rc = -1;
            break;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    return rc;
}

int user_vma_fault_lazy_anon(uint64_t cr2) {
    if (cr2 < 0x200000ULL || cr2 >= (uint64_t)MMIO_IDENTITY_LIMIT)
        return 0;
    thread_t *t = thread_current();
    if (!t || t->ring != 3) {
        t = thread_get_current_user();
        if (!t) return 0;
    }
    unsigned long fl = 0;
    uintptr_t va2m = (uintptr_t)(cr2 & ~(uint64_t)(PAGE_SIZE_2M - 1));
    int rc = 0;
    acquire_irqsave(&g_user_vma_lock, &fl);
    user_vma_t *hit = NULL;
    for (int i = 0; i < USER_VMA_MAX; i++) {
        if (!g_user_vmas[i].used) continue;
        if (!user_vma_tid_matches_runner_mm_nolock(t, (uint64_t)g_user_vmas[i].tid)) continue;
        if (g_user_vmas[i].kind != USER_VMA_KIND_MMAP_LAZY) continue;
        uint64_t a64 = (uint64_t)g_user_vmas[i].addr;
        uint64_t end64 = a64 + (uint64_t)g_user_vmas[i].len;
        if (end64 < a64) continue;
        if ((uint64_t)cr2 >= a64 && (uint64_t)cr2 < end64) {
            hit = &g_user_vmas[i];
            break;
        }
    }
    if (!hit || va2m < hit->addr) {
        release_irqrestore(&g_user_vma_lock, fl);
        return 0;
    }
    uint64_t hit_end = (uint64_t)hit->addr + (uint64_t)hit->len;
    if (hit_end < (uint64_t)hit->addr || (uint64_t)cr2 >= hit_end) {
        release_irqrestore(&g_user_vma_lock, fl);
        return 0;
    }
    uintptr_t mmap_cap = user_as_mmap_brk_top_limit(t);
    uint64_t cap64 = (uint64_t)mmap_cap;
    if (cap64 > (uint64_t)USER_STACK_TOP)
        cap64 = (uint64_t)USER_STACK_TOP;
    if ((uint64_t)va2m >= cap64 || (uint64_t)va2m >= hit_end) {
        release_irqrestore(&g_user_vma_lock, fl);
        return 0;
    }
    uint64_t chunk_end = (uint64_t)va2m + (uint64_t)PAGE_SIZE_2M;
    size_t zlen = (size_t)PAGE_SIZE_2M;
    if (chunk_end > hit_end) {
        zlen = (size_t)(hit_end - (uint64_t)va2m);
        if (zlen == 0 || zlen > (size_t)PAGE_SIZE_2M) {
            release_irqrestore(&g_user_vma_lock, fl);
            return 0;
        }
    }
    release_irqrestore(&g_user_vma_lock, fl);
    if (map_page_2m((uint64_t)va2m, (uint64_t)va2m, PG_PRESENT | PG_RW | PG_US) != 0)
        return 0;
    memset((void *)(uintptr_t)va2m, 0, zlen);
    return 1;
}

/* axonos.h / idt.c */
int fault_try_mmap_lazy_anon(uint64_t cr2) {
    return user_vma_fault_lazy_anon(cr2);
}
