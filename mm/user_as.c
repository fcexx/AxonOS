#include <user_as.h>
#include <user_map.h>
#include <user_mm.h>
#include <exec.h>
#include <heap.h>
#include <klog.h>
#include <mmio.h>
#include <paging.h>
#include <string.h>
#include <thread.h>

uintptr_t user_as_mmap_next = 0;
uintptr_t user_as_mmap_hi = 0;
uintptr_t user_as_brk_base = 0;
uintptr_t user_as_brk_cur = 0;

uintptr_t user_as_stack_top_for_tid(uint64_t tid) {
    const uintptr_t top = (uintptr_t)USER_STACK_TOP;
    const uintptr_t stride = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + (uintptr_t)(64 * 1024);
    const uint64_t slot = tid + 1ULL;
    if (stride == 0) return top;
    if (slot > (uint64_t)((uintptr_t)-1) / (uint64_t)stride) return top;
    const uintptr_t off = (uintptr_t)(slot * (uint64_t)stride);
    const uintptr_t min_room = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + 0x10000u;
    if (top <= min_room) return top;
    if (off >= (top - min_room)) return top;
    return top - off;
}

uintptr_t user_as_mmap_brk_top_limit(thread_t *tcur) {
    uintptr_t top_limit = (uintptr_t)USER_TLS_BASE;
    if (!tcur)
        return top_limit;
    uintptr_t tls_slot = user_as_stack_top_for_tid(tcur->tid ? tcur->tid : 1);
    tls_slot = tls_slot - (uintptr_t)USER_STACK_SIZE - (uintptr_t)USER_TLS_SIZE;
    if (tls_slot > 0x200000 && tls_slot < (uintptr_t)MMIO_IDENTITY_LIMIT && tls_slot < top_limit)
        top_limit = tls_slot;
    if (tcur->user_stack_base != 0u && tcur->user_stack_limit > tcur->user_stack_base) {
        uintptr_t st = (uintptr_t)tcur->user_stack_limit;
        if (st > (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + 0x200000u) {
            uintptr_t tls_exec = st - (uintptr_t)USER_STACK_SIZE - (uintptr_t)USER_TLS_SIZE;
            if (tls_exec > 0x200000 && tls_exec < (uintptr_t)MMIO_IDENTITY_LIMIT && tls_exec < top_limit)
                top_limit = tls_exec;
        }
    }
    if (top_limit > (uintptr_t)USER_STACK_TOP)
        top_limit = (uintptr_t)USER_STACK_TOP;
    return top_limit;
}

uintptr_t user_as_shared_max_mmap_next(thread_t *cur, uintptr_t fallback) {
    uintptr_t cap = (uintptr_t)USER_STACK_TOP;
    if (cur) {
        uintptr_t tl = user_as_mmap_brk_top_limit(cur);
        if (tl < cap)
            cap = tl;
    }
    uintptr_t v = (fallback < cap) ? fallback : 0;
    if (!cur || !cur->mm)
        return v;
    int n = thread_get_count();
    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t->ring != 3) continue;
        if (t->mm != cur->mm) continue;
        uintptr_t nx = t->user_mmap_next;
        if (nx >= cap) continue;
        if (nx > v) v = nx;
    }
    return v;
}

uintptr_t user_as_shared_max_brk_cur(thread_t *cur, uintptr_t fallback) {
    uintptr_t v = fallback;
    if (!cur || !cur->mm) return v;
    int n = thread_get_count();
    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t->ring != 3) continue;
        if (t->mm != cur->mm) continue;
        if (t->user_brk_cur > v) v = t->user_brk_cur;
    }
    return v;
}

uintptr_t user_as_shared_pick_brk_base(thread_t *cur, uintptr_t fallback) {
    uintptr_t v = fallback;
    if (!cur || !cur->mm) return v;
    int n = thread_get_count();
    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t->ring != 3) continue;
        if (t->mm != cur->mm) continue;
        if (t->user_brk_base > 0 && (v == 0 || t->user_brk_base < v))
            v = t->user_brk_base;
    }
    return v;
}

void user_as_shared_publish_brk(thread_t *cur, uintptr_t base, uintptr_t cur_brk) {
    if (!cur || !cur->mm) return;
    int n = thread_get_count();
    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t->ring != 3) continue;
        if (t->mm != cur->mm) continue;
        if (t->user_brk_base == 0) t->user_brk_base = base;
        if (t->user_brk_cur < cur_brk) t->user_brk_cur = cur_brk;
    }
}

void user_as_shared_publish_mmap(thread_t *cur, uintptr_t next, uintptr_t hi) {
    if (!cur || !cur->mm) return;
    uintptr_t cap = user_as_mmap_brk_top_limit(cur);
    if (cap > (uintptr_t)USER_STACK_TOP)
        cap = (uintptr_t)USER_STACK_TOP;
    if (next > cap || hi > cap) {
        klogprintf("user_as: drop corrupt mmap cursor next=0x%llx hi=0x%llx cap=0x%llx\n",
            (unsigned long long)next, (unsigned long long)hi, (unsigned long long)cap);
        return;
    }
    int n = thread_get_count();
    for (int i = 0; i < n; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t->ring != 3) continue;
        if (t->mm != cur->mm) continue;
        if (t->user_mmap_next < next) t->user_mmap_next = next;
        if (t->user_mmap_hi < hi) t->user_mmap_hi = hi;
    }
}

int user_as_mmap_overlaps_kernel_heap(uintptr_t addr, uintptr_t len) {
    uintptr_t hlo = (uintptr_t)heap_base_addr();
    uintptr_t hhi = heap_region_end_exclusive();
    if (hlo <= 0x200000 || !(hhi > hlo))
        return 0;
    uintptr_t map_end = addr + len;
    if (map_end < addr)
        return 1;
    if (map_end <= hlo || addr >= hhi)
        return 0;
    return 1;
}

void user_as_mmap_memset_zero_chunked(uintptr_t addr, size_t len) {
    const size_t chunk = 4u * 1024u * 1024u;
    if (len <= chunk) {
        memset((void *)addr, 0, len);
        return;
    }
    for (size_t off = 0; off < len; off += chunk) {
        size_t now = (len - off < chunk) ? (len - off) : chunk;
        memset((void *)(addr + off), 0, now);
    }
}

void user_as_mmap_lazy_drop_present_pages(uintptr_t addr, size_t len) {
    uintptr_t begin = addr & ~((uintptr_t)PAGE_SIZE_2M - 1);
    uintptr_t end = (addr + len + (uintptr_t)PAGE_SIZE_2M - 1) & ~((uintptr_t)PAGE_SIZE_2M - 1);
    for (uintptr_t va = begin; va < end; va += (uintptr_t)PAGE_SIZE_2M)
        (void)unmap_page_2m((uint64_t)va);
}

void user_as_reset_on_exec(thread_t *tcur, uintptr_t brk_base) {
    if (brk_base < (8u * 1024u * 1024u)) brk_base = 8u * 1024u * 1024u;
    brk_base = user_mm_align_up(brk_base, 4096);
    if (tcur) {
        tcur->user_brk_base = brk_base;
        tcur->user_brk_cur = brk_base;
        tcur->user_mmap_next = 0;
        tcur->user_mmap_hi = 0;
    } else {
        user_as_brk_base = brk_base;
        user_as_brk_cur = brk_base;
        user_as_mmap_next = 0;
        user_as_mmap_hi = 0;
    }
}
