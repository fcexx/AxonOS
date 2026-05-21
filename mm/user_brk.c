#include <user_brk.h>
#include <user_as.h>
#include <user_map.h>
#include <user_mm.h>
#include <user_vma.h>
#include <exec.h>
#include <heap.h>
#include <mmio.h>
#include <paging.h>
#include <string.h>
#include <thread.h>
#include <axonos.h>

extern void kprintf(const char *fmt, ...);

static int user_brk_watch(thread_t *t) {
    if (!t || !t->name[0]) return 0;
    return (strstr(t->name, "wget") || strstr(t->name, "busybox") || strstr(t->name, "uget") ||
            strstr(t->name, "adduser") || strstr(t->name, "addgroup")) ? 1 : 0;
}

void syscall_set_user_brk(uintptr_t base) {
    thread_t *tcur = thread_get_current_user();
    if (!tcur) tcur = thread_current();
    user_as_reset_on_exec(tcur, base);
}

int fault_try_grow_user_heap(uint64_t cr2) {
    thread_t *tcur = thread_current();
    if (!tcur || tcur->ring != 3) {
        tcur = thread_get_current_user();
        if (!tcur) return 0;
    }
    uintptr_t brk_base = tcur->user_brk_base;
    uintptr_t brk_cur = tcur->user_brk_cur;
    if (brk_base == 0) brk_base = brk_cur = 8u * 1024u * 1024u;
    uintptr_t top_limit = user_as_mmap_brk_top_limit(tcur);
    {
        uintptr_t heap_lo = (uintptr_t)heap_base_addr();
        if (heap_lo > 0x200000u && heap_lo < (uintptr_t)MMIO_IDENTITY_LIMIT) {
            uintptr_t guard = 0x20000u;
            uintptr_t heap_cap = (heap_lo > guard) ? (heap_lo - guard) : heap_lo;
            if (heap_cap < top_limit)
                top_limit = heap_cap;
        }
    }
    {
        uintptr_t mmap_lo = user_vma_min_mmap_like_for_thread(tcur, brk_base);
        if (mmap_lo < (uintptr_t)MMIO_IDENTITY_LIMIT && mmap_lo > brk_base && mmap_lo < top_limit)
            top_limit = mmap_lo;
    }
    uintptr_t page_va = (uintptr_t)cr2 & ~((uintptr_t)PAGE_SIZE_2M - 1);
    if (page_va >= (uintptr_t)MMIO_IDENTITY_LIMIT) return 0;
    if (page_va + PAGE_SIZE_2M < page_va) return 0;
    if (page_va < brk_base || page_va + PAGE_SIZE_2M > top_limit) return 0;
    if (page_va + PAGE_SIZE_2M <= brk_cur) return 0;
    if (map_page_2m(page_va, page_va, PG_PRESENT | PG_RW | PG_US) != 0) return 0;
    uintptr_t old_brk = brk_cur;
    uintptr_t new_brk = page_va + PAGE_SIZE_2M;
    if (old_brk < page_va) old_brk = page_va;
    if (new_brk > brk_cur)
        tcur->user_brk_cur = new_brk;
    user_as_shared_publish_brk(tcur, tcur->user_brk_base, tcur->user_brk_cur);
    if (new_brk > old_brk && !user_as_mmap_overlaps_kernel_heap(old_brk, (uintptr_t)(new_brk - old_brk)))
        user_as_mmap_memset_zero_chunked(old_brk, (size_t)(new_brk - old_brk));
    if (user_brk_watch(tcur)) {
        kprintf("heap-grow: pid=%s cr2=0x%llx page=0x%llx old_brk=0x%llx new_brk=0x%llx\n",
            tcur->name, (unsigned long long)cr2, (unsigned long long)page_va,
            (unsigned long long)brk_cur, (unsigned long long)tcur->user_brk_cur);
    }
    return 1;
}

uint64_t user_syscall_brk(uint64_t req) {
    thread_t *tcur = thread_get_current_user();
    if (!tcur) tcur = thread_current();
    uintptr_t *p_base = tcur ? &tcur->user_brk_base : &user_as_brk_base;
    uintptr_t *p_cur = tcur ? &tcur->user_brk_cur : &user_as_brk_cur;
    if (tcur) {
        uintptr_t shared_base = user_as_shared_pick_brk_base(tcur, *p_base);
        uintptr_t shared_cur = user_as_shared_max_brk_cur(tcur, *p_cur);
        if (shared_base != 0 && (*p_base == 0 || *p_base > shared_base))
            *p_base = shared_base;
        if (shared_cur > *p_cur)
            *p_cur = shared_cur;
    }
    if (*p_base == 0) {
        *p_base = 8u * 1024u * 1024u;
        *p_cur = *p_base;
    }
    if (req == 0) return (uint64_t)(*p_cur);
    req = user_mm_align_up((uintptr_t)req, 16);
    if (req >= (uintptr_t)MMIO_IDENTITY_LIMIT || *p_cur >= (uintptr_t)MMIO_IDENTITY_LIMIT ||
        *p_base >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
        *p_base = 8u * 1024u * 1024u;
        *p_cur = *p_base;
        return (uint64_t)(*p_cur);
    }
    uintptr_t top_limit = user_as_mmap_brk_top_limit(tcur);
    {
        uintptr_t heap_lo = (uintptr_t)heap_base_addr();
        if (heap_lo > 0x200000u && heap_lo < (uintptr_t)MMIO_IDENTITY_LIMIT) {
            uintptr_t guard = 0x20000u;
            uintptr_t heap_cap = (heap_lo > guard) ? (heap_lo - guard) : heap_lo;
            if (heap_cap < top_limit)
                top_limit = heap_cap;
        }
    }
    {
        uintptr_t mmap_lo = user_vma_min_mmap_like_for_thread(tcur, *p_base);
        if (mmap_lo < (uintptr_t)MMIO_IDENTITY_LIMIT && mmap_lo > *p_base && mmap_lo < top_limit)
            top_limit = mmap_lo;
    }
    {
        uintptr_t rsp = (uintptr_t)syscall_user_rsp_saved;
        if (rsp >= 0x200000u && rsp < top_limit) {
            uintptr_t rsp_cap = (rsp > 0x40000u) ? (rsp - 0x40000u) : 0x200000u;
            if (rsp_cap < top_limit)
                top_limit = rsp_cap;
        }
    }
    if (req < *p_base || req >= top_limit) return (uint64_t)(*p_cur);
    if (req > *p_cur) {
        if (tcur && user_as_mmap_overlaps_user_stack(tcur, (uintptr_t)(*p_cur),
                (uintptr_t)(req - *p_cur), NULL)) {
            kprintf("brk: refuse grow through stack cur=0x%llx req=0x%llx rsp=0x%llx stk=[0x%llx..0x%llx]\n",
                (unsigned long long)*p_cur, (unsigned long long)req,
                (unsigned long long)(uint64_t)syscall_user_rsp_saved,
                (unsigned long long)tcur->user_stack_base,
                (unsigned long long)tcur->user_stack_limit);
            return (uint64_t)(*p_cur);
        }
        if (user_map_ensure_present_us_2m((uint64_t)(*p_cur), (uint64_t)req) != 0)
            return (uint64_t)(*p_cur);
        if (tcur && user_as_mmap_overlaps_user_stack(tcur, (uintptr_t)(*p_cur),
                (uintptr_t)(req - *p_cur), NULL))
            return (uint64_t)(*p_cur);
        if (user_as_mmap_overlaps_kernel_heap((uintptr_t)(*p_cur), (uintptr_t)(req - *p_cur)))
            return (uint64_t)(*p_cur);
        user_as_mmap_memset_zero_chunked((uintptr_t)(*p_cur), (size_t)(req - *p_cur));
    }
    *p_cur = (uintptr_t)req;
    user_as_shared_publish_brk(tcur, *p_base, *p_cur);
    if (user_brk_watch(tcur)) {
        kprintf("brk: pid=%s base=0x%llx cur=0x%llx req=0x%llx top=0x%llx mmap_next=0x%llx\n",
            tcur->name, (unsigned long long)*p_base, (unsigned long long)*p_cur,
            (unsigned long long)req, (unsigned long long)top_limit,
            (unsigned long long)(tcur ? tcur->user_mmap_next : user_as_mmap_next));
    }
    return (uint64_t)(*p_cur);
}
