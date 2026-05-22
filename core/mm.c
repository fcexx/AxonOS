#include <mm.h>
#include <paging.h>
#include <heap.h>
#include <string.h>
#include <mmio.h>
#include <thread.h>

static mm_t g_kernel_mm;
static int g_mm_ready = 0;

typedef struct mm_alloc_node {
    void *raw;
    struct mm_alloc_node *next;
} mm_alloc_node_t;

static void *kmalloc_aligned(size_t size, size_t align, void **out_raw) {
    if (!out_raw || align == 0) return NULL;
    void *raw = kmalloc(size + align);
    if (!raw) return NULL;
    uintptr_t p = (uintptr_t)raw;
    uintptr_t aligned = (p + (uintptr_t)align - 1u) & ~((uintptr_t)align - 1u);
    *out_raw = raw;
    return (void*)aligned;
}

static int mm_track_raw(mm_t *mm, void *raw) {
    if (!mm || !raw) return -1;
    mm_alloc_node_t *n = (mm_alloc_node_t*)kmalloc(sizeof(*n));
    if (!n) return -1;
    n->raw = raw;
    n->next = (mm_alloc_node_t*)mm->allocs;
    mm->allocs = (struct mm_alloc_node*)n;
    return 0;
}

static uint64_t *alloc_pt_page(mm_t *mm) {
    void *raw = NULL;
    void *aligned = kmalloc_aligned((size_t)PAGE_SIZE_4K, (size_t)PAGE_SIZE_4K, &raw);
    if (!aligned) return NULL;
    if (mm_track_raw(mm, raw) != 0) { kfree(raw); return NULL; }
    memset(aligned, 0, (size_t)PAGE_SIZE_4K);
    return (uint64_t*)aligned;
}

/* Page-table pages must live in the identity-mapped low region; otherwise
 * casting PTE physical addresses to pointers faults (e.g. PA == 4GiB). */
static inline int pt_page_pa_ok(uint64_t ent) {
    if (!(ent & PG_PRESENT)) return 1;
    return (ent & ~0xFFFULL) < (uint64_t)MMIO_IDENTITY_LIMIT;
}

static uint64_t *dup_pt_page(mm_t *mm, uint64_t *src) {
    if (!src || (uintptr_t)src >= (uintptr_t)MMIO_IDENTITY_LIMIT) return NULL;
    uint64_t *dst = alloc_pt_page(mm);
    if (!dst) return NULL;
    memcpy(dst, src, (size_t)PAGE_SIZE_4K);
    return dst;
}

static int split_2m_to_4k(mm_t *mm, uint64_t *l2, int l2i) {
    uint64_t ent2 = l2[l2i];
    if (!(ent2 & PG_PRESENT) || !(ent2 & PG_PS_2M)) return 0;
    uint64_t base_pa = ent2 & ~(PAGE_SIZE_2M - 1ULL);
    uint64_t keep = ent2 & (PG_PRESENT | PG_RW | PG_US | PG_PWT | PG_PCD | PG_GLOBAL | PG_NX);
    uint64_t *l1 = alloc_pt_page(mm);
    if (!l1) return -1;
    for (size_t i = 0; i < 512; i++) {
        uint64_t pa = base_pa + ((uint64_t)i * PAGE_SIZE_4K);
        l1[i] = (pa & ~0xFFFULL) | (keep & ~PG_PS_2M);
    }
    l2[l2i] = ((uint64_t)(uintptr_t)l1) | (keep & ~PG_PS_2M);
    return 0;
}

/* Split a 1GiB L3 leaf (bootstrap identity) into a L2 table of 2MiB pages. */
static int split_l3_1g_to_l2(mm_t *mm, uint64_t *l3, int l3i) {
    uint64_t ent3 = l3[l3i];
    if (!(ent3 & PG_PRESENT) || !(ent3 & PG_PS_2M)) return 0;
    uint64_t base_pa = ent3 & ~0x3FFFFFFFULL;
    uint64_t keep = ent3 & (PG_PRESENT | PG_RW | PG_US | PG_PWT | PG_PCD | PG_GLOBAL | PG_NX);
    uint64_t *l2 = alloc_pt_page(mm);
    if (!l2) return -1;
    for (size_t i = 0; i < 512; i++) {
        uint64_t pa = base_pa + (uint64_t)i * PAGE_SIZE_2M;
        l2[i] = (pa & ~(PAGE_SIZE_2M - 1ULL)) | keep | PG_PS_2M;
    }
    l3[l3i] = ((uint64_t)(uintptr_t)l2) | (keep & ~PG_PS_2M);
    return 0;
}

/* Map one 4K user page at `va` -> `pa` in `mm`, breaking sharing with baseline page tables
 * one level at a time. `share_l4` is the *physical root* of the comparison tree (identity VA):
 *   - fork(copy_old): must be paging_read_cr3() so it matches the parent even when
 *     share_cmp_mm->pml4 (e.g. g_kernel_mm) is stale vs loaded CR3.
 *   - exec: use retained parent template ->pml4. */
static int mm_map_4k_sharedaware(mm_t *mm, uint64_t *share_l4, uint64_t va, uint64_t pa, uint64_t flags) {
    if (!mm || !mm->pml4 || !share_l4) return -1;
    if (va >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;
    if ((uintptr_t)mm->pml4 == (uintptr_t)share_l4) return -1;

    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    int l1i = (int)((va >> 12) & 0x1FF);

    uint64_t se4 = share_l4[l4i];
    if (!(se4 & PG_PRESENT) || !pt_page_pa_ok(se4)) return -1;

    uint64_t ent4 = mm->pml4[l4i];
    uint64_t *l3 = NULL;
    if (ent4 & PG_PRESENT) {
        if (!pt_page_pa_ok(ent4)) return -1;
        if ((se4 & PG_PRESENT) && pt_page_pa_ok(se4) &&
            (ent4 & ~0xFFFULL) == (se4 & ~0xFFFULL)) {
            l3 = (uint64_t*)(uintptr_t)(ent4 & ~0xFFFULL);
            uint64_t *n3 = dup_pt_page(mm, l3);
            if (!n3) return -1;
            l3 = n3;
            mm->pml4[l4i] = ((uint64_t)(uintptr_t)l3) | (ent4 & 0xFFFULL);
        } else {
            l3 = (uint64_t*)(uintptr_t)(ent4 & ~0xFFFULL);
        }
    } else {
        l3 = alloc_pt_page(mm);
        if (!l3) return -1;
        mm->pml4[l4i] = ((uint64_t)(uintptr_t)l3) | PG_PRESENT | PG_RW | PG_US;
    }

    uint64_t *share_l3 = (uint64_t*)(uintptr_t)(se4 & ~0xFFFULL);
    uint64_t se3 = share_l3[l3i];

    uint64_t ent3 = l3[l3i];
    if ((ent3 & PG_PRESENT) && (ent3 & PG_PS_2M)) {
        if (split_l3_1g_to_l2(mm, l3, l3i) != 0) return -1;
        ent3 = l3[l3i];
    }
    if (ent3 & PG_PS_2M) return -1;
    uint64_t *l2 = NULL;
    if (ent3 & PG_PRESENT) {
        if (!pt_page_pa_ok(ent3)) return -1;
        if ((se3 & PG_PRESENT) && !(se3 & PG_PS_2M) && pt_page_pa_ok(se3) &&
            (ent3 & ~0xFFFULL) == (se3 & ~0xFFFULL)) {
            l2 = (uint64_t*)(uintptr_t)(ent3 & ~0xFFFULL);
            uint64_t *n2 = dup_pt_page(mm, l2);
            if (!n2) return -1;
            l2 = n2;
            l3[l3i] = ((uint64_t)(uintptr_t)l2) | (ent3 & 0xFFFULL);
        } else {
            l2 = (uint64_t*)(uintptr_t)(ent3 & ~0xFFFULL);
        }
    } else {
        l2 = alloc_pt_page(mm);
        if (!l2) return -1;
        l3[l3i] = ((uint64_t)(uintptr_t)l2) | PG_PRESENT | PG_RW | PG_US;
    }

    uint64_t se2 = 0;
    if (!(se3 & PG_PRESENT)) return -1;
    if (!(se3 & PG_PS_2M)) {
        uint64_t *share_l2 = (uint64_t*)(uintptr_t)(se3 & ~0xFFFULL);
        se2 = share_l2[l2i];
    }

    uint64_t ent2_pre = l2[l2i];
    int had_2m_ps = (ent2_pre & PG_PRESENT) && (ent2_pre & PG_PS_2M);
    if (split_2m_to_4k(mm, l2, l2i) != 0) return -1;
    uint64_t ce2 = l2[l2i];

    uint64_t *l1 = NULL;
    if (!(ce2 & PG_PRESENT)) {
        l1 = alloc_pt_page(mm);
        if (!l1) return -1;
        l2[l2i] = ((uint64_t)(uintptr_t)l1) | PG_PRESENT | PG_RW | PG_US;
    } else {
        if (!pt_page_pa_ok(ce2)) return -1;
        if (ce2 & PG_PS_2M) return -1;
        l1 = (uint64_t*)(uintptr_t)(ce2 & ~0xFFFULL);
        if (!had_2m_ps && !(se3 & PG_PS_2M) && (se2 & PG_PRESENT) && !(se2 & PG_PS_2M) && pt_page_pa_ok(se2) &&
            (ce2 & ~0xFFFULL) == (se2 & ~0xFFFULL)) {
            uint64_t *n1 = dup_pt_page(mm, l1);
            if (!n1) return -1;
            l1 = n1;
            l2[l2i] = ((uint64_t)(uintptr_t)l1) | (ce2 & 0xFFFULL);
        }
    }

    l1[l1i] = (pa & ~0xFFFULL) | (flags & ~(PG_PS_2M)) | PG_PRESENT;
    return 0;
}

/* Ensure child mm has a private page-table path to `va` (dup shared levels vs share_l4). */
static int mm_fork_private_pt_path(mm_t *mm, uint64_t *share_l4, uint64_t va,
                                   uint64_t **out_l2, int *out_l2i, uint64_t **out_l1) {
    if (!mm || !mm->pml4 || !share_l4 || !out_l2 || !out_l2i || !out_l1) return -1;
    if ((uintptr_t)mm->pml4 == (uintptr_t)share_l4) return -1;
    if (va >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;

    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);

    uint64_t se4 = share_l4[l4i];
    if (!(se4 & PG_PRESENT) || !pt_page_pa_ok(se4)) return -1;

    uint64_t ent4 = mm->pml4[l4i];
    uint64_t *l3 = NULL;
    if (ent4 & PG_PRESENT) {
        if (!pt_page_pa_ok(ent4)) return -1;
        l3 = (uint64_t *)(uintptr_t)(ent4 & ~0xFFFULL);
        if ((ent4 & ~0xFFFULL) == (se4 & ~0xFFFULL)) {
            uint64_t *n3 = dup_pt_page(mm, l3);
            if (!n3) return -1;
            l3 = n3;
            mm->pml4[l4i] = ((uint64_t)(uintptr_t)l3) | (ent4 & 0xFFFULL);
        }
    } else {
        return -1;
    }

    uint64_t *share_l3 = (uint64_t *)(uintptr_t)(se4 & ~0xFFFULL);
    uint64_t se3 = share_l3[l3i];
    uint64_t ent3 = l3[l3i];
    if (!(ent3 & PG_PRESENT)) return -1;
    if ((ent3 & PG_PS_2M) || (se3 & PG_PS_2M)) {
        if (split_l3_1g_to_l2(mm, l3, l3i) != 0) return -1;
        ent3 = l3[l3i];
    }
    if (ent3 & PG_PS_2M) return -1;

    uint64_t *l2 = NULL;
    if (ent3 & PG_PRESENT) {
        if (!pt_page_pa_ok(ent3)) return -1;
        l2 = (uint64_t *)(uintptr_t)(ent3 & ~0xFFFULL);
        if ((se3 & PG_PRESENT) && !(se3 & PG_PS_2M) && pt_page_pa_ok(se3) &&
            (ent3 & ~0xFFFULL) == (se3 & ~0xFFFULL)) {
            uint64_t *n2 = dup_pt_page(mm, l2);
            if (!n2) return -1;
            l2 = n2;
            l3[l3i] = ((uint64_t)(uintptr_t)l2) | (ent3 & 0xFFFULL);
        }
    } else {
        return -1;
    }

    uint64_t se2 = 0;
    if ((se3 & PG_PRESENT) && !(se3 & PG_PS_2M) && pt_page_pa_ok(se3)) {
        uint64_t *share_l2 = (uint64_t *)(uintptr_t)(se3 & ~0xFFFULL);
        se2 = share_l2[l2i];
    }

    uint64_t ent2 = l2[l2i];
    if (!(ent2 & PG_PRESENT)) return -1;
    if (ent2 & PG_PS_2M) {
        *out_l2 = l2;
        *out_l2i = l2i;
        *out_l1 = NULL;
        return 0;
    }

    uint64_t *l1 = (uint64_t *)(uintptr_t)(ent2 & ~0xFFFULL);
    if (!pt_page_pa_ok(ent2)) return -1;
    if ((se2 & PG_PRESENT) && !(se2 & PG_PS_2M) && pt_page_pa_ok(se2) &&
        (ent2 & ~0xFFFULL) == (se2 & ~0xFFFULL)) {
        uint64_t *n1 = dup_pt_page(mm, l1);
        if (!n1) return -1;
        l1 = n1;
        l2[l2i] = ((uint64_t)(uintptr_t)l1) | (ent2 & 0xFFFULL);
    }

    *out_l2 = l2;
    *out_l2i = l2i;
    *out_l1 = l1;
    return 0;
}

int mm_clear_range_private(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end) {
    if (!mm || !mm->pml4 || !share_l4) return -1;
    if (va_end <= va_begin) return 0;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;

    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    for (uint64_t va = begin; va < end; ) {
        uint64_t *l2 = NULL;
        int l2i = 0;
        uint64_t *l1 = NULL;
        if (mm_fork_private_pt_path(mm, share_l4, va, &l2, &l2i, &l1) != 0) {
            va += 0x1000ULL;
            continue;
        }
        uint64_t ent2 = l2[l2i];
        if (ent2 & PG_PS_2M) {
            l2[l2i] = 0;
            va = (va & ~((uint64_t)PAGE_SIZE_2M - 1ULL)) + PAGE_SIZE_2M;
            continue;
        }
        if (l1) {
            int l1i = (int)((va >> 12) & 0x1FF);
            l1[l1i] = 0;
        }
        va += 0x1000ULL;
    }
    return 0;
}

void mm_init(void) {
    if (g_mm_ready) return;
    memset(&g_kernel_mm, 0, sizeof(g_kernel_mm));
    g_kernel_mm.cr3 = paging_read_cr3();
    g_kernel_mm.pml4 = (uint64_t*)(uintptr_t)(g_kernel_mm.cr3 & ~0xFFFULL);
    g_kernel_mm.pml4_alloc_raw = NULL;
    g_kernel_mm.refcount = 1;
    g_mm_ready = 1;
}

mm_t *mm_kernel(void) {
    if (!g_mm_ready) mm_init();
    return &g_kernel_mm;
}

mm_t *mm_retain(mm_t *mm) {
    if (!mm) return mm_kernel();
    if (mm->refcount <= 0) mm->refcount = 1;
    else mm->refcount++;
    return mm;
}

void mm_release(mm_t *mm) {
    if (!mm) return;
    if (mm == &g_kernel_mm) return;
    if (mm->refcount <= 0) return;
    mm->refcount--;
    if (mm->refcount == 0) {
        /* free all aligned backing allocations tracked in this mm */
        mm_alloc_node_t *n = (mm_alloc_node_t*)mm->allocs;
        while (n) {
            mm_alloc_node_t *nx = n->next;
            if (n->raw) kfree(n->raw);
            kfree(n);
            n = nx;
        }
        if (mm->pml4_alloc_raw) kfree(mm->pml4_alloc_raw);
        kfree(mm);
    }
}

mm_t *mm_clone_current(void) {
    if (!g_mm_ready) mm_init();
    mm_t *m = (mm_t*)kmalloc(sizeof(mm_t));
    if (!m) return NULL;
    memset(m, 0, sizeof(*m));

    void *raw = kmalloc((size_t)PAGE_SIZE_4K + (size_t)PAGE_SIZE_4K);
    if (!raw) {
        kfree(m);
        return NULL;
    }
    uintptr_t p = (uintptr_t)raw;
    uintptr_t aligned = (p + (uintptr_t)PAGE_SIZE_4K - 1u) & ~((uintptr_t)PAGE_SIZE_4K - 1u);
    uint64_t *new_l4 = (uint64_t*)aligned;
    uint64_t cur_cr3 = paging_read_cr3();
    uint64_t *src_l4 = (uint64_t*)(uintptr_t)(cur_cr3 & ~0xFFFULL);
    if (!src_l4) {
        kfree(raw);
        kfree(m);
        return NULL;
    }
    memcpy(new_l4, (void*)src_l4, (size_t)PAGE_SIZE_4K);

    m->pml4 = new_l4;
    m->cr3 = (uint64_t)(uintptr_t)new_l4;
    m->pml4_alloc_raw = raw;
    m->refcount = 1;
    return m;
}

int mm_switch(mm_t *mm) {
    if (!g_mm_ready) mm_init();
    mm_t *target = mm ? mm : &g_kernel_mm;
    uint64_t want = target->cr3 ? target->cr3 : (uint64_t)(uintptr_t)target->pml4;
    if (want == 0) want = g_kernel_mm.cr3;
    uint64_t cur = paging_read_cr3();
    if (cur != want) {
        paging_write_cr3(want);
    }
    return 0;
}

/* 0 absent, 1 present read-only user, 2 present writable user (4K or 2MiB). */
static int mm_share_pte_class(uint64_t *share_l4, uint64_t va) {
    if (!share_l4 || va >= (uint64_t)MMIO_IDENTITY_LIMIT) return 0;
    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    int l1i = (int)((va >> 12) & 0x1FF);
    uint64_t se4 = share_l4[l4i];
    if (!(se4 & PG_PRESENT) || !pt_page_pa_ok(se4)) return 0;
    uint64_t *share_l3 = (uint64_t *)(uintptr_t)(se4 & ~0xFFFULL);
    uint64_t se3 = share_l3[l3i];
    if (!(se3 & PG_PRESENT)) return 0;
    if (se3 & PG_PS_2M) {
        if (!(se3 & PG_US)) return 0;
        return (se3 & PG_RW) ? 2 : 1;
    }
    uint64_t *share_l2 = (uint64_t *)(uintptr_t)(se3 & ~0xFFFULL);
    uint64_t se2 = share_l2[l2i];
    if (!(se2 & PG_PRESENT)) return 0;
    if (se2 & PG_PS_2M) {
        if (!(se2 & PG_US)) return 0;
        return (se2 & PG_RW) ? 2 : 1;
    }
    uint64_t *share_l1 = (uint64_t *)(uintptr_t)(se2 & ~0xFFFULL);
    uint64_t se1 = share_l1[l1i];
    if (!(se1 & PG_PRESENT) || !(se1 & PG_US)) return 0;
    return (se1 & PG_RW) ? 2 : 1;
}

int mm_cow_fork_pages(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end,
                      unsigned max_pages, unsigned *copied_out) {
    if (copied_out) *copied_out = 0;
    if (!mm || !mm->pml4 || max_pages == 0) return 0;
    if (!share_l4) return -1;
    if ((uintptr_t)mm->pml4 == (uintptr_t)share_l4) return -1;
    if (va_end <= va_begin) return 0;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    unsigned copied = 0;
    for (uint64_t va = (end > begin) ? (end - 0x1000ULL) : begin; copied < max_pages; ) {
        if (va < begin) break;
        if (mm_share_pte_class(share_l4, va) == 2) {
            void *raw = NULL;
            void *newp = kmalloc_aligned((size_t)PAGE_SIZE_4K, (size_t)PAGE_SIZE_4K, &raw);
            if (!newp) return (copied > 0) ? 0 : -1;
            memcpy(newp, (void *)(uintptr_t)va, (size_t)PAGE_SIZE_4K);
            if (mm_map_4k_sharedaware(mm, share_l4, va, (uint64_t)(uintptr_t)newp, PG_RW | PG_US) != 0) {
                kfree(raw);
                return (copied > 0) ? 0 : -1;
            }
            if (mm_track_raw(mm, raw) != 0) return (copied > 0) ? 0 : -1;
            copied++;
        }
        if (va < begin + 0x1000ULL) break;
        va -= 0x1000ULL;
    }
    if (copied_out) *copied_out = copied;
    return 0;
}

int mm_cow_private_writable(mm_t *mm, uint64_t va_begin, uint64_t va_end) {
    if (!mm || !mm->pml4) return -1;
    uint64_t *share_l4 = (uint64_t *)(uintptr_t)(paging_read_cr3() & ~0xFFFULL);
    if (!share_l4) return -1;
    if (va_end <= va_begin) return 0;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (end - begin > (uint64_t)(512u * 1024u))
        end = begin + (uint64_t)(512u * 1024u);
    uint64_t page_idx = 0;
    enum { COW_PAGE_BUDGET = 48u };
    for (uint64_t va = begin; va < end; va += 0x1000ULL) {
        int cls = mm_share_pte_class(share_l4, va);
        if (cls != 2) continue;
        /* Skip 2MiB huge pages (split per-4K in mm_map_4k_sharedaware is far too slow). */
        {
            int l4i = (int)((va >> 39) & 0x1FF);
            int l3i = (int)((va >> 30) & 0x1FF);
            int l2i = (int)((va >> 21) & 0x1FF);
            uint64_t se4 = share_l4[l4i];
            if (se4 & PG_PRESENT) {
                uint64_t *l3 = (uint64_t *)(uintptr_t)(se4 & ~0xFFFULL);
                uint64_t se3 = l3[l3i];
                if ((se3 & PG_PRESENT) && (se3 & PG_PS_2M)) {
                    va = (va & ~((uint64_t)PAGE_SIZE_2M - 1)) + PAGE_SIZE_2M;
                    continue;
                }
                if (se3 & PG_PRESENT && !(se3 & PG_PS_2M)) {
                    uint64_t *l2 = (uint64_t *)(uintptr_t)(se3 & ~0xFFFULL);
                    uint64_t se2 = l2[l2i];
                    if ((se2 & PG_PRESENT) && (se2 & PG_PS_2M)) {
                        va = (va & ~((uint64_t)PAGE_SIZE_2M - 1)) + PAGE_SIZE_2M;
                        continue;
                    }
                }
            }
        }
        if (page_idx >= COW_PAGE_BUDGET)
            break;
        page_idx++;
        void *raw = NULL;
        void *newp = kmalloc_aligned((size_t)PAGE_SIZE_4K, (size_t)PAGE_SIZE_4K, &raw);
        if (!newp) return -1;
        memcpy(newp, (void *)(uintptr_t)va, (size_t)PAGE_SIZE_4K);
        if (mm_map_4k_sharedaware(mm, share_l4, va, (uint64_t)(uintptr_t)newp, PG_RW | PG_US) != 0) {
            kfree(raw);
            return -1;
        }
        if (mm_track_raw(mm, raw) != 0) return -1;
    }
    return 0;
}

int mm_make_private_range(mm_t *mm, uint64_t va_begin, uint64_t va_end, int copy_old,
                          mm_t *share_cmp_mm) {
    if (!mm || !mm->pml4) return -1;
    /* Baseline for dup/split decisions: live CR3 at fork syscall; else mm_ptemplate/kernel. */
    uint64_t *share_l4 = NULL;
    if (copy_old) {
        share_l4 = (uint64_t*)(uintptr_t)(paging_read_cr3() & ~0xFFFULL);
    } else {
        mm_t *share = share_cmp_mm ? share_cmp_mm : mm_kernel();
        if (!share->pml4) return -1;
        share_l4 = share->pml4;
    }
    if (!share_l4) return -1;
    if (va_end <= va_begin) return 0;
    /* Never touch VA >= 4GB: identity map ends at MMIO_IDENTITY_LIMIT.
       Otherwise memcpy from (void*)va would page-fault at 0x100000000. */
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    if (va_begin >= va_end) return 0;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t page_idx = 0;
    for (uint64_t va = begin; va < end; va += 0x1000ULL) {
        /* fork(copy_old): force private copy for the full requested range.
         * Skipping pages based on live CR3 probing can leave parent/child sharing
         * heap mappings, which later corrupts userspace malloc metadata. */
        /* fork() can duplicate many 4K pages — yield periodically. */
        if (copy_old && (++page_idx & 31u) == 0u)
            thread_yield();
        void *raw = NULL;
        void *newp = kmalloc_aligned((size_t)PAGE_SIZE_4K, (size_t)PAGE_SIZE_4K, &raw);
        if (!newp) return -1;
        if (copy_old) memcpy(newp, (void*)(uintptr_t)va, (size_t)PAGE_SIZE_4K);
        else memset(newp, 0, (size_t)PAGE_SIZE_4K);
        if (mm_map_4k_sharedaware(mm, share_l4, va, (uint64_t)(uintptr_t)newp, PG_RW | PG_US) != 0) {
            kfree(raw);
            return -1;
        }
        /* Track raw backing so mm_release() can free this page later. */
        if (mm_track_raw(mm, raw) != 0) {
            /* Mapping exists now; keep going would leak raw forever. Fail fast. */
            return -1;
        }
    }
    return 0;
}
