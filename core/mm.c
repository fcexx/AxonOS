#include <mm.h>
#include <paging.h>
#include <heap.h>
#include <string.h>

static mm_t g_kernel_mm;
static int g_mm_ready = 0;

static void *kmalloc_aligned(size_t size, size_t align, void **out_raw) {
    if (!out_raw || align == 0) return NULL;
    void *raw = kmalloc(size + align);
    if (!raw) return NULL;
    uintptr_t p = (uintptr_t)raw;
    uintptr_t aligned = (p + (uintptr_t)align - 1u) & ~((uintptr_t)align - 1u);
    *out_raw = raw;
    return (void*)aligned;
}

static uint64_t *alloc_pt_page(void **out_raw) {
    void *aligned = kmalloc_aligned((size_t)PAGE_SIZE_4K, (size_t)PAGE_SIZE_4K, out_raw);
    if (!aligned) return NULL;
    memset(aligned, 0, (size_t)PAGE_SIZE_4K);
    return (uint64_t*)aligned;
}

static uint64_t *dup_pt_page(uint64_t *src) {
    void *raw = NULL;
    uint64_t *dst = alloc_pt_page(&raw);
    if (!dst) return NULL;
    memcpy(dst, src, (size_t)PAGE_SIZE_4K);
    return dst;
}

static int split_2m_to_4k(uint64_t *l2, int l2i) {
    uint64_t ent2 = l2[l2i];
    if (!(ent2 & PG_PRESENT) || !(ent2 & PG_PS_2M)) return 0;
    uint64_t base_pa = ent2 & ~(PAGE_SIZE_2M - 1ULL);
    uint64_t keep = ent2 & (PG_PRESENT | PG_RW | PG_US | PG_PWT | PG_PCD | PG_GLOBAL | PG_NX);
    void *raw = NULL;
    uint64_t *l1 = alloc_pt_page(&raw);
    (void)raw;
    if (!l1) return -1;
    for (size_t i = 0; i < 512; i++) {
        uint64_t pa = base_pa + ((uint64_t)i * PAGE_SIZE_4K);
        l1[i] = (pa & ~0xFFFULL) | (keep & ~PG_PS_2M);
    }
    l2[l2i] = ((uint64_t)(uintptr_t)l1) | (keep & ~PG_PS_2M);
    return 0;
}

static int mm_map_4k(mm_t *mm, uint64_t va, uint64_t pa, uint64_t flags) {
    if (!mm || !mm->pml4) return -1;
    uint64_t *l4 = mm->pml4;
    int l4i = (int)((va >> 39) & 0x1FF);
    int l3i = (int)((va >> 30) & 0x1FF);
    int l2i = (int)((va >> 21) & 0x1FF);
    int l1i = (int)((va >> 12) & 0x1FF);

    uint64_t ent4 = l4[l4i];
    uint64_t *l3 = NULL;
    if (ent4 & PG_PRESENT) {
        l3 = (uint64_t*)(uintptr_t)(ent4 & ~0xFFFULL);
        uint64_t *n3 = dup_pt_page(l3);
        if (!n3) return -1;
        l3 = n3;
        l4[l4i] = ((uint64_t)(uintptr_t)l3) | (ent4 & 0xFFFULL);
    } else {
        void *raw = NULL;
        l3 = alloc_pt_page(&raw);
        if (!l3) return -1;
        l4[l4i] = ((uint64_t)(uintptr_t)l3) | PG_PRESENT | PG_RW | PG_US;
    }

    uint64_t ent3 = l3[l3i];
    if (ent3 & PG_PS_2M) return -1;
    uint64_t *l2 = NULL;
    if (ent3 & PG_PRESENT) {
        l2 = (uint64_t*)(uintptr_t)(ent3 & ~0xFFFULL);
        uint64_t *n2 = dup_pt_page(l2);
        if (!n2) return -1;
        l2 = n2;
        l3[l3i] = ((uint64_t)(uintptr_t)l2) | (ent3 & 0xFFFULL);
    } else {
        void *raw = NULL;
        l2 = alloc_pt_page(&raw);
        if (!l2) return -1;
        l3[l3i] = ((uint64_t)(uintptr_t)l2) | PG_PRESENT | PG_RW | PG_US;
    }

    if (split_2m_to_4k(l2, l2i) != 0) return -1;
    uint64_t ent2 = l2[l2i];
    uint64_t *l1 = NULL;
    if (ent2 & PG_PRESENT) {
        l1 = (uint64_t*)(uintptr_t)(ent2 & ~0xFFFULL);
        uint64_t *n1 = dup_pt_page(l1);
        if (!n1) return -1;
        l1 = n1;
        l2[l2i] = ((uint64_t)(uintptr_t)l1) | (ent2 & 0xFFFULL);
    } else {
        void *raw = NULL;
        l1 = alloc_pt_page(&raw);
        if (!l1) return -1;
        l2[l2i] = ((uint64_t)(uintptr_t)l1) | PG_PRESENT | PG_RW | PG_US;
    }

    l1[l1i] = (pa & ~0xFFFULL) | (flags & ~(PG_PS_2M)) | PG_PRESENT;
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

int mm_make_private_range(mm_t *mm, uint64_t va_begin, uint64_t va_end, int copy_old) {
    if (!mm) return -1;
    if (va_end <= va_begin) return 0;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    for (uint64_t va = begin; va < end; va += 0x1000ULL) {
        void *raw = NULL;
        void *newp = kmalloc_aligned((size_t)PAGE_SIZE_4K, (size_t)PAGE_SIZE_4K, &raw);
        if (!newp) return -1;
        if (copy_old) memcpy(newp, (void*)(uintptr_t)va, (size_t)PAGE_SIZE_4K);
        else memset(newp, 0, (size_t)PAGE_SIZE_4K);
        if (mm_map_4k(mm, va, (uint64_t)(uintptr_t)newp, PG_RW | PG_US) != 0) return -1;
        (void)raw;
    }
    return 0;
}
