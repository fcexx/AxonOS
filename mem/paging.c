#include <paging.h>

// Simple page-table allocator for creating new PDPT/PD tables for 2MiB mappings
static uint64_t* next_free_table(void) {
    /* 2MiB remaps (MMIO, user mmaps, etc.) need to split bootstrap 1GiB pages.
       Give ourselves enough tables so we don't silently fail and end up accessing
       MMIO through cached/incorrect mappings. */
    static uint64_t pool[128][PT_ENTRIES] __attribute__((aligned(4096)));
    static size_t used = 0;
    if (used >= 128) return 0;
    for (size_t i = 0; i < PT_ENTRIES; i++) pool[used][i] = 0;
    return pool[used++];
}

uint64_t paging_read_cr3(void) {
    uint64_t v; __asm__ volatile("mov %%cr3, %0" : "=r"(v)); return v;
}
void paging_write_cr3(uint64_t v) {
    __asm__ volatile("mov %0, %%cr3" :: "r"(v) : "memory");
}

void invlpg(void* va) { __asm__ volatile("invlpg (%0)" :: "r"(va) : "memory"); }

static inline uint64_t rdmsr_u64(uint32_t msr) {
    uint32_t lo = 0, hi = 0;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}
static inline void wrmsr_u64(uint32_t msr, uint64_t v) {
    uint32_t lo = (uint32_t)(v & 0xFFFFFFFFu);
    uint32_t hi = (uint32_t)(v >> 32);
    __asm__ volatile("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

#define MSR_EFER 0xC0000080u
#define EFER_NXE (1ULL << 11)

void paging_init(void) {
    // Ensure CR3 is loaded with our L4 base (it already is after bootstrap)
    (void)paging_read_cr3();
    // Enable EFER.NXE so PG_NX in PTEs is valid; without this, NX bit causes RSVD page fault
    uint64_t efer = rdmsr_u64(MSR_EFER);
    efer |= EFER_NXE;
    wrmsr_u64(MSR_EFER, efer);
}

int map_page_2m(uint64_t va, uint64_t pa, uint64_t flags) {
    // Extract indices
    uint64_t l4i = (va >> 39) & 0x1FF;
    uint64_t l3i = (va >> 30) & 0x1FF;
    uint64_t l2i = (va >> 21) & 0x1FF;

    uint64_t cr3 = paging_read_cr3();
    uint64_t* l4 = (uint64_t*)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!l4) return -1;
    if (!(l4[l4i] & PG_PRESENT)) {
        uint64_t* new_l3 = next_free_table();
        if (!new_l3) return -1;
        l4[l4i] = ((uint64_t)new_l3) | PG_PRESENT | PG_RW;
    }

    uint64_t* l3 = (uint64_t*)(l4[l4i] & ~0xFFFULL);
    if (!(l3[l3i] & PG_PRESENT)) {
        uint64_t* new_l2 = next_free_table();
        if (!new_l2) return -2;
        l3[l3i] = ((uint64_t)new_l2) | PG_PRESENT | PG_RW;
    }
    /* If L3 entry is a 1GiB leaf mapping, split it into a L2 table of 2MiB pages.
       Bootstrap identity mapping uses 1GiB pages for the first 4GiB; MMIO mappings
       need to override small ranges inside those hugepages. */
    if (l3[l3i] & PG_PS_2M) {
        uint64_t leaf = l3[l3i];
        uint64_t* new_l2 = next_free_table();
        if (!new_l2) return -2;

        /* 1GiB page base PA (bits 30+) */
        uint64_t base_pa = leaf & ~0x3FFFFFFFULL;
        /* Preserve relevant flags from the leaf entry. */
        uint64_t keep = leaf & (PG_PRESENT | PG_RW | PG_US | PG_PWT | PG_PCD | PG_GLOBAL | PG_NX);
        for (size_t i = 0; i < PT_ENTRIES; i++) {
            uint64_t pa_i = base_pa + (uint64_t)i * PAGE_SIZE_2M;
            new_l2[i] = (pa_i & ~(PAGE_SIZE_2M - 1)) | keep | PG_PS_2M;
        }
        /* Point L3 entry to new L2 table (clear PS). */
        l3[l3i] = ((uint64_t)new_l2) | (keep & ~PG_PS_2M);
    }

    uint64_t* l2 = (uint64_t*)(l3[l3i] & ~0xFFFULL);
    // Set 2MiB page entry. Explicitly clear PG_NX: when EFER.NXE=0, NX bit is reserved
    // and causes page fault with RSVD (err bit 3).
    l2[l2i] = ((pa & ~(PAGE_SIZE_2M - 1)) | PG_PRESENT | PG_RW | PG_PS_2M | (flags & (PG_US|PG_PWT|PG_PCD|PG_GLOBAL))) & ~PG_NX;

    invlpg((void*)va);
    return 0;
}

int unmap_page_2m(uint64_t va) {
    uint64_t l4i = (va >> 39) & 0x1FF;
    uint64_t l3i = (va >> 30) & 0x1FF;
    uint64_t l2i = (va >> 21) & 0x1FF;
    uint64_t cr3 = paging_read_cr3();
    uint64_t* l4 = (uint64_t*)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!l4) return -1;
    if (!(l4[l4i] & PG_PRESENT)) return -1;
    uint64_t* l3 = (uint64_t*)(l4[l4i] & ~0xFFFULL);
    if (!(l3[l3i] & PG_PRESENT)) return -1;
    uint64_t* l2 = (uint64_t*)(l3[l3i] & ~0xFFFULL);
    l2[l2i] = 0;
    invlpg((void*)va);
    return 0;
}


