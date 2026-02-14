#include <paging.h>

// Bootstrap page tables are defined in boot/multiboot.asm
// We import only L4. L3 identity maps first 4GiB using 1GiB pages already.
extern uint64_t page_table_l4[];   // 4KiB aligned, 512 entries

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

static inline uint64_t read_cr3(void) {
    uint64_t v; __asm__ volatile("mov %%cr3, %0" : "=r"(v)); return v;
}
static inline void write_cr3(uint64_t v) {
    __asm__ volatile("mov %0, %%cr3" :: "r"(v) : "memory");
}

void invlpg(void* va) { __asm__ volatile("invlpg (%0)" :: "r"(va) : "memory"); }

void paging_init(void) {
    // Ensure CR3 is loaded with our L4 base (it already is after bootstrap)
    (void)read_cr3();
}

int map_page_2m(uint64_t va, uint64_t pa, uint64_t flags) {
    // Extract indices
    uint64_t l4i = (va >> 39) & 0x1FF;
    uint64_t l3i = (va >> 30) & 0x1FF;
    uint64_t l2i = (va >> 21) & 0x1FF;

    uint64_t* l4 = (uint64_t*)((uint64_t)page_table_l4);
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
    // Set 2MiB page entry
    l2[l2i] = (pa & ~(PAGE_SIZE_2M - 1)) | PG_PRESENT | PG_RW | PG_PS_2M | (flags & (PG_US|PG_PWT|PG_PCD|PG_GLOBAL));

    invlpg((void*)va);
    return 0;
}

int unmap_page_2m(uint64_t va) {
    uint64_t l4i = (va >> 39) & 0x1FF;
    uint64_t l3i = (va >> 30) & 0x1FF;
    uint64_t l2i = (va >> 21) & 0x1FF;
    uint64_t* l4 = (uint64_t*)((uint64_t)page_table_l4);
    if (!(l4[l4i] & PG_PRESENT)) return -1;
    uint64_t* l3 = (uint64_t*)(l4[l4i] & ~0xFFFULL);
    if (!(l3[l3i] & PG_PRESENT)) return -1;
    uint64_t* l2 = (uint64_t*)(l3[l3i] & ~0xFFFULL);
    l2[l2i] = 0;
    invlpg((void*)va);
    return 0;
}


