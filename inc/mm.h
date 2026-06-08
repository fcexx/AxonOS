#pragma once

#include <stdint.h>

typedef struct mm_struct {
    /* Top-level page table (virtual pointer to identity-mapped physical page).
     * Linux separates mm_struct (page tables, refcount) from the VMA rb_tree in
     * struct mm_struct; AxonOS keeps user VMAs in mm/user_vma.c and mmap/brk cursors
     * in mm/user_as.c (per-thread fields + CLONE_VM publish). */
    uint64_t *pml4;
    /* CR3 value used for this address space. */
    uint64_t cr3;
    /* Backing allocation for aligned pml4 (used for release). */
    void *pml4_alloc_raw;
    /* Backing allocations for page-table pages and private user pages created via kmalloc_aligned().
       Each entry is the original `raw` pointer that must be freed (aligned pointer is interior). */
    struct mm_alloc_node *allocs;
    int refcount;
} mm_t;

/* Initialize mm subsystem and capture bootstrap kernel address space. */
void mm_init(void);

/* Get kernel/default address space descriptor. */
mm_t *mm_kernel(void);

/* Retain/release references to mm. */
mm_t *mm_retain(mm_t *mm);
void mm_release(mm_t *mm);

/* Create a new mm by cloning current L4 entries. */
mm_t *mm_clone_current(void);

/* Switch CPU CR3 to provided mm (or kernel mm when NULL). */
int mm_switch(mm_t *mm);

/* Ensure [va_begin, va_end) is mapped to private pages in mm.
   If copy_old != 0, old page contents are copied before remap.
 * share_cmp_mm: page tables to compare against when copy_old==0 (exec); if NULL, mm_kernel().
 * When copy_old!=0 (fork), the live parent root is taken from paging_read_cr3(); share_cmp_mm
 * is ignored for split/dup decisions (callers may still pass parent mm for API symmetry). */
int mm_make_private_range(mm_t *mm, uint64_t va_begin, uint64_t va_end, int copy_old, mm_t *share_cmp_mm);

/* COW up to max_pages present user-writable 4KiB pages (splits 2MiB when needed).
 * share_l4: parent page table root (NOT paging_read_cr3() — CR3 may differ mid-fork). */
int mm_cow_fork_pages(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end,
                      unsigned max_pages, unsigned *copied_out);

/* Fork COW: copy only present user-writable pages in [va_begin, va_end). */
int mm_cow_private_writable(mm_t *mm, uint64_t va_begin, uint64_t va_end);
/* Linux-style COW on first user write after fork (single 4K page at cr2). */
int mm_cow_fault_page(mm_t *mm, uint64_t va, mm_t *share_cmp_mm);

/* Clear [va_begin, va_end) in child mm without touching parent share_l4 mappings.
   Duplicates shared page-table pages one level at a time before clearing PTEs. */
int mm_clear_range_private(mm_t *mm, uint64_t *share_l4, uint64_t va_begin, uint64_t va_end);
