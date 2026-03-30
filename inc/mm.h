#pragma once

#include <stdint.h>

typedef struct mm_struct {
    /* Top-level page table (virtual pointer to identity-mapped physical page). */
    uint64_t *pml4;
    /* CR3 value used for this address space. */
    uint64_t cr3;
    /* Backing allocation for aligned pml4 (used for release). */
    void *pml4_alloc_raw;
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
   If copy_old != 0, old page contents are copied before remap. */
int mm_make_private_range(mm_t *mm, uint64_t va_begin, uint64_t va_end, int copy_old);
