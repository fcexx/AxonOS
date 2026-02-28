#pragma once

#include <stdint.h>
#include <stddef.h>

// Page size and table constants
#define PAGE_SIZE_4K             4096ULL
#define PAGE_SIZE_2M             (2ULL * 1024 * 1024)
#define PT_ENTRIES               512ULL

// Paging flags (x86_64 long mode)
#define PG_PRESENT               (1ULL << 0)
#define PG_RW                    (1ULL << 1)
#define PG_US                    (1ULL << 2)
#define PG_PWT                   (1ULL << 3)
#define PG_PCD                   (1ULL << 4)
#define PG_ACCESSED              (1ULL << 5)
#define PG_DIRTY                 (1ULL << 6)
#define PG_PS_2M                 (1ULL << 7)   // set in PD entry for 2MiB page
#define PG_GLOBAL                (1ULL << 8)
#define PG_NX                    (1ULL << 63)  // if EFER.NXE is enabled

// Initialize paging helpers (assumes bootstrap tables are already active)
void paging_init(void);

// Map one 2MiB page at 'va' to physical 'pa' with flags (PG_PRESENT|PG_RW|...)
// Returns 0 on success, <0 on error.
int map_page_2m(uint64_t va, uint64_t pa, uint64_t flags);

// Unmap one 2MiB page at 'va'. No free of frames; only removes mapping.
int unmap_page_2m(uint64_t va);

// Invalidate TLB for given virtual address
void invlpg(void* va);

/* Raw CR3 access helpers for scheduler/mm switching. */
uint64_t paging_read_cr3(void);
void paging_write_cr3(uint64_t v);


