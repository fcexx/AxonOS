#pragma once

#include <stddef.h>
#include <stdint.h>

// Initialize kernel heap. If start/size are zero, implementation chooses defaults.
void heap_init(uintptr_t heap_start, size_t heap_size);

void* kmalloc(size_t size);
void  kfree(void* ptr);
void* krealloc(void* ptr, size_t new_size);
void* kcalloc(size_t num, size_t size);

// Heap stats
size_t heap_total_bytes(void);
size_t heap_used_bytes(void);
size_t heap_peak_bytes(void);

/* Base virtual/physical address where the kernel heap starts (identity mapped). */
uintptr_t heap_base_addr(void);


