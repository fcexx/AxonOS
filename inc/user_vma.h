#pragma once

#include <stdint.h>
#include <stddef.h>
#include <thread.h>

#define USER_VMA_MAX 4096

enum {
    USER_VMA_KIND_MMAP = 1,
    USER_VMA_KIND_SHM = 2,
    USER_VMA_KIND_MMAP_LAZY = 3,
};

typedef struct {
    int used;
    uint64_t tid;
    uintptr_t addr;
    size_t len;
    int prot;
    int kind;
} user_vma_t;

void user_vma_remove_all_for_tid(uint64_t tid);
int user_vma_clone_for_tid(uint64_t from_tid, uint64_t to_tid);

/* Deep-copy mapped anon mmap pages into child mm at fork (Linux MAP_PRIVATE COW semantics). */
int user_vma_fork_privatize_mapped(mm_t *child_mm, uint64_t from_tid);

int user_vma_add(uint64_t tid, uintptr_t addr, size_t len, int prot, int kind);
void user_vma_unmap_range(uint64_t tid, uintptr_t addr, size_t len);
int user_vma_set_prot(uint64_t tid, uintptr_t addr, size_t len, int prot);
int user_vma_is_fully_mapped(uint64_t tid, uintptr_t addr, size_t len);

uintptr_t user_vma_max_mmap_like_end(uint64_t tid);
uintptr_t user_vma_max_mmap_like_end_for_mm(thread_t *runner);
uintptr_t user_vma_min_mmap_like_for_thread(thread_t *tcur, uintptr_t brk_base);
int user_vma_mmap_range_overlaps(thread_t *runner, uintptr_t addr, size_t len);

int user_vma_fault_lazy_anon(uint64_t cr2);
