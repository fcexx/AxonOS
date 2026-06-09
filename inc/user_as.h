#pragma once

#include <stdint.h>
#include <thread.h>

/* Per-mm anonymous mmap cursor (fallback when no thread_t). */
extern uintptr_t user_as_mmap_next;
extern uintptr_t user_as_mmap_hi;
extern uintptr_t user_as_brk_base;
extern uintptr_t user_as_brk_cur;

uintptr_t user_as_stack_top_for_tid(uint64_t tid);
uintptr_t user_as_mmap_brk_top_limit(thread_t *tcur);

uintptr_t user_as_shared_max_mmap_next(thread_t *cur, uintptr_t fallback);
uintptr_t user_as_shared_max_brk_cur(thread_t *cur, uintptr_t fallback);
uintptr_t user_as_shared_pick_brk_base(thread_t *cur, uintptr_t fallback);
void user_as_shared_publish_brk(thread_t *cur, uintptr_t base, uintptr_t cur_brk);
void user_as_shared_publish_mmap(thread_t *cur, uintptr_t next, uintptr_t hi);

int user_as_mmap_overlaps_kernel_heap(uintptr_t addr, uintptr_t len);
/* True if [addr,addr+len) hits the thread stack (including live RSP..stack_top). */
int user_as_mmap_overlaps_user_stack(thread_t *t, uintptr_t addr, uintptr_t len,
    uintptr_t *above_stack_out);
void user_as_mmap_memset_zero_chunked(uintptr_t addr, size_t len);
void user_as_mmap_lazy_drop_present_pages(uintptr_t addr, size_t len);

void user_as_reset_on_exec(thread_t *tcur, uintptr_t brk_base);
/* Set program break after ELF load; zero [image_hi,brk) so glibc heap metadata is clean. */
void user_as_set_brk_after_load(thread_t *tcur, uintptr_t elf_brk, uintptr_t image_hi);
/* Tear down prior mmap/brk/ELF mappings before loading a new program (Linux execve). */
void user_as_teardown_for_exec(thread_t *tcur, uintptr_t new_brk_base);
