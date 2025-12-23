#include <heap.h>
#include <string.h>
#include <stdint.h>
#include <vga.h>

// Very simple kernel heap: first-fit free list with headers, 16-byte alignment,
// coalescing on free. No thread safety assumed (callers should serialize).

typedef struct heap_block_header {
    size_t size;                 // payload size (bytes)
    struct heap_block_header* next;
    struct heap_block_header* prev;
    uint32_t magic;
    uint32_t free;
    size_t req_size;             // requested size (before alignment), for diagnostics
} heap_block_header_t;

#define ALIGN16(x)   (((x) + 15) & ~((size_t)15))

static uint8_t* heap_base = 0;
static size_t   heap_capacity = 0;
static heap_block_header_t* head = 0;

static size_t heap_used_now = 0;
static size_t heap_peak     = 0;

extern uint8_t _end[]; // provided by linker as end of kernel image

#ifndef HEAP_GUARD
#define HEAP_GUARD 1
#endif

#define HEAP_MAGIC_FREE  0xC0FFEE00u
#define HEAP_MAGIC_ALLOC 0xC0FFEE01u
#define HEAP_CANARY_QWORD 0xDEADBEEFCAFEBABEULL

static int heap_ptr_in_range(const void *p) {
    if (!heap_base || heap_capacity == 0) return 0;
    uintptr_t a = (uintptr_t)p;
    uintptr_t lo = (uintptr_t)heap_base;
    uintptr_t hi = (uintptr_t)heap_base + heap_capacity;
    return (a >= lo && a < hi);
}

static int heap_range_in_range(const void *p, size_t n) {
    if (!heap_base || heap_capacity == 0) return 0;
    if (n == 0) return heap_ptr_in_range(p);
    uintptr_t a = (uintptr_t)p;
    uintptr_t lo = (uintptr_t)heap_base;
    uintptr_t hi = (uintptr_t)heap_base + heap_capacity;
    /* check [a, a+n) fits in [lo, hi) without overflow */
    if (a < lo) return 0;
    if (a > hi) return 0;
    if (n > (size_t)(hi - a)) return 0;
    return 1;
}

void heap_init(uintptr_t heap_start, size_t heap_size) {
    if (heap_start == 0) {
        // Default: place heap right after kernel end, align to 16 bytes
        uintptr_t base = ((uintptr_t)_end + 0xFFF) & ~((uintptr_t)0xFFF);
        heap_start = base;
    }
    if (heap_size == 0) {
        // Default size: 16 MiB
        heap_size = 16ULL * 1024 * 1024;
    }

    heap_base = (uint8_t*)heap_start;
    heap_capacity = heap_size;

    head = (heap_block_header_t*)heap_base;
    head->size = heap_capacity - sizeof(heap_block_header_t);
    head->next = 0;
    head->prev = 0;
    head->free = 1;
    head->magic = HEAP_MAGIC_FREE;
    head->req_size = 0;

    heap_used_now = 0;
    heap_peak = 0;
}

static void split_block(heap_block_header_t* blk, size_t size) {
    size_t remaining = blk->size - size;
    if (remaining <= sizeof(heap_block_header_t) + 16) return; // too small to split
    heap_block_header_t* newblk = (heap_block_header_t*)((uint8_t*)blk + sizeof(heap_block_header_t) + size);
    newblk->size = remaining - sizeof(heap_block_header_t);
    newblk->free = 1;
    newblk->magic = HEAP_MAGIC_FREE;
    newblk->req_size = 0;
    newblk->next = blk->next;
    newblk->prev = blk;
    if (newblk->next) newblk->next->prev = newblk;
    blk->next = newblk;
    blk->size = size;
}

static void coalesce(heap_block_header_t* blk) {
    // merge with next
    if (blk->next && blk->next->free) {
        blk->size += sizeof(heap_block_header_t) + blk->next->size;
        blk->next = blk->next->next;
        if (blk->next) blk->next->prev = blk;
    }
    // merge with prev
    if (blk->prev && blk->prev->free) {
        blk->prev->size += sizeof(heap_block_header_t) + blk->size;
        blk->prev->next = blk->next;
        if (blk->next) blk->next->prev = blk->prev;
        blk = blk->prev;
    }
    blk->magic = HEAP_MAGIC_FREE;
    blk->req_size = 0;
}

void* kmalloc(size_t size) {
    if (!head || size == 0) return 0;
    size_t req = size;
#if HEAP_GUARD
    size = ALIGN16(req + sizeof(uint64_t));
#else
    size = ALIGN16(req);
#endif
    heap_block_header_t* cur = head;
    while (cur) {
        if (cur->free && cur->size >= size) {
            split_block(cur, size);
            cur->free = 0;
            cur->magic = HEAP_MAGIC_ALLOC;
            cur->req_size = req;
            heap_used_now += cur->size;
            if (heap_used_now > heap_peak) heap_peak = heap_used_now;
            uint8_t *p = (uint8_t*)cur + sizeof(heap_block_header_t);
#if HEAP_GUARD
            /* Write canary right after requested bytes. */
            uint64_t v = (uint64_t)HEAP_CANARY_QWORD;
            memcpy(p + req, &v, sizeof(v));
#endif
            return p;
        }
        cur = cur->next;
    }
    return 0; // out of memory
}

void kfree(void* ptr) {
    if (!ptr) return;
    if (!heap_ptr_in_range(ptr)) {
        kprintf("heap: invalid free ptr=%p (out of heap range)\n", ptr);
        return;
    }
    heap_block_header_t* blk = (heap_block_header_t*)((uint8_t*)ptr - sizeof(heap_block_header_t));
    if (!heap_ptr_in_range(blk)) {
        kprintf("heap: invalid free header ptr=%p\n", (void*)blk);
        return;
    }
    if (blk->magic != HEAP_MAGIC_ALLOC || blk->free) {
        kprintf("heap: double free / corrupt header ptr=%p magic=0x%x free=%u\n",
                ptr, (unsigned)blk->magic, (unsigned)blk->free);
        /* print caller address to help locate the double-free site */
        void *caller = __builtin_return_address(0);
        kprintf("    caller: %p\n", caller);
        /* print header diagnostics */
        kprintf("    hdr: addr=%p size=%u req=%u prev=%p next=%p\n",
                (void*)blk, (unsigned)blk->size, (unsigned)blk->req_size,
                (void*)blk->prev, (void*)blk->next);
        return;
    }
#if HEAP_GUARD
    {
        uint8_t *p = (uint8_t*)ptr;
        const uint8_t *canp = (const uint8_t*)(p + blk->req_size);
        uint64_t got = 0;
        if (!heap_range_in_range(canp, sizeof(uint64_t))) got = 0;
        else memcpy(&got, canp, sizeof(got));
        if (got != (uint64_t)HEAP_CANARY_QWORD) {
            kprintf("heap: overflow detected ptr=%p req=%u can=%p\n",
                    ptr, (unsigned)blk->req_size, (void*)canp);
            void *caller = __builtin_return_address(0);
            kprintf("    caller: %p\n", caller);
        }
    }
#endif
    blk->free = 1;
    blk->magic = HEAP_MAGIC_FREE;
    if (heap_used_now >= blk->size) heap_used_now -= blk->size; else heap_used_now = 0;
    coalesce(blk);
}

void* krealloc(void* ptr, size_t new_size) {
    if (!ptr) return kmalloc(new_size);
    if (new_size == 0) { kfree(ptr); return 0; }
    if (!heap_ptr_in_range(ptr)) {
        kprintf("heap: invalid realloc ptr=%p\n", ptr);
        return 0;
    }
    heap_block_header_t* blk = (heap_block_header_t*)((uint8_t*)ptr - sizeof(heap_block_header_t));
    if (!heap_ptr_in_range(blk) || blk->magic != HEAP_MAGIC_ALLOC || blk->free) {
        kprintf("heap: invalid realloc header ptr=%p magic=0x%x free=%u\n",
                ptr, (unsigned)(blk ? blk->magic : 0), (unsigned)(blk ? blk->free : 0));
        return 0;
    }
    size_t old_size = blk->size;
    size_t old_req = blk->req_size;
    size_t new_req = new_size;
#if HEAP_GUARD
    new_size = ALIGN16(new_req + sizeof(uint64_t));
#else
    new_size = ALIGN16(new_req);
#endif
    if (new_size <= old_size) {
        split_block(blk, new_size);
        size_t diff = old_size - new_size;
        if (heap_used_now >= diff) heap_used_now -= diff; else heap_used_now = 0;
#if HEAP_GUARD
        /* refresh canary at the new requested end */
        blk->req_size = new_req;
        uint8_t *p = (uint8_t*)blk + sizeof(heap_block_header_t);
        uint64_t v = (uint64_t)HEAP_CANARY_QWORD;
        memcpy(p + new_req, &v, sizeof(v));
#else
        blk->req_size = new_req;
#endif
        return ptr;
    }
    // try to grow in place if next is free and large enough
    if (blk->next && blk->next->free && old_size + sizeof(heap_block_header_t) + blk->next->size >= new_size) {
        blk->size += sizeof(heap_block_header_t) + blk->next->size;
        blk->next = blk->next->next;
        if (blk->next) blk->next->prev = blk;
        split_block(blk, new_size);
        size_t diff = new_size - old_size;
        heap_used_now += diff;
        if (heap_used_now > heap_peak) heap_peak = heap_used_now;
#if HEAP_GUARD
        blk->req_size = new_req;
        uint8_t *p = (uint8_t*)blk + sizeof(heap_block_header_t);
        uint64_t v = (uint64_t)HEAP_CANARY_QWORD;
        memcpy(p + new_req, &v, sizeof(v));
#else
        blk->req_size = new_req;
#endif
        return ptr;
    }
    void* n = kmalloc(new_req);
    if (!n) return 0;
    size_t to_copy = old_req < new_req ? old_req : new_req;
    memcpy(n, ptr, to_copy);
    kfree(ptr);
    return n;
}

void* kcalloc(size_t num, size_t size) {
    size_t total = num * size;
    void* p = kmalloc(total);
    if (p) memset(p, 0, total);
    return p;
}

size_t heap_total_bytes(void) { return heap_capacity; }
size_t heap_used_bytes(void)  { return heap_used_now; }
size_t heap_peak_bytes(void)  { return heap_peak; }


