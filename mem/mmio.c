#include <axonos.h>
#include <stdint.h>
#include <stddef.h>
#include <spinlock.h>
#include <mmio.h>
#include <paging.h>
#include <vga.h>

#define MMIO_IDENTITY_LIMIT ((uint64_t)0x100000000ULL) /* 4GiB */
/* place MMIO pool at a high virtual address to avoid stomping low memory used
   by boot modules / initrd scanning. 0x08000000 == 128MiB aligned down to 2MiB. */
#define MMIO_POOL_SLOTS 64 /* 64 * 2MiB = 128MiB virtual pool */
#define MMIO_POOL_BASE_VA ((uintptr_t)0x08000000ULL)

static uint8_t mmio_slot_used[MMIO_POOL_SLOTS];
static uint16_t mmio_alloc_count[MMIO_POOL_SLOTS]; /* non-zero only at allocation start */
static spinlock_t mmio_pool_lock = { 0 };
static int mmio_inited = 0;

/* Configurable behavior:
   - Define MMIO_CACHE_ENABLED=1 to allow cached mappings (no PAT/PWT/PCD).
     By default MMIO uses uncached (PG_PCD|PG_PWT) for safety.
*/
#ifndef MMIO_CACHE_ENABLED
#define MMIO_CACHE_ENABLED 0
#endif

/* Map one physical address range `pa..pa+len-1` into kernel virtual space.
   Для pa < 4GiB возвращаем (void*)pa. Для >=4GiB выделяем подряд n слотов
   по 2MiB и делаем map_page_2m для каждой страницы.
*/
void *mmio_map_phys(uint64_t pa, size_t len) {
	if (len == 0) return NULL;

	/* fast path: fully below 4GiB -> identity */
	if (pa + (uint64_t)len <= MMIO_IDENTITY_LIMIT) {
		return (void*)(uintptr_t)pa;
	}

	/* align physical to 2MiB pages */
	uint64_t pa_page = pa & ~(PAGE_SIZE_2M - 1);
	size_t offset_in_page = (size_t)(pa - pa_page);
	size_t total = offset_in_page + len;
	size_t pages_needed = (total + PAGE_SIZE_2M - 1) / PAGE_SIZE_2M;
	if (pages_needed == 0 || pages_needed > MMIO_POOL_SLOTS) {
		kprintf("mmio: request too large pages_needed=%u\n", (unsigned)pages_needed);
		return NULL;
	}

	/* allocate contiguous slots */
	acquire(&mmio_pool_lock);
	int start = -1;
	for (int i = 0; i + (int)pages_needed <= MMIO_POOL_SLOTS; i++) {
		int ok = 1;
		for (size_t j = 0; j < pages_needed; j++) {
			if (mmio_slot_used[i + j]) { ok = 0; break; }
		}
		if (ok) { start = i; break; }
	}
	if (start < 0) {
		release(&mmio_pool_lock);
		//kprintf("mmio: no contiguous virtual slots available\n");
		return NULL;
	}

	/* reserve slots */
	for (size_t j = 0; j < pages_needed; j++) mmio_slot_used[start + j] = 1;
	mmio_alloc_count[start] = (uint16_t)pages_needed;
	release(&mmio_pool_lock);

	/* perform mapping per 2MiB page; rollback on failure */
	/* choose mapping flags based on cache preference */
#if MMIO_CACHE_ENABLED
	const uint64_t flags = PG_PRESENT | PG_RW;
#else
	const uint64_t flags = PG_PRESENT | PG_RW | PG_PCD | PG_PWT;
#endif
	for (size_t p = 0; p < pages_needed; p++) {
		uint64_t va_page = MMIO_POOL_BASE_VA + (uint64_t)(start + p) * PAGE_SIZE_2M;
		uint64_t pa_map = pa_page + p * PAGE_SIZE_2M;
		int r = map_page_2m(va_page, pa_map, flags);
		if (r != 0) {
			/* rollback: unmap previous mapped pages and free slots */
			for (size_t q = 0; q < p; q++) {
				uint64_t vaq = MMIO_POOL_BASE_VA + (uint64_t)(start + q) * PAGE_SIZE_2M;
				(void)unmap_page_2m((void*)vaq);
			}
			acquire(&mmio_pool_lock);
			for (size_t j = 0; j < pages_needed; j++) {
				mmio_slot_used[start + j] = 0;
				mmio_alloc_count[start + j] = 0;
			}
			release(&mmio_pool_lock);
			kprintf("mmio: map_page_2m failed for pa=0x%llx\n", (unsigned long long)pa);
			return NULL;
		}
	}

	/* return pointer with correct offset within first page */
	void *ret = (void*)( (char*)(uintptr_t)(MMIO_POOL_BASE_VA + (uint64_t)start * PAGE_SIZE_2M) + offset_in_page );
	return ret;
}

/* Unmap area previously returned by mmio_map_phys. For identity-mapped VA do nothing.
   For pooled mappings we unmap whole allocation stored in mmio_alloc_count.
*/
void mmio_unmap(void *va, size_t len) {
	if (!va) return;
	uintptr_t v = (uintptr_t)va;
	if (v + (uintptr_t)len <= MMIO_IDENTITY_LIMIT) return; /* identity region */

	uintptr_t pool_base = (uintptr_t)MMIO_POOL_BASE_VA;
	uintptr_t pool_end = pool_base + MMIO_POOL_SLOTS * PAGE_SIZE_2M;
	uintptr_t va_page = v & ~(PAGE_SIZE_2M - 1);
	if (va_page < pool_base || va_page >= pool_end) {
		/* not from our pool */
		return;
	}

	size_t idx = (va_page - pool_base) / PAGE_SIZE_2M;
	acquire(&mmio_pool_lock);
	uint16_t count = mmio_alloc_count[idx];
	if (count == 0) {
		/* nothing recorded at this slot */
		release(&mmio_pool_lock);
		return;
	}
	/* clear metadata first under lock */
	mmio_alloc_count[idx] = 0;
	for (size_t j = 0; j < count; j++) mmio_slot_used[idx + j] = 0;
	release(&mmio_pool_lock);

	/* unmap pages */
	for (size_t p = 0; p < count; p++) {
		uintptr_t vaq = pool_base + (idx + p) * PAGE_SIZE_2M;
		(void)unmap_page_2m((void*)vaq);
	}
}

/* Initialize mmio subsystem (idempotent). */
void mmio_init(void) {
	if (mmio_inited) return;
	acquire(&mmio_pool_lock);
	for (size_t i = 0; i < MMIO_POOL_SLOTS; i++) {
		mmio_slot_used[i] = 0;
		mmio_alloc_count[i] = 0;
	}
	mmio_inited = 1;
	kprintf("mmio: initialized with %u slots\n", (unsigned)MMIO_POOL_SLOTS);
	release(&mmio_pool_lock);
}

/* Return pool usage; 0 on success */
int mmio_pool_get_status(mmio_pool_status_t *out) {
	if (!out) return -1;
	mmio_init();
	acquire(&mmio_pool_lock);
	size_t used = 0;
	size_t best_free = 0;
	size_t cur_free = 0;
	for (size_t i = 0; i < MMIO_POOL_SLOTS; i++) {
		if (mmio_slot_used[i]) { used++; cur_free = 0; }
		else { cur_free++; if (cur_free > best_free) best_free = cur_free; }
	}
	out->slots_total = MMIO_POOL_SLOTS;
	out->slots_used = used;
	out->largest_free_run = best_free;
	release(&mmio_pool_lock);
	return 0;
}

/* используем volatile указатели чтобы избежать оптимизаций */
uint8_t mmio_read8(const volatile void *base, size_t offset) {
	const volatile uint8_t *p = (const volatile uint8_t *)((const char*)base + offset);
	return *p;
}

uint16_t mmio_read16(const volatile void *base, size_t offset) {
	const volatile uint16_t *p = (const volatile uint16_t *)((const char*)base + offset);
	return *p;
}

uint32_t mmio_read32(const volatile void *base, size_t offset) {
	const volatile uint32_t *p = (const volatile uint32_t *)((const char*)base + offset);
	return *p;
}

uint64_t mmio_read64(const volatile void *base, size_t offset) {
	const volatile uint64_t *p = (const volatile uint64_t *)((const char*)base + offset);
	return *p;
}

void mmio_write8(volatile void *base, size_t offset, uint8_t val) {
	volatile uint8_t *p = (volatile uint8_t *)((char*)base + offset);
	*p = val;
}

void mmio_write16(volatile void *base, size_t offset, uint16_t val) {
	volatile uint16_t *p = (volatile uint16_t *)((char*)base + offset);
	*p = val;
}

void mmio_write32(volatile void *base, size_t offset, uint32_t val) {
	volatile uint32_t *p = (volatile uint32_t *)((char*)base + offset);
	*p = val;
}

void mmio_write64(volatile void *base, size_t offset, uint64_t val) {
	volatile uint64_t *p = (volatile uint64_t *)((char*)base + offset);
	*p = val;
}
