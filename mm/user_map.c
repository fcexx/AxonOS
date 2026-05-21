#include <user_map.h>
#include <exec.h>
#include <mmio.h>
#include <paging.h>

#define USER_DATA_REGION_LO 0x200000ULL
#define USER_DATA_REGION_HI ((uint64_t)0x10000000ULL)

int user_map_unmap_range(uint64_t va_begin, uint64_t va_end) {
    if (va_end < va_begin) return -1;
    if (va_begin >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    uint64_t cr3 = paging_read_cr3();
    uint64_t *l4 = (uint64_t *)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!l4) return -1;
    for (uint64_t va = begin; va < end; va += 0x1000ULL) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        uint64_t l1i = (va >> 12) & 0x1FF;
        if (!(l4[l4i] & PG_PRESENT)) continue;
        uint64_t *l3 = (uint64_t *)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) continue;
        uint64_t l3e = l3[l3i];
        if (l3e & PG_PS_2M) continue;
        uint64_t l2_phys = l3e & ~0xFFFULL;
        uint64_t *l2 = (uint64_t *)(uintptr_t)l2_phys;
        if (!(l2[l2i] & PG_PRESENT)) continue;
        uint64_t l2e = l2[l2i];
        if (l2e & PG_PS_2M) {
            uint64_t page_lo = va & ~((uint64_t)(PAGE_SIZE_2M - 1));
            uint64_t page_hi = page_lo + PAGE_SIZE_2M;
            uint64_t l3_phys = l4[l4i] & ~0xFFFULL;
            uint64_t l4_phys = cr3 & ~0xFFFULL;
            if ((l2_phys >= page_lo && l2_phys < page_hi) ||
                (l3_phys >= page_lo && l3_phys < page_hi) ||
                (l4_phys >= page_lo && l4_phys < page_hi))
                continue;
            l2[l2i] = 0;
            invlpg((void *)(uintptr_t)va);
            continue;
        }
        uint64_t *l1 = (uint64_t *)(uintptr_t)(l2e & ~0xFFFULL);
        l1[l1i] = 0;
        invlpg((void *)(uintptr_t)va);
    }
    return 0;
}

int user_map_mprotect_range(uint64_t va_begin, uint64_t va_end, int prot) {
    if (va_end < va_begin) return -1;
    if (va_begin >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t begin = va_begin & ~((uint64_t)(PAGE_SIZE_2M - 1));
    uint64_t end = (va_end + PAGE_SIZE_2M - 1) & ~((uint64_t)(PAGE_SIZE_2M - 1));
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t cr3 = paging_read_cr3();
    uint64_t *l4 = (uint64_t *)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!l4) return -1;
    uint64_t new_flags = 0;
    if (prot != 0) {
        new_flags = PG_PRESENT | PG_US | PG_PS_2M;
        if (prot & 2) new_flags |= PG_RW;
        if (!(prot & 4)) new_flags |= PG_NX;
        if (va_begin < USER_DATA_REGION_HI && va_end > USER_DATA_REGION_LO)
            new_flags |= PG_RW;
    }
    for (uint64_t va = begin; va < end; va += PAGE_SIZE_2M) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        if (!(l4[l4i] & PG_PRESENT)) return -1;
        uint64_t *l3 = (uint64_t *)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) return -1;
        uint64_t l3e = l3[l3i];
        if (l3e & PG_PS_2M) return -1;
        uint64_t *l2 = (uint64_t *)(uintptr_t)(l3e & ~0xFFFULL);
        if (!(l2[l2i] & PG_PRESENT)) return -1;
        uint64_t l2e = l2[l2i];
        if (l2e & PG_PS_2M) {
            uint64_t pa = l2e & ~(PAGE_SIZE_2M - 1) & ~0xFFFULL;
            l2[l2i] = pa | new_flags;
        } else {
            uint64_t *l1 = (uint64_t *)(uintptr_t)(l2e & ~0xFFFULL);
            for (uint64_t v = va; v < va + PAGE_SIZE_2M && v < (uint64_t)MMIO_IDENTITY_LIMIT; v += 0x1000ULL) {
                uint64_t l1i = (v >> 12) & 0x1FF;
                uint64_t pa = l1[l1i] & ~0xFFFULL;
                uint64_t f = new_flags & ~PG_PS_2M;
                l1[l1i] = pa | f;
                invlpg((void *)(uintptr_t)v);
            }
        }
        invlpg((void *)(uintptr_t)va);
    }
    return 0;
}

int user_map_ensure_present_us_2m(uint64_t va_begin, uint64_t va_end) {
    if (va_end < va_begin) return -1;
    if (va_begin >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t begin = va_begin & ~((uint64_t)(PAGE_SIZE_2M - 1));
    uint64_t end = (va_end + PAGE_SIZE_2M - 1) & ~((uint64_t)(PAGE_SIZE_2M - 1));
    if (begin >= end) return -1;
    for (uint64_t va = begin; va < end; va += PAGE_SIZE_2M) {
        if (map_page_2m(va, va, PG_PRESENT | PG_RW | PG_US) != 0)
            return -1;
    }
    return 0;
}

int user_map_mark_identity_2m(uint64_t va_begin, uint64_t va_end) {
    if (va_end < va_begin) return -1;
    uint64_t cr3 = paging_read_cr3();
    uint64_t *active_l4 = (uint64_t *)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!active_l4) return -1;
    uint64_t begin = va_begin & ~((uint64_t)(PAGE_SIZE_2M - 1));
    uint64_t end = (va_end + PAGE_SIZE_2M - 1) & ~((uint64_t)(PAGE_SIZE_2M - 1));
    for (uint64_t va = begin; va < end; va += PAGE_SIZE_2M) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        uint64_t *l4 = active_l4;
        if (!(l4[l4i] & PG_PRESENT)) return -1;
        l4[l4i] |= PG_US | PG_RW;
        l4[l4i] &= ~PG_NX;
        uint64_t *l3 = (uint64_t *)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) return -1;
        l3[l3i] |= PG_US | PG_RW;
        l3[l3i] &= ~PG_NX;
        uint64_t l3e = l3[l3i];
        if (l3e & PG_PS_2M) {
            l3[l3i] |= PG_US | PG_RW;
            l3[l3i] &= ~PG_NX;
            invlpg((void *)(uintptr_t)va);
            continue;
        }
        uint64_t *l2 = (uint64_t *)(uintptr_t)(l3e & ~0xFFFULL);
        if (!(l2[l2i] & PG_PRESENT)) return -1;
        l2[l2i] |= PG_US | PG_RW;
        l2[l2i] &= ~PG_NX;
        uint64_t l2e = l2[l2i];
        if (l2e & PG_PS_2M) {
            l2[l2i] = (l2e | PG_US | PG_RW) & ~PG_NX;
            invlpg((void *)(uintptr_t)va);
            continue;
        }
        uint64_t *l1 = (uint64_t *)(uintptr_t)(l2e & ~0xFFFULL);
        l1[(va >> 12) & 0x1FF] |= PG_US | PG_RW;
        l1[(va >> 12) & 0x1FF] &= ~PG_NX;
        invlpg((void *)(uintptr_t)va);
    }
    return 0;
}
