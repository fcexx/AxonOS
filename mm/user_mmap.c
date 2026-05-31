#include <user_mmap.h>
#include <user_vma.h>
#include <user_as.h>
#include <user_map.h>
#include <user_mm.h>
#include <exec.h>
#include <fs.h>
#include <thread.h>
#include <heap.h>
#include <mmio.h>
#include <paging.h>
#include <debug.h>
#include <klog.h>
#include <fbdev.h>
#include <string.h>
#include <axonos.h>

extern void kprintf(const char *fmt, ...);

static int user_mmap_watch(thread_t *t) {
    if (!t || !t->name[0]) return 0;
    return (strstr(t->name, "wget") || strstr(t->name, "busybox") || strstr(t->name, "uget") ||
            strstr(t->name, "adduser") || strstr(t->name, "addgroup")) ? 1 : 0;
}

enum {
    MAP_FIXED = 0x10,
    MAP_ANONYMOUS = 0x20,
    MAP_PRIVATE = 0x02,
    MAP_SHARED = 0x01,
    MAP_FIXED_NOREPLACE = 0x100000,
};

uint64_t user_syscall_mmap(thread_t *cur, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6) {
    uintptr_t req_addr = (uintptr_t)a1;
    uint64_t len_u64 = (uint64_t)a2;
    int prot = (int)a3;
    int flags = (int)a4;
    (void)prot;

    if (len_u64 == 0) return user_mm_ret_err(USER_MM_EINVAL);
    if (user_mm_len_exceeds_cap(len_u64)) {
        kprintf("mmap: ENOMEM raw len 0x%llx >= cap 0x10000000\n", (unsigned long long)len_u64);
        klogprintf("mmap: ENOMEM raw len 0x%llx >= cap 0x10000000\n", (unsigned long long)len_u64);
        return user_mm_ret_err(USER_MM_ENOMEM);
    }
    len_u64 = (len_u64 + 4095ull) & ~4095ull;
    if (len_u64 > (uint64_t)((size_t)-1)) return user_mm_ret_err(USER_MM_EINVAL);
    if (user_mm_len_exceeds_cap(len_u64)) {
        kprintf("mmap: ENOMEM len 0x%llx >= cap 0x10000000\n", (unsigned long long)len_u64);
        klogprintf("mmap: ENOMEM len 0x%llx >= cap 0x10000000\n", (unsigned long long)len_u64);
        return user_mm_ret_err(USER_MM_ENOMEM);
    }
    size_t len = (size_t)len_u64;

    int fixed_mapping = (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) ? 1 : 0;
    if (!(flags & (MAP_PRIVATE | MAP_SHARED))) return user_mm_ret_err(USER_MM_ENOSYS);

    thread_t *tcur = thread_get_current_user();
    if (!tcur) tcur = thread_current();

    uintptr_t top_limit = user_as_mmap_brk_top_limit(tcur);
    if (top_limit > (uintptr_t)USER_STACK_TOP)
        top_limit = (uintptr_t)USER_STACK_TOP;

    uintptr_t *p_mmap_next = tcur ? &tcur->user_mmap_next : &user_as_mmap_next;
    uintptr_t shared_next = tcur ? user_as_shared_max_mmap_next(tcur, *p_mmap_next) : *p_mmap_next;
    if (shared_next > *p_mmap_next) *p_mmap_next = shared_next;
    if (*p_mmap_next >= top_limit) *p_mmap_next = 0;

    if (tcur) {
        uintptr_t vma_hi = user_vma_max_mmap_like_end_for_mm(tcur);
        if (vma_hi > *p_mmap_next) {
            if (vma_hi < top_limit) *p_mmap_next = vma_hi;
            else *p_mmap_next = 0;
        }
    }

    uintptr_t brk_cur_for_mmap = tcur ? user_as_shared_max_brk_cur(tcur, tcur->user_brk_cur) : user_as_brk_cur;
    if (brk_cur_for_mmap == 0) brk_cur_for_mmap = 8u * 1024u * 1024u;
    uintptr_t brk_guard_floor = user_mm_align_up(brk_cur_for_mmap + 0x10000u, 4096);

    if (len_u64 > (uint64_t)top_limit) {
        kprintf("mmap: ENOMEM len 0x%llx > top_limit 0x%llx\n",
            (unsigned long long)len_u64, (unsigned long long)top_limit);
        return user_mm_ret_err(USER_MM_ENOMEM);
    }

    if (user_mmap_watch(tcur)) {
        kprintf("mmap-enter: pid=%s tid=%llu len=0x%016llx (~%lluMiB) USER_STACK_TOP=0x%016llx next=0x%016llx brk=0x%016llx floor=0x%016llx stk=[0x%016llx..0x%016llx] top=0x%016llx\n",
            tcur->name, (unsigned long long)(tcur->tid ? tcur->tid : 1),
            (unsigned long long)len_u64, (unsigned long long)(len_u64 >> 20),
            (unsigned long long)(uint64_t)USER_STACK_TOP, (unsigned long long)*p_mmap_next,
            (unsigned long long)brk_cur_for_mmap, (unsigned long long)brk_guard_floor,
            (unsigned long long)(tcur ? tcur->user_stack_base : 0),
            (unsigned long long)(tcur ? tcur->user_stack_limit : 0),
            (unsigned long long)top_limit);
    }

    if (*p_mmap_next == 0) {
        uintptr_t def = 32u * 1024u * 1024u;
        if (def >= top_limit && top_limit > (8u * 1024u * 1024u)) {
            def = user_mm_align_up(top_limit / 2u, 4096);
            if (def < (8u * 1024u * 1024u)) def = 8u * 1024u * 1024u;
        }
        if (def < brk_guard_floor) def = brk_guard_floor;
        *p_mmap_next = def;
    }
    if (*p_mmap_next < brk_guard_floor) *p_mmap_next = brk_guard_floor;

    if (tcur && tcur->user_stack_base != 0 && tcur->user_stack_limit > tcur->user_stack_base) {
        uintptr_t se = (uintptr_t)tcur->user_stack_limit;
        uintptr_t min_alloc = user_mm_align_up(se, PAGE_SIZE_2M);
        if (tcur->user_fs_base > se && tcur->user_fs_base < (uintptr_t)MMIO_IDENTITY_LIMIT) {
            uintptr_t tls_min = user_mm_align_up((uintptr_t)tcur->user_fs_base + 0x3000u, PAGE_SIZE_2M);
            if (tls_min > min_alloc) min_alloc = tls_min;
        }
        if (min_alloc < top_limit && *p_mmap_next < min_alloc)
            *p_mmap_next = min_alloc;
        else if (*p_mmap_next >= top_limit)
            *p_mmap_next = brk_guard_floor;
    }

    uintptr_t addr = fixed_mapping ? req_addr : user_mm_align_up(*p_mmap_next, 4096);
    if (fixed_mapping && (addr & 0xFFFu) != 0) return user_mm_ret_err(USER_MM_EINVAL);
    if (fixed_mapping && user_as_mmap_overlaps_kernel_heap(addr, len))
        return user_mm_ret_err(USER_MM_EINVAL);

    if (!fixed_mapping && tcur && user_as_mmap_overlaps_user_stack(tcur, addr, (uintptr_t)len_u64, NULL)) {
        uintptr_t above_stack = 0;
        (void)user_as_mmap_overlaps_user_stack(tcur, addr, (uintptr_t)len_u64, &above_stack);
        if (above_stack > addr && user_mm_range_fits(above_stack, len_u64, top_limit)) {
            addr = above_stack;
            *p_mmap_next = addr;
        } else {
            kprintf("mmap: ENOMEM overlaps user stack rsp=0x%llx stk=[0x%llx..0x%llx] addr=0x%llx len=0x%llx\n",
                (unsigned long long)(uint64_t)syscall_user_rsp_saved,
                (unsigned long long)tcur->user_stack_base,
                (unsigned long long)tcur->user_stack_limit,
                (unsigned long long)addr, (unsigned long long)len_u64);
            return user_mm_ret_err(USER_MM_ENOMEM);
        }
    }
    if (!fixed_mapping) {
        if (addr < brk_guard_floor) {
            addr = brk_guard_floor;
            *p_mmap_next = brk_guard_floor;
        }
    }
    if (addr < brk_guard_floor) return user_mm_ret_err(USER_MM_EINVAL);
    if (!fixed_mapping && user_as_mmap_overlaps_kernel_heap(addr, len)) {
        const uintptr_t hgap = 0x10000u;
        uintptr_t hhi = heap_region_end_exclusive();
        uintptr_t skip = user_mm_align_up(hhi + hgap, 4096);
        if (skip >= top_limit || skip >= (uintptr_t)USER_TLS_BASE) {
            kprintf("mmap: ENOMEM overlap kernel heap (heap above user VA cap)\n");
            return user_mm_ret_err(USER_MM_ENOMEM);
        }
        addr = skip;
        *p_mmap_next = addr;
        if ((uint64_t)addr + len_u64 < (uint64_t)addr) return user_mm_ret_err(USER_MM_ENOMEM);
        if (tcur && user_as_mmap_overlaps_user_stack(tcur, addr, (uintptr_t)len_u64, NULL)) {
            uintptr_t above_stack = 0;
            (void)user_as_mmap_overlaps_user_stack(tcur, addr, (uintptr_t)len_u64, &above_stack);
            if (above_stack > addr && user_mm_range_fits(above_stack, len_u64, top_limit)) {
                addr = above_stack;
                *p_mmap_next = addr;
            } else {
                return user_mm_ret_err(USER_MM_ENOMEM);
            }
        }
        if (addr < brk_guard_floor) return user_mm_ret_err(USER_MM_EINVAL);
        if (user_as_mmap_overlaps_kernel_heap(addr, len)) {
            kprintf("mmap: ENOMEM mmap still overlaps kernel heap after skip\n");
            return user_mm_ret_err(USER_MM_ENOMEM);
        }
    }

    if (!user_mm_range_fits(addr, len_u64, top_limit)) {
        kprintf("mmap: ENOMEM span_end=0x%llx cap=0x%llx\n",
            (unsigned long long)((uint64_t)addr + len_u64), (unsigned long long)top_limit);
        return user_mm_ret_err(USER_MM_ENOMEM);
    }
    if (user_mm_len_exceeds_cap(len_u64)) return user_mm_ret_err(USER_MM_ENOMEM);

    if (tcur && user_as_mmap_overlaps_user_stack(tcur, addr, (uintptr_t)len_u64, NULL)) {
        kprintf("mmap: ENOMEM still overlaps user stack addr=0x%llx len=0x%llx\n",
            (unsigned long long)addr, (unsigned long long)len_u64);
        return user_mm_ret_err(USER_MM_ENOMEM);
    }

    uintptr_t map_hwm = top_limit & ~((uintptr_t)PAGE_SIZE_2M - 1);
    if (addr < 0x200000 || (uint64_t)addr + len_u64 > (uint64_t)USER_STACK_TOP) {
        if (addr >= (uintptr_t)USER_TLS_BASE ||
            (uint64_t)addr + len_u64 > (uint64_t)USER_TLS_BASE ||
            user_as_mmap_overlaps_kernel_heap(addr, len))
            return user_mm_ret_err(USER_MM_ENOMEM);
        if (user_map_mark_identity_2m((uint64_t)addr, (uint64_t)addr + len_u64) != 0)
            return user_mm_ret_err(USER_MM_EFAULT);
    } else if (tcur && tcur->user_stack_base != 0) {
        uintptr_t map_begin = addr & ~((uintptr_t)PAGE_SIZE_2M - 1);
        uintptr_t map_end = (uintptr_t)(((uint64_t)addr + len_u64 + PAGE_SIZE_2M - 1) & ~(PAGE_SIZE_2M - 1));
        if (map_end > map_hwm) map_end = map_hwm;
        if (map_begin >= map_end) return user_mm_ret_err(USER_MM_ENOMEM);
        for (uintptr_t va = map_begin; va < map_end; va += PAGE_SIZE_2M) {
            if (map_page_2m(va, va, PG_PRESENT | PG_RW | PG_US) != 0)
                return user_mm_ret_err(USER_MM_EFAULT);
        }
    } else if (addr >= 0x200000 && (uint64_t)addr + len_u64 <= (uint64_t)USER_STACK_TOP) {
        uintptr_t map_begin = addr & ~((uintptr_t)PAGE_SIZE_2M - 1);
        uintptr_t map_end = (uintptr_t)(((uint64_t)addr + len_u64 + PAGE_SIZE_2M - 1) & ~(PAGE_SIZE_2M - 1));
        if (map_end > map_hwm) map_end = map_hwm;
        if (map_begin >= map_end) return user_mm_ret_err(USER_MM_ENOMEM);
        for (uintptr_t va = map_begin; va < map_end; va += PAGE_SIZE_2M) {
            if (map_page_2m(va, va, PG_PRESENT | PG_RW | PG_US) != 0)
                return user_mm_ret_err(USER_MM_EFAULT);
        }
    }

    int mmap_vma_kind = USER_VMA_KIND_MMAP;
    if (flags & MAP_ANONYMOUS) {
        flags &= ~(MAP_ANONYMOUS | MAP_PRIVATE | MAP_SHARED | MAP_FIXED | MAP_FIXED_NOREPLACE);
        if (flags != 0) return user_mm_ret_err(USER_MM_ENOSYS);
        const int lazy_anon = (len_u64 > (96ull << 20)) &&
            ((addr & ((uintptr_t)PAGE_SIZE_2M - 1)) == 0) &&
            ((len_u64 & ((uint64_t)PAGE_SIZE_2M - 1)) == 0);
        if (lazy_anon) {
            mmap_vma_kind = USER_VMA_KIND_MMAP_LAZY;
            user_as_mmap_lazy_drop_present_pages(addr, len);
        } else {
            user_as_mmap_memset_zero_chunked(addr, len);
        }
    } else {
        int fd = (int)(int64_t)a5;
        off_t file_off = (off_t)(int64_t)a6;
        if (fd < 0 || fd >= THREAD_MAX_FD) return user_mm_ret_err(USER_MM_EBADF);
        struct fs_file *f = cur->fds[fd];
        if (!f) return user_mm_ret_err(USER_MM_EBADF);
        if (f->type != FS_TYPE_REG) return user_mm_ret_err(USER_MM_EBADF);
        if (fbdev_is_fb0_file(f)) {
            if (!fbdev_is_active()) return user_mm_ret_err(USER_MM_ENODEV);
            if (file_off < 0) return user_mm_ret_err(USER_MM_EINVAL);
            size_t fo = (size_t)file_off;
            if (fo > f->size) return user_mm_ret_err(USER_MM_EINVAL);
            size_t maxl = f->size - fo;
            size_t maplen = len < maxl ? len : maxl;
            if (maplen > 0 && fbdev_mmap_user(addr, maplen, fo) != 0)
                return user_mm_ret_err(USER_MM_EFAULT);
        } else {
            user_as_mmap_memset_zero_chunked(addr, len);
            size_t file_avail = 0;
            if ((size_t)file_off < f->size) file_avail = f->size - (size_t)file_off;
            size_t to_read = len < file_avail ? len : file_avail;
            if (to_read > 0)
                (void)fs_read(f, (void *)addr, to_read, (size_t)file_off);
        }
    }

    uint64_t vtid = (uint64_t)(tcur ? (tcur->tid ? tcur->tid : 1) : 1);
    if (!fixed_mapping && user_vma_mmap_range_overlaps(tcur, addr, len)) {
        kprintf("mmap: ENOMEM overlap addr=0x%llx len=0x%llx\n",
            (unsigned long long)addr, (unsigned long long)len_u64);
        return user_mm_ret_err(USER_MM_ENOMEM);
    }
    if (user_vma_add(vtid, addr, len, prot & 7, mmap_vma_kind) != 0)
        return user_mm_ret_err(USER_MM_ENOSPC);

    uint64_t sum_next = (uint64_t)addr + len_u64;
    if (sum_next < (uint64_t)addr || sum_next > (uint64_t)top_limit)
        return user_mm_ret_err(USER_MM_ENOMEM);
    if (!fixed_mapping)
        *p_mmap_next = (uintptr_t)sum_next;
    else if ((uint64_t)*p_mmap_next < sum_next)
        *p_mmap_next = (uintptr_t)sum_next;

    uint64_t he64 = (uint64_t)addr + len_u64;
    if (tcur) {
        if (he64 > tcur->user_mmap_hi) tcur->user_mmap_hi = (uintptr_t)he64;
        user_as_shared_publish_mmap(tcur, *p_mmap_next, (uintptr_t)he64);
    } else if (he64 > user_as_mmap_hi) {
        user_as_mmap_hi = (uintptr_t)he64;
    }

    if (user_mmap_watch(tcur)) {
        kprintf("mmap: pid=%s tid=%llu addr=0x%016llx len=0x%016llx end=0x%016llx next=0x%016llx top=0x%016llx\n",
            tcur->name, (unsigned long long)(tcur->tid ? tcur->tid : 1),
            (unsigned long long)addr, (unsigned long long)len_u64, (unsigned long long)he64,
            (unsigned long long)*p_mmap_next, (unsigned long long)top_limit);
    }
    if (!user_mm_range_fits(addr, len_u64, top_limit))
        return user_mm_ret_err(USER_MM_ENOMEM);
    if (user_as_mmap_overlaps_kernel_heap(addr, len))
        return user_mm_ret_err(USER_MM_EFAULT);
    return (uint64_t)addr;
}

uint64_t user_syscall_munmap(uint64_t a1, uint64_t a2) {
    uintptr_t addr = (uintptr_t)a1;
    size_t len = (size_t)a2;
    if (len == 0) return 0;
    len = (size_t)user_mm_align_up((uintptr_t)len, 4096);
    if (addr < 0x200000) return user_mm_ret_err(USER_MM_EINVAL);
    if (addr + len >= (uintptr_t)MMIO_IDENTITY_LIMIT) return user_mm_ret_err(USER_MM_EINVAL);
    if ((addr & 0xFFF) != 0) return user_mm_ret_err(USER_MM_EINVAL);

    thread_t *tcur = thread_get_current_user();
    if (!tcur) tcur = thread_current();
    uint64_t tid = (uint64_t)(tcur ? (tcur->tid ? tcur->tid : 1) : 1);
    user_vma_unmap_range(tid, addr, len);
    uintptr_t max_end = tcur ? user_vma_max_mmap_like_end_for_mm(tcur) : user_vma_max_mmap_like_end(tid);
    if (tcur) {
        uintptr_t floor = user_mm_align_up(
            (tcur->user_brk_cur ? tcur->user_brk_cur : (8u * 1024u * 1024u)) + 0x10000u, 4096);
        if (max_end < floor) max_end = floor;
        if (tcur->mm) {
            int n = thread_get_count();
            for (int i = 0; i < n; i++) {
                thread_t *pt = thread_get_by_index(i);
                if (!pt || pt->ring != 3 || pt->mm != tcur->mm) continue;
                if (pt->user_mmap_next > max_end) pt->user_mmap_next = max_end;
                if (pt->user_mmap_hi > pt->user_mmap_next) pt->user_mmap_hi = pt->user_mmap_next;
            }
        } else {
            if (tcur->user_mmap_next > max_end) tcur->user_mmap_next = max_end;
            if (tcur->user_mmap_hi > tcur->user_mmap_next) tcur->user_mmap_hi = tcur->user_mmap_next;
        }
    }
    return 0;
}

uint64_t user_syscall_mprotect(uint64_t a1, uint64_t a2, uint64_t a3) {
    uintptr_t addr = (uintptr_t)a1;
    size_t len = (size_t)a2;
    int prot = (int)a3;
    if (len == 0) return 0;
    len = (size_t)user_mm_align_up((uintptr_t)len, 4096);
    if (addr < 0x200000) return user_mm_ret_err(USER_MM_EINVAL);
    if (addr + len >= (uintptr_t)MMIO_IDENTITY_LIMIT) return user_mm_ret_err(USER_MM_EINVAL);
    if ((addr & 0xFFF) != 0) return user_mm_ret_err(USER_MM_EINVAL);
    if ((prot & ~7) != 0) return user_mm_ret_err(USER_MM_EINVAL);

    thread_t *tcur = thread_get_current_user();
    if (!tcur) tcur = thread_current();
    uint64_t tid = (uint64_t)(tcur ? (tcur->tid ? tcur->tid : 1) : 1);
    if (!user_vma_is_fully_mapped(tid, addr, len)) {
        user_vma_unmap_range(tid, addr, len);
        if (user_vma_add(tid, addr, len, prot & 7, USER_VMA_KIND_MMAP) != 0)
            return 0;
        return 0;
    }
    if (user_vma_set_prot(tid, addr, len, prot & 7) != 0)
        return user_mm_ret_err(USER_MM_ENOSPC);
    if (user_map_mprotect_range((uint64_t)addr, (uint64_t)addr + len, prot & 7) != 0)
        return user_mm_ret_err(USER_MM_EFAULT);
    return 0;
}
