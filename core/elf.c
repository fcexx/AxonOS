/*
 * core/elf.c
 * ELF file parser
 * Author: fcexx
*/

#include <axonos.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fs.h>
#include <exec.h>
#include <heap.h>
#include <mmio.h>
#include <thread.h>
#include <devfs.h>
#include <gdt.h>
#include <paging.h>
#include <elf.h>
#include <vga.h>

extern uint8_t _end[]; /* kernel end symbol from linker */

/* Fixed base to load ET_DYN (PIE) style executables when full relocation/loader
   support isn't available. */
static const uint64_t ELF_ET_DYN_BASE = 0x00400000ULL; /* 4MiB */

/* In AxonOS, user programs currently run as kernel threads in a shared identity-mapped
   address space. That means user stacks and TLS must not overlap between threads,
   otherwise vfork/exec will clobber the parent's stack/TLS and trigger user-mode #GP
   after the child exits. We carve out per-tid stack/TLS regions below USER_STACK_TOP. */
static uintptr_t user_stack_top_for_tid(uint64_t tid) {
    const uintptr_t top = (uintptr_t)USER_STACK_TOP;
    /* Each slot: stack + tls + small guard. */
    const uintptr_t stride = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + (uintptr_t)(64 * 1024);
    /* Avoid colliding with tid0/ring0 assumptions; shift by 1. */
    const uint64_t slot = tid + 1ULL;
    /* Defensive programming:
       - if tid is corrupted/huge, (slot * stride) can overflow and later cause unsigned underflow
         in (top - off), producing a bogus "TLS base outside identity map".
       - avoid overflow and avoid (off + 0x10000) wrap by using a non-overflowing comparison. */
    if (stride == 0) return top;
    if (slot > (uint64_t)((uintptr_t)-1) / (uint64_t)stride) {
        return top;
    }
    const uintptr_t off = (uintptr_t)(slot * (uint64_t)stride);
    /* We must guarantee that the computed stack_top leaves room for BOTH:
       - the full reserved user stack (USER_STACK_SIZE)
       - the reserved TLS region (USER_TLS_SIZE)
       Otherwise TLS base = stack_top - stack - tls will underflow and become huge,
       triggering "tls base outside identity map" after enough process launches. */
    const uintptr_t min_room = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + 0x10000u;
    if (top <= min_room) return top;
    if (off >= (top - min_room)) {
        /* Out of reserved per-tid slots: reuse the top slot.
           This is safe for the common "run one program at a time from osh" case. */
        return top;
    }
    return top - off;
}

static inline uintptr_t user_tls_base_for_stack_top(uintptr_t stack_top) {
    return (uintptr_t)stack_top - (uintptr_t)USER_STACK_SIZE - (uintptr_t)USER_TLS_SIZE;
}

static inline uint64_t msr_read_u64_local(uint32_t msr) {
    uint32_t lo = 0, hi = 0;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}
static inline void msr_write_u64_local(uint32_t msr, uint64_t v) {
    uint32_t lo = (uint32_t)(v & 0xFFFFFFFFu);
    uint32_t hi = (uint32_t)(v >> 32);
    asm volatile("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

/* Helpers for per-process page table creation.
   We allocate 4KiB-aligned tables via kmalloc and build a new PML4 for the process,
   copying kernel entries and installing per-segment leaf entries with PG_US.
*/
static void *alloc_page_table(void) {
    void *p = kmalloc(PAGE_SIZE_4K);
    if (!p) return NULL;
    memset(p, 0, PAGE_SIZE_4K);
    return p;
}

/* Duplicate an existing page table page (virtual pointer assumed identity-mapped). */
static void *dup_page_table(void *old) {
    void *n = alloc_page_table();
    if (!n) return NULL;
    memcpy(n, old, PAGE_SIZE_4K);
    return n;
}

/* Translate virtual address to physical by walking current page_table_l4.
   Returns physical base (frame) or 0 on failure. Works only while current
   page tables are active and mapping exists. */
uint64_t virt_to_phys(uint64_t va) {
    extern uint64_t page_table_l4[];
    uint64_t *l4 = (uint64_t*)page_table_l4;
    uint64_t l4i = (va >> 39) & 0x1FF;
    uint64_t l3i = (va >> 30) & 0x1FF;
    uint64_t l2i = (va >> 21) & 0x1FF;
    uint64_t l1i = (va >> 12) & 0x1FF;
    if (!(l4[l4i] & PG_PRESENT)) return 0;
    uint64_t l3e = l4[l4i];
    if (l3e & PG_PS_2M) {
        /* 1GiB page */
        return (l3e & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFFULL);
    }
    uint64_t *l3 = (uint64_t*)(uintptr_t)(l3e & ~0xFFFULL);
    if (!(l3[l3i] & PG_PRESENT)) return 0;
    uint64_t l2e = l3[l3i];
    if (l2e & PG_PS_2M) {
        /* 2MiB page */
        return (l2e & ~(PAGE_SIZE_2M - 1)) | (va & (PAGE_SIZE_2M - 1));
    }
    uint64_t *l2 = (uint64_t*)(uintptr_t)(l2e & ~0xFFFULL);
    if (!(l2[l2i] & PG_PRESENT)) return 0;
    uint64_t l1e = l2[l2i];
    uint64_t *l1 = (uint64_t*)(uintptr_t)(l1e & ~0xFFFULL);
    if (!(l1[l1i] & PG_PRESENT)) return 0;
    return (l1[l1i] & ~0xFFFULL) | (va & 0xFFFULL);
}

/* Create new PML4 by cloning current page_table_l4 contents. */
static void *create_process_pml4(void) {
    extern uint64_t page_table_l4[];
    void *newpml4 = alloc_page_table();
    if (!newpml4) return NULL;
    memcpy(newpml4, (void*)page_table_l4, PAGE_SIZE_4K);
    return newpml4;
}

/* Ensure a table exists at given entry (level pointer) and return pointer to it.
   parent_entry_ptr points to the 64-bit entry in parent table. If entry is not present,
   allocate new table and update parent entry. Returns pointer to child table. */
static uint64_t *ensure_child_table(uint64_t *parent_entries, int idx) {
    uint64_t ent = parent_entries[idx];
    if (ent & PG_PRESENT) {
        /* existing */
        return (uint64_t*)(uintptr_t)(ent & ~0xFFFULL);
    }
    void *nt = alloc_page_table();
    if (!nt) return NULL;
    uint64_t newent = ((uint64_t)(uintptr_t)nt) | PG_PRESENT | PG_RW;
    parent_entries[idx] = newent;
    return (uint64_t*)nt;
}

/* Map one VA->PA into provided pml4 (virtual pointer) with flags. Doesn't split large pages.
   flags should include PG_PRESENT|PG_RW|PG_US and optionally PG_NX omitted for executable.
*/
static int pml4_map_one(void *pml4_ptr, uint64_t va, uint64_t pa, uint64_t flags) {
    uint64_t *l4 = (uint64_t*)pml4_ptr;
    int l4i = (va >> 39) & 0x1FF;
    int l3i = (va >> 30) & 0x1FF;
    int l2i = (va >> 21) & 0x1FF;
    int l1i = (va >> 12) & 0x1FF;

    uint64_t ent4 = l4[l4i];
    /* allocate l3 if missing or clone if present and shared with kernel */
    uint64_t *l3;
    if (ent4 & PG_PRESENT) {
        l3 = (uint64_t*)(uintptr_t)(ent4 & ~0xFFFULL);
        /* clone to avoid modifying kernel tables */
        l3 = dup_page_table(l3);
        if (!l3) return -1;
        l4[l4i] = ((uint64_t)(uintptr_t)l3) | (ent4 & 0xFFF);
    } else {
        l3 = alloc_page_table();
        if (!l3) return -1;
        l4[l4i] = ((uint64_t)(uintptr_t)l3) | PG_PRESENT | PG_RW | PG_US;
    }

    uint64_t ent3 = l3[l3i];
    /* check for large 1GiB mapping */
    if (ent3 & PG_PS_2M) {
        /* convert not supported; return error if large page present */
        return -1;
    }
    uint64_t *l2;
    if (ent3 & PG_PRESENT) {
        l2 = (uint64_t*)(uintptr_t)(ent3 & ~0xFFFULL);
        l2 = dup_page_table(l2);
        if (!l2) return -1;
        l3[l3i] = ((uint64_t)(uintptr_t)l2) | (ent3 & 0xFFF);
    } else {
        l2 = alloc_page_table();
        if (!l2) return -1;
        l3[l3i] = ((uint64_t)(uintptr_t)l2) | PG_PRESENT | PG_RW | PG_US;
    }

    uint64_t ent2 = l2[l2i];
    if (ent2 & PG_PS_2M) {
        /* 2MiB large page exists; replace with new 2MiB mapping */
        l2[l2i] = (pa & ~(PAGE_SIZE_2M - 1)) | (flags & ~PG_PS_2M) | PG_PS_2M;
        return 0;
    }
    uint64_t *l1;
    if (ent2 & PG_PRESENT) {
        l1 = (uint64_t*)(uintptr_t)(ent2 & ~0xFFFULL);
        l1 = dup_page_table(l1);
        if (!l1) return -1;
        l2[l2i] = ((uint64_t)(uintptr_t)l1) | (ent2 & 0xFFF);
    } else {
        l1 = alloc_page_table();
        if (!l1) return -1;
        l2[l2i] = ((uint64_t)(uintptr_t)l1) | PG_PRESENT | PG_RW | PG_US;
    }

    /* set final L1 entry */
    l1[l1i] = (pa & ~0xFFFULL) | (flags & ~PG_PS_2M) | PG_PRESENT;
    return 0;
}

/* Validate minimal ELF64 header */
static int elf_validate_header(const Elf64_Ehdr *eh, size_t len) {
    if (!eh) return 0;
    if (len < sizeof(Elf64_Ehdr)) return 0;
    /* magic 0x7F 'E' 'L' 'F' */
    if (eh->e_ident[0] != 0x7F || eh->e_ident[1] != 'E' || eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F') return 0;
    /* class must be ELFCLASS64 (2) */
    if (eh->e_ident[4] != 2) return 0;
    /* data encoding little endian */
    if (eh->e_ident[5] != 1) return 0;
    /* ELF type/executable */
    /* Accept both ET_EXEC and ET_DYN (PIE). ET_DYN will be loaded at a fixed
       base address to support position-independent executables; full dynamic
       loader/relocations are still not implemented. */
    if (eh->e_type != 2 && eh->e_type != 3) {
        return 0;
    }
    return 1;
}

/* User images are loaded into the low identity-mapped region by copying to p_vaddr.
   To avoid corrupting the kernel heap (which is also identity-mapped), keep user
   segments strictly below the heap base. */
static uint64_t user_image_limit_bytes(void) {
    uintptr_t hb = heap_base_addr();
    /* If heap isn't initialized for some reason, fall back to 64MiB. */
    if (hb == 0) return 64ULL * 1024ULL * 1024ULL;
    return (uint64_t)hb;
}

/* Mark an identity-mapped VA range as user-accessible and writable, and clear NX
   on the relevant page table entries. This is required for instruction fetch and
   data access in ring3. We best-effort handle existing 1GiB/2MiB mappings without
   splitting; for 4KiB mappings we update the leaf entry. */
static int mark_user_range_exec(uint64_t va_begin, uint64_t va_end) {
    extern uint64_t page_table_l4[];
    if (va_end < va_begin) return -1;

    uint64_t begin = va_begin & ~(PAGE_SIZE_2M - 1);
    uint64_t end = (va_end + PAGE_SIZE_2M - 1) & ~(PAGE_SIZE_2M - 1);
    for (uint64_t va = begin; va < end; va += PAGE_SIZE_2M) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        uint64_t l1i = (va >> 12) & 0x1FF;
        uint64_t *l4 = (uint64_t*)page_table_l4;
        if (!(l4[l4i] & PG_PRESENT)) return -1;
        l4[l4i] |= PG_US | PG_RW;
        l4[l4i] &= ~PG_NX;

        uint64_t *l3 = (uint64_t*)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) return -1;
        l3[l3i] |= PG_US | PG_RW;
        l3[l3i] &= ~PG_NX;
        uint64_t l3e = l3[l3i];
        if (l3e & PG_PS_2M) {
            /* 1GiB mapping */
            invlpg((void*)(uintptr_t)va);
            continue;
        }

        uint64_t *l2 = (uint64_t*)(uintptr_t)(l3e & ~0xFFFULL);
        if (!(l2[l2i] & PG_PRESENT)) return -1;
        uint64_t l2e = l2[l2i];
        if (l2e & PG_PS_2M) {
            /* 2MiB mapping */
            l2[l2i] |= PG_US | PG_RW;
            l2[l2i] &= ~PG_NX;
            invlpg((void*)(uintptr_t)va);
            continue;
        }

        uint64_t *l1 = (uint64_t*)(uintptr_t)(l2e & ~0xFFFULL);
        l1[l1i] |= PG_US | PG_RW;
        l1[l1i] &= ~PG_NX;
        invlpg((void*)(uintptr_t)va);
    }
    return 0;
}

int elf_load_from_memory(const void *buf, size_t len, uint64_t *out_entry) {
    if (!buf || len < sizeof(Elf64_Ehdr)) {kprintf("!buf || len < sizeof(Elf64_Ehdr)\n");return -1;}
    const Elf64_Ehdr *eh = (const Elf64_Ehdr*)buf;
    if (!elf_validate_header(eh, len)) return -2;
    if (eh->e_phoff == 0 || eh->e_phnum == 0) return -3;

    /* For ET_DYN (PIE) load at a fixed base within identity-mapped region. */
    uint64_t load_base = 0;
    if (eh->e_type == 3) load_base = ELF_ET_DYN_BASE;

    /* Basic safety: do not allow loading segments that overlap kernel image */
    uintptr_t kernel_start = (uintptr_t)0x100000; /* from linker.ld */
    uintptr_t kernel_end = (uintptr_t)_end;

    uint64_t brk_end = 0;
    /* iterate program headers */
    const Elf64_Phdr *ph = (const Elf64_Phdr*)((const char*)buf + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++) {
        if ((const char*)ph + sizeof(Elf64_Phdr) > (const char*)buf + len) return -4;
        if (ph->p_type != 1) { ph++; continue; } /* PT_LOAD */

        /* Check bounds */
        uint64_t vstart = ph->p_vaddr + load_base;
        uint64_t vend = ph->p_vaddr + load_base + ph->p_memsz;
        if (vend < vstart) return -5;
        /* Hard limit for user image virtual range.
           We currently load user binaries into the low identity-mapped region by copying to p_vaddr.
           Keep them below the heap floor (64MiB) to prevent corrupting kernel heap. */
        const uint64_t USER_IMAGE_LIMIT = user_image_limit_bytes();
        if (vend > USER_IMAGE_LIMIT) {
            kprintf("elf: user image too high (segment 0x%llx..0x%llx, limit 0x%llx)\n",
                    (unsigned long long)vstart, (unsigned long long)vend,
                    (unsigned long long)USER_IMAGE_LIMIT);
            return -6;
        }
        if (vstart < kernel_end && vend > kernel_start) {
            kprintf("elf: segment overlaps kernel (vaddr 0x%llx..0x%llx kernel 0x%llx..0x%llx)\n",
                (unsigned long long)vstart, (unsigned long long)vend,
                (unsigned long long)kernel_start, (unsigned long long)kernel_end);
            return -7;
        }
        if (vstart + ph->p_filesz > MMIO_IDENTITY_LIMIT) {
            /* avoid writing above identity-mapped region for now */
            kprintf("elf: segment outside identity-mapped range, unsupported vaddr=0x%llx\n", (unsigned long long)vstart);
            return -8;
        }

        /* Copy file data into target vaddr (assumes identity mapping) */
        if (ph->p_offset + ph->p_filesz > len) return -12;
        void *dst = (void*)(uintptr_t)(ph->p_vaddr + load_base);
        const void *src = (const char*)buf + ph->p_offset;
        /* copy filesz bytes */
        if (ph->p_filesz > 0) memcpy(dst, src, (size_t)ph->p_filesz);
        /* zero remaining (bss) */
        if (ph->p_memsz > ph->p_filesz) {
            memset((char*)dst + ph->p_filesz, 0, (size_t)(ph->p_memsz - ph->p_filesz));
        }

        /* Ensure pages are user-accessible (include load_base for ET_DYN). */
        uint64_t ua_begin = (ph->p_vaddr + load_base);
        uint64_t ua_end = (ph->p_vaddr + load_base + ph->p_memsz);
        if (mark_user_range_exec(ua_begin, ua_end) != 0) return -9;
        if (vend > brk_end) brk_end = vend;
        ph++;
    }

    if (brk_end) syscall_set_user_brk((uintptr_t)brk_end);
    if (out_entry) *out_entry = eh->e_entry + load_base;
    return 0;
}

/* Mark an identity-mapped VA range as user-accessible by setting PG_US
   on all relevant paging structure levels. This is required for both
   instruction fetch and stack/data access in ring3. */
static int mark_user_identity_range_2m(uint64_t va_begin, uint64_t va_end) {
    extern uint64_t page_table_l4[];
    if (va_end < va_begin) return -1;
    uint64_t begin = va_begin & ~(PAGE_SIZE_2M - 1);
    uint64_t end = (va_end + PAGE_SIZE_2M - 1) & ~(PAGE_SIZE_2M - 1);
    for (uint64_t va = begin; va < end; va += PAGE_SIZE_2M) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        uint64_t *l4 = (uint64_t*)page_table_l4;
        if (!(l4[l4i] & PG_PRESENT)) return -1;
        l4[l4i] |= PG_US;
        uint64_t *l3 = (uint64_t*)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) return -1;
        l3[l3i] |= PG_US;
        uint64_t l3e = l3[l3i];
        if (l3e & PG_PS_2M) {
            /* 1GiB mapping */
            continue;
        }
        uint64_t *l2 = (uint64_t*)(uintptr_t)(l3e & ~0xFFFULL);
        if (!(l2[l2i] & PG_PRESENT)) return -1;
        l2[l2i] |= PG_US;
        invlpg((void*)(uintptr_t)va);
    }
    return 0;
}

/* Temporary broad user-mark helper used during execve to avoid missing mappings.
   This is a defensive measure: mark a large low address range user-accessible/writable
   to avoid spurious PFs during early userspace bootstrap. */
static void mark_broad_user_ranges_for_exec(void) {
    uintptr_t begin = 0x200000; /* 2MiB */
    uintptr_t end = USER_STACK_TOP;
    (void)mark_user_identity_range_2m((uint64_t)begin, (uint64_t)end);
}

int elf_load_from_path(const char *path, uint64_t *out_entry) {
    struct fs_file *f = fs_open(path);
    if (!f) {
        kprintf("execve: open failed: %s\n", path ? path : "(null)");
        return -1;
    }
    size_t fsz = f->size;

    /* Read only the ELF header first (avoid buffering whole file). */
    Elf64_Ehdr eh;
    ssize_t rh = fs_read(f, &eh, sizeof(eh), 0);
    if (rh != (ssize_t)sizeof(eh) || !elf_validate_header(&eh, sizeof(eh))) {
        fs_file_free(f);
        return -1;
    }
    if (eh.e_phoff == 0 || eh.e_phnum == 0 || eh.e_phentsize != sizeof(Elf64_Phdr)) {
        fs_file_free(f);
        return -1;
    }

    /* IMPORTANT:
       We do not implement dynamic linking (PT_INTERP) nor relocation processing for PIE/ET_DYN yet.
       Loading ET_DYN images without relocations commonly crashes immediately (NULL/GOT derefs).
       Return a distinct error so execve can translate it to ENOEXEC instead of letting userspace fault. */
    if (eh.e_type == 3) {
        qemu_debug_printf("elf: refusing ET_DYN (PIE) without relocations: %s\n", path ? path : "(null)");
        fs_file_free(f);
        return -2;
    }

    uint64_t load_base = 0;

    /* Basic safety: do not allow loading segments that overlap kernel image */
    uintptr_t kernel_start = (uintptr_t)0x100000; /* from linker.ld */
    uintptr_t kernel_end = (uintptr_t)_end;

    /* Read program headers */
    size_t phsz = (size_t)eh.e_phnum * (size_t)eh.e_phentsize;
    if (phsz == 0 || phsz > 256u * 1024u) { fs_file_free(f); return -1; } /* sanity */
    Elf64_Phdr *phdrs = (Elf64_Phdr*)kmalloc(phsz);
    if (!phdrs) { fs_file_free(f); return -1; }
    ssize_t rp = fs_read(f, phdrs, phsz, (size_t)eh.e_phoff);
    if (rp != (ssize_t)phsz) { kfree(phdrs); fs_file_free(f); return -1; }

    /* Reject dynamically linked binaries (PT_INTERP) until we have a loader. */
    for (int i = 0; i < (int)eh.e_phnum; i++) {
        if (phdrs[i].p_type == 3 /* PT_INTERP */) {
            qemu_debug_printf("elf: refusing PT_INTERP (dynamic) binary: %s\n", path ? path : "(null)");
            kfree(phdrs);
            fs_file_free(f);
            return -2;
        }
    }

    uint64_t brk_end = 0;
    /* Load PT_LOAD segments directly from file into their target VAs */
    for (int i = 0; i < (int)eh.e_phnum; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != 1) continue; /* PT_LOAD */

        uint64_t vstart = ph->p_vaddr + load_base;
        uint64_t vend = ph->p_vaddr + load_base + ph->p_memsz;
        if (vend < vstart) { kfree(phdrs); fs_file_free(f); return -1; }

        /* Keep user images below heap floor (64MiB) to avoid corrupting heap. */
        const uint64_t USER_IMAGE_LIMIT = user_image_limit_bytes();
        if (vend > USER_IMAGE_LIMIT) {
            kprintf("elf: user image too high (segment 0x%llx..0x%llx, limit 0x%llx)\n",
                    (unsigned long long)vstart, (unsigned long long)vend,
                    (unsigned long long)USER_IMAGE_LIMIT);
            kfree(phdrs);
            fs_file_free(f);
            return -1;
        }
        if (vstart < kernel_end && vend > kernel_start) {
            kprintf("elf: segment overlaps kernel (vaddr 0x%llx..0x%llx kernel 0x%llx..0x%llx)\n",
                    (unsigned long long)vstart, (unsigned long long)vend,
                    (unsigned long long)kernel_start, (unsigned long long)kernel_end);
            kfree(phdrs);
            fs_file_free(f);
            return -1;
        }
        if (vstart + ph->p_filesz > MMIO_IDENTITY_LIMIT) {
            kprintf("elf: segment outside identity-mapped range, unsupported vaddr=0x%llx\n",
                    (unsigned long long)vstart);
            kfree(phdrs);
            fs_file_free(f);
            return -1;
        }

        /* Sanity: file bounds if size is known */
        if (fsz && (uint64_t)ph->p_offset + (uint64_t)ph->p_filesz > (uint64_t)fsz) {
            kfree(phdrs);
            fs_file_free(f);
            return -1;
        }

        void *dst = (void*)(uintptr_t)(ph->p_vaddr + load_base);
        if (ph->p_filesz > 0) {
            ssize_t rr = fs_read(f, dst, (size_t)ph->p_filesz, (size_t)ph->p_offset);
            if (rr != (ssize_t)ph->p_filesz) {
                kfree(phdrs);
                fs_file_free(f);
                return -1;
            }
        }
        if (ph->p_memsz > ph->p_filesz) {
            memset((char*)dst + ph->p_filesz, 0, (size_t)(ph->p_memsz - ph->p_filesz));
        }
        if (mark_user_range_exec(vstart, vend) != 0) {
            kfree(phdrs);
            fs_file_free(f);
            return -1;
        }
        if (vend > brk_end) brk_end = vend;
    }

    if (brk_end) syscall_set_user_brk((uintptr_t)brk_end);
    if (out_entry) *out_entry = (uint64_t)eh.e_entry + load_base;
    kfree(phdrs);
    fs_file_free(f);
    return 0;
}

/* Kernel execve: load ELF and prepare user stack then transfer to user mode.
   Simple implementation: expects identity mapping for all segments and stack
   under USER_STACK_TOP (<4GiB). Returns negative on error; on success does not return. */
static int is_space_char(char c) {
    return (c == ' ' || c == '\t' || c == '\r' || c == '\n');
}

/* Parse "#!<interp> [arg]\n" from buffer.
   Returns 1 on success, 0 if not a shebang or parse error. */
static int parse_shebang(const uint8_t *buf, size_t n,
                         char *out_interp, size_t out_interp_sz,
                         char *out_arg, size_t out_arg_sz) {
    if (!buf || n < 3) return 0;
    if (buf[0] != '#' || buf[1] != '!') return 0;
    if (!out_interp || out_interp_sz == 0) return 0;
    if (!out_arg || out_arg_sz == 0) return 0;

    size_t i = 2;
    while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
    if (i >= n) return 0;

    /* interp path */
    size_t ip = 0;
    while (i < n && !is_space_char((char)buf[i])) {
        if (ip + 1 < out_interp_sz) out_interp[ip++] = (char)buf[i];
        i++;
    }
    out_interp[ip] = '\0';
    if (ip == 0) return 0;

    /* optional arg */
    while (i < n && (buf[i] == ' ' || buf[i] == '\t')) i++;
    size_t ap = 0;
    while (i < n && !is_space_char((char)buf[i])) {
        if (ap + 1 < out_arg_sz) out_arg[ap++] = (char)buf[i];
        i++;
    }
    out_arg[ap] = '\0';
    return 1;
}

static char *kstrdup_local(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *p = (char*)kmalloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

/* If `path` is a script with shebang, exec its interpreter. */
static int try_exec_shebang(const char *resolved_path,
                            const char *orig_path,
                            const char *const argv[],
                            const char *const envp[]) {
    if (!resolved_path || !orig_path) return -1;
    struct fs_file *f = fs_open(resolved_path);
    if (!f) return -1;

    uint8_t hdr[256];
    memset(hdr, 0, sizeof(hdr));
    ssize_t rr = fs_read(f, hdr, sizeof(hdr) - 1, 0);
    fs_file_free(f);
    if (rr <= 0) return -1;

    char interp[192];
    char arg[64];
    if (!parse_shebang(hdr, (size_t)rr, interp, sizeof(interp), arg, sizeof(arg))) return -1;

    /* Build new argv: [interp, (arg?), orig_path, argv[1..]] */
    int argc = 0;
    while (argv && argv[argc]) argc++;
    const int has_arg = (arg[0] != '\0');
    const int tail = (argc > 1) ? (argc - 1) : 0;
    const int new_argc = 1 + (has_arg ? 1 : 0) + 1 + tail;

    char *k_interp = kstrdup_local(interp);
    char *k_arg = has_arg ? kstrdup_local(arg) : NULL;
    const char **nargv = (const char**)kmalloc((size_t)(new_argc + 1) * sizeof(char*));
    if (!k_interp || (has_arg && !k_arg) || !nargv) {
        if (nargv) kfree((void*)nargv);
        if (k_interp) kfree(k_interp);
        if (k_arg) kfree(k_arg);
        return -1;
    }

    int p = 0;
    nargv[p++] = k_interp;
    if (has_arg) nargv[p++] = k_arg;
    nargv[p++] = orig_path;
    for (int i = 1; i < argc; i++) nargv[p++] = argv[i];
    nargv[p] = NULL;

    qemu_debug_printf("execve: shebang '%s' -> interp='%s'%s%s%s\n",
                      resolved_path, interp,
                      has_arg ? " arg='" : "",
                      has_arg ? arg : "",
                      has_arg ? "'" : "");

    int rc = kernel_execve_from_path(k_interp, nargv, envp);
    kfree((void*)nargv);
    kfree(k_interp);
    if (k_arg) kfree(k_arg);
    return rc;
}

int kernel_execve_from_path(const char *path, const char *const argv[], const char *const envp[]) {
    if (!path) return -1;
    /* IMPORTANT:
       Symlinks are resolved by VFS (`fs_open()` does it via `fs_resolve_symlinks()`).
       Do NOT attempt to "readlink" via fs_open() here, because that would read the
       *target file* (already resolved) rather than the symlink contents. */
    const char *curpath = path;
    uint64_t entry = 0;
    int r = elf_load_from_path(curpath, &entry);
    if (r == -2) {
        /* unsupported ELF format (dynamic/PIE without relocations) */
        return -2;
    }
    if (r != 0) {
        /* Not an ELF. Try shebang scripts (e.g. /linuxrc). */
        return try_exec_shebang(curpath, path, argv, envp);
    }
    /* NOTE:
       We currently execute user programs in the *same* address space (same CR3),
       relying on identity mapping and marking PT_LOAD pages as user-accessible in elf_load_from_memory().
       The previous attempt to build a per-process PML4 was buggy and leaked page tables heavily.
       Once we have a real physical-page allocator, we can reintroduce isolated address spaces. */

    /* Parse ELF headers again to construct a minimal auxv.
       glibc static startup relies on AT_PHDR/AT_PHENT/AT_PHNUM/AT_ENTRY/AT_RANDOM. */
    uint64_t aux_entry = entry;
    uint64_t aux_phdr = 0;
    uint64_t aux_phent = 0;
    uint64_t aux_phnum = 0;
    {
        struct fs_file *f = fs_open(path);
        if (f) {
            Elf64_Ehdr eh;
            ssize_t rr = fs_read(f, &eh, sizeof(eh), 0);
            if (rr == (ssize_t)sizeof(eh) && elf_validate_header(&eh, sizeof(eh)) && eh.e_phnum > 0 && eh.e_phentsize == sizeof(Elf64_Phdr)) {
                size_t phsz = (size_t)eh.e_phnum * (size_t)eh.e_phentsize;
                size_t need = (size_t)eh.e_phoff + phsz;
                if (need > 0 && need <= 65536) {
                    uint8_t *phbuf = (uint8_t*)kmalloc(need);
                    if (phbuf) {
                        ssize_t rr2 = fs_read(f, phbuf, need, 0);
                        if (rr2 == (ssize_t)need) {
                            const Elf64_Ehdr *eh2 = (const Elf64_Ehdr*)phbuf;
                            const Elf64_Phdr *ph = (const Elf64_Phdr*)(phbuf + eh2->e_phoff);
                            aux_phent = (uint64_t)eh2->e_phentsize;
                            aux_phnum = (uint64_t)eh2->e_phnum;
                            aux_entry = (uint64_t)eh2->e_entry;
                            /* Compute in-memory PHDR virtual address: find PT_LOAD that contains e_phoff..e_phoff+phsz */
                            for (int i = 0; i < eh2->e_phnum; i++) {
                                if (ph[i].p_type != 1) continue; /* PT_LOAD */
                                uint64_t poff = ph[i].p_offset;
                                uint64_t pend = ph[i].p_offset + ph[i].p_filesz;
                                uint64_t want0 = eh2->e_phoff;
                                uint64_t want1 = eh2->e_phoff + phsz;
                                if (want0 >= poff && want1 <= pend) {
                                    aux_phdr = ph[i].p_vaddr + (want0 - poff);
                                    break;
                                }
                            }
                        }
                        kfree(phbuf);
                    }
                }
            }
            fs_file_free(f);
        }
    }

    /* If this ELF is ET_DYN (PIE) we loaded it at a fixed base; reflect that
       in aux_phdr/aux_entry so libc startup code sees correct addresses. */
    {
        struct fs_file *f3 = fs_open(path);
        if (f3) {
            Elf64_Ehdr eh3;
            ssize_t r3 = fs_read(f3, &eh3, sizeof(eh3), 0);
            if (r3 == (ssize_t)sizeof(eh3) && eh3.e_type == 3) {
                aux_phdr += ELF_ET_DYN_BASE;
                aux_entry += ELF_ET_DYN_BASE;
            }
            fs_file_free(f3);
        }
    }

    /* Determine which tid we are preparing the stack/TLS for.
       If called from ring0 (osh/kernel), we must base the per-thread stack/TLS layout
       on the tid of the NEW user thread we are about to run, not on the caller's tid0.
       Using tid0 here causes all user programs spawned from osh to share the same stack
       slot, which breaks vfork/exec and leads to user-mode #GP after child exit. */
    thread_t *cur_user = thread_get_current_user();
    thread_t *planned_ut = NULL;
    uint64_t planned_tid = 0;
    if (cur_user) {
        planned_tid = (uint64_t)cur_user->tid;
    } else {
        /* Create the user thread early (BLOCKED) to reserve a unique tid for layout. */
        extern void user_thread_entry(void);
        planned_ut = thread_create_blocked(user_thread_entry, path ? path : "user");
        if (!planned_ut) return -1;
        planned_tid = (uint64_t)planned_ut->tid;
    }

    /* Build argv strings and pointers in kernel, then copy into user stack area.
       We must ensure the final RSP passed to user mode is 16-byte aligned to avoid
       misaligned iret frame / ABI issues. Compute aligned base accordingly. */
    int argc = 0;
    while (argv && argv[argc]) argc++;

    /* compute total strings size */
    size_t strings_size = 0;
    for (int i = 0; i < argc; i++) strings_size += strlen(argv[i]) + 1;
    size_t env_strings_size = 0; /* env not supported for now */

    /* Stack layout (SysV x86_64):
       RSP -> argc
              argv[0..argc-1], NULL
              envp[0..], NULL (we provide empty envp)
              auxv pairs (a_type,a_val) ending with AT_NULL
       Many libc start routines expect auxv to exist; without AT_NULL they may parse garbage. */
    enum { AT_NULL = 0, AT_PHDR = 3, AT_PHENT = 4, AT_PHNUM = 5, AT_PAGESZ = 6, AT_ENTRY = 9, AT_RANDOM = 25 };
    const size_t aux_pairs = 7; /* PHDR,PHENT,PHNUM,ENTRY,PAGESZ,RANDOM,NULL */
    const size_t aux_qwords = aux_pairs * 2;
    /* pointer area: argv pointers + NULL + env NULL + auxv */
    size_t ptrs = (size_t)(argc + 1 + 1) + aux_qwords;
    size_t ptrs_bytes = ptrs * sizeof(uint64_t);

    /* total needed on stack: pointers + strings + AT_RANDOM bytes + small padding */
    const size_t random_bytes = 16;
    size_t total = ptrs_bytes + strings_size + random_bytes + 32;
    if (total > USER_STACK_SIZE - 128) {
        kprintf("required stack size too large %u\n", (unsigned)total);
        return -1;
    }

    /* Align stack_top downward to 16 bytes */
    uintptr_t stack_top = user_stack_top_for_tid(planned_tid);
    stack_top &= ~((uintptr_t)0xFULL);

    /* provisional base then align final_stack (base-8) to 16 */
    uintptr_t base = stack_top - total;
    uintptr_t final_stack = (base - 8) & ~((uintptr_t)0xFULL); /* final RSP aligned */
    /* recompute base relative to aligned final_stack */
    base = final_stack + 8;

    /* layout: pointers at [base .. base+ptrs_bytes), strings at [base+ptrs_bytes .. ),
       then 16 bytes for AT_RANDOM. */
    uintptr_t ptrs_addr = base;
    uintptr_t strings_addr = base + ptrs_bytes;
    uintptr_t random_addr = strings_addr + strings_size;

    /* Ensure addresses are within identity-mapped range */
    if (strings_addr + strings_size > (uintptr_t)MMIO_IDENTITY_LIMIT) {
        kprintf("execve: stack region outside identity map\n");
        return -1;
    }

    /* copy strings into their place */
    char *str_dst = (char*)(uintptr_t)strings_addr;
    uint64_t *sp64 = (uint64_t*)(uintptr_t)ptrs_addr;
    for (int i = 0; i < argc; i++) {
        size_t l = strlen(argv[i]) + 1;
        memcpy(str_dst, argv[i], l);
        sp64[i] = (uint64_t)(uintptr_t)str_dst; /* argv[i] pointer */
        str_dst += l;
    }
    sp64[argc] = 0;     /* argv NULL */
    sp64[argc + 1] = 0; /* envp NULL */

    /* AT_RANDOM: 16 bytes. Not cryptographically secure; enough for libc bootstrap. */
    {
        uint8_t *rp = (uint8_t*)(uintptr_t)random_addr;
        for (size_t i = 0; i < 16; i++) rp[i] = (uint8_t)(0xA5u ^ (uint8_t)(i * 17u));
    }

    /* auxv pairs start right after envp NULL */
    size_t ax = (size_t)argc + 2;
    sp64[ax + 0] = (uint64_t)AT_PHDR;   sp64[ax + 1] = aux_phdr;
    sp64[ax + 2] = (uint64_t)AT_PHENT;  sp64[ax + 3] = aux_phent ? aux_phent : (uint64_t)sizeof(Elf64_Phdr);
    sp64[ax + 4] = (uint64_t)AT_PHNUM;  sp64[ax + 5] = aux_phnum;
    sp64[ax + 6] = (uint64_t)AT_ENTRY;  sp64[ax + 7] = aux_entry;
    sp64[ax + 8] = (uint64_t)AT_PAGESZ; sp64[ax + 9] = 4096ULL;
    sp64[ax +10] = (uint64_t)AT_RANDOM; sp64[ax +11] = (uint64_t)random_addr;
    sp64[ax +12] = (uint64_t)AT_NULL;   sp64[ax +13] = 0;

    /* write argc at final_stack (RSP will point here) */
    *((uint64_t*)(uintptr_t)final_stack) = (uint64_t)argc;

    /* Ensure the entire user stack mapping is user-accessible (PG_US).
       Without this, the first user push/read will trigger #PF err=0x5. */
    {
        uintptr_t stack_base = (stack_top - USER_STACK_SIZE) & ~0xFFFULL;
        uintptr_t stack_end = stack_top;
        if (mark_user_identity_range_2m((uint64_t)stack_base, (uint64_t)stack_end) != 0) {
            kprintf("Failed to mark user stack range user-accessible\n");
            return -1;
        }
    }

    /* Seed a minimal TLS/TCB layout before entering userspace.
       Why: busybox in your initfs is **glibc static**, and glibc expects some TLS/TCB
       fields to exist immediately. In particular, early code may call pthread_getspecific(),
       which on x86_64 glibc reads a pointer from %fs:-0x78 and then indexes at +0x80.
       If %fs points to an uninitialized area, this turns into a NULL/low-memory deref
       (exactly the CR2=0xa8 fault you saw).

       Strategy (minimal, single-thread-friendly):
       - Reserve a TLS region of size USER_TLS_SIZE (already carved in layout).
       - Place %fs base one page *inside* the region so both positive offsets (e.g. canary at +0x28)
         and negative offsets (e.g. -0x78) stay inside mapped memory.
       - Write a pointer at %fs:-0x78 to a zeroed "fake pthread" structure which contains a
         zeroed specifics array starting at +0x80. This makes pthread_getspecific() return NULL
         instead of crashing, which is enough for glibc/busybox to continue bootstrap. */
    enum { MSR_FS_BASE_LOCAL = 0xC0000100u };
    const uintptr_t tls_region_base = user_tls_base_for_stack_top(stack_top);
    const uintptr_t fs_base = tls_region_base + 0x1000u;      /* keep -0x78 and +0x28 in-range */
    const uintptr_t pthread_fake = tls_region_base + 0x2000u; /* within first few pages */
    {
        /* Need a few pages inside the TLS region for our minimal layout. */
        if (pthread_fake + 0x1000u >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
            kprintf("execve: tls base outside identity map\n");
            return -1;
        }
        if (mark_user_identity_range_2m((uint64_t)tls_region_base, (uint64_t)(pthread_fake + 0x1000u)) != 0) {
            kprintf("execve: failed to mark TLS range user-accessible\n");
            return -1;
        }
        /* Clear the first 3 pages we use */
        memset((void*)tls_region_base, 0, 0x3000u);
        uint64_t guard = 0;
        if (random_addr + 16 <= (uintptr_t)MMIO_IDENTITY_LIMIT) guard = *(uint64_t*)(uintptr_t)random_addr;
        else guard = 0x8b13f00d2a11c0deULL;
        /* glibc uses a "terminator canary": least-significant byte is 0 */
        guard &= ~0xFFULL;
        *(volatile uint64_t*)(uintptr_t)(fs_base + 0x28u) = guard;

        /* pthread_getspecific() expects *(%fs:-0x78) to be a valid pointer. */
        *(volatile uint64_t*)(uintptr_t)(fs_base - 0x78u) = (uint64_t)pthread_fake;

        /* glibc locale bootstrap:
           Some early code uses pthread_getspecific(5) and expects a non-NULL pointer whose
           first byte can be compared to 'C'. Provide a minimal default "C" string. */
        {
            const uintptr_t c_str = tls_region_base + 0x2800u;
            if (c_str + 2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                *(volatile uint8_t*)(uintptr_t)(c_str + 0) = (uint8_t)'C';
                *(volatile uint8_t*)(uintptr_t)(c_str + 1) = 0;
                /* specifics array base is at +0x80 in glibc's struct pthread */
                const uintptr_t specific5_slot = pthread_fake + 0x80u + (uintptr_t)(5u * 8u);
                *(volatile uint64_t*)(uintptr_t)specific5_slot = (uint64_t)c_str;
            }
        }

        msr_write_u64_local(MSR_FS_BASE_LOCAL, (uint64_t)fs_base);
    }


    /* IMPORTANT: userspace must run from a scheduled kernel thread.
       Otherwise syscalls run on the TSS RSP0 stack but the scheduler saves/restores
       `thread_current()->context` for a different stack, and vfork/fork will corrupt
       kernel context (seen as user-mode #GP with non-canonical pointers after vfork).
       
       Strategy:
       - If we are already in a user thread (thread_get_current_user()!=NULL), perform an
         in-place exec: update current user thread metadata and jump to user entry.
       - If called from ring0 (osh/kernel), spawn a new kernel thread that will enter
         user mode via user_thread_entry, block the caller until it exits, and schedule. */
    if (cur_user) {
        /* in-place exec for current user thread */
        cur_user->user_rip = entry;
        cur_user->user_stack = final_stack;
        cur_user->user_fs_base = (uint64_t)fs_base;
        /* update display name */
        strncpy(cur_user->name, path, sizeof(cur_user->name) - 1);
        cur_user->name[sizeof(cur_user->name) - 1] = '\0';
        /* New program runs in its own process group so Ctrl+C (SIGINT) only kills it, not the shell */
        cur_user->pgid = (int)(cur_user->tid ? cur_user->tid : 1);
        /* Set foreground so Ctrl+C terminates this process when waiting */
        if (cur_user->attached_tty >= 0) {
            devfs_set_tty_fg_pgrp(cur_user->attached_tty, cur_user->pgid);
        }
        /* ensure TSS RSP0 points to this thread's kernel stack */
        if (cur_user->kernel_stack) {
            tss_set_rsp0(cur_user->kernel_stack);
        }
    } else {
        /* spawn a scheduled user thread (already created as planned_ut) and block the caller until it terminates */
        thread_t *caller = thread_current();
        thread_t *ut = planned_ut;
        if (!ut) return -1;
        ut->ring = 3;
        ut->user_rip = entry;
        ut->user_stack = final_stack;
        ut->user_fs_base = (uint64_t)fs_base;
        /* Mark PID 1 only for kernel-launched init candidates */
        if (strcmp(path, "/init") == 0 || strcmp(path, "/sbin/init") == 0) {
            thread_mark_init_user(ut);
        }
        /* inherit basic POSIX-ish attributes and stdio from caller (usually tid0 osh) */
        if (caller) {
            ut->euid = caller->euid;
            ut->egid = caller->egid;
            ut->umask = caller->umask;
            ut->attached_tty = caller->attached_tty;
            strncpy(ut->cwd, caller->cwd[0] ? caller->cwd : "/", sizeof(ut->cwd));
            ut->cwd[sizeof(ut->cwd) - 1] = '\0';
            for (int i = 0; i < THREAD_MAX_FD; i++) {
                ut->fds[i] = caller->fds[i];
                if (ut->fds[i]) {
                    if (ut->fds[i]->refcount <= 0) ut->fds[i]->refcount = 1;
                    else ut->fds[i]->refcount++;
                }
            }
            /* block caller until user program exits */
            ut->waiter_tid = (int)caller->tid;
            caller->state = THREAD_BLOCKED;
        }
        /* New program in its own process group so Ctrl+C only kills it */
        ut->pgid = (int)(ut->tid ? ut->tid : 1);
        if (ut->attached_tty >= 0) {
            devfs_set_tty_fg_pgrp(ut->attached_tty, ut->pgid);
        }
        /* Now make the new user thread runnable. */
        thread_unblock((int)ut->tid);
        /* schedule immediately; when caller resumes, the program has terminated */
        thread_schedule();
        return 0;
    }

    /* Debug: print argv/env passed to execve for user debugging (qemu debug) */
    if (argv) {
        int i = 0;
        qemu_debug_printf("execve: launching %s argv:", path);
        while (argv[i]) {
            qemu_debug_printf(" \"%s\"", argv[i]);
            i++;
            if (i > 16) break;
        }
        qemu_debug_printf("\n");
    }
    if (envp) {
        int i = 0;
        qemu_debug_printf("execve: envp first entries:");
        while (envp[i]) {
            qemu_debug_printf(" %s", envp[i]);
            i++;
            if (i > 8) break;
        }
        qemu_debug_printf("\n");
    }


    if ((uintptr_t)entry >= (uintptr_t)MMIO_IDENTITY_LIMIT || (uintptr_t)final_stack >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
        kprintf("execve: entry or stack outside identity-mapped region, abort\n");
        return -1;
    }

    /* try to read first byte of entry */
    volatile uint8_t *entry_b = (volatile uint8_t*)(uintptr_t)entry;
    uint8_t first = 0;
    /* wrap read in a benign check */
    first = entry_b[0];

    /* If this thread was created via vfork, we normally wake parent on exec.
       However, in a shared address space we keep the parent blocked when a full
       memory snapshot is active, and only restore/unblock on child exit. */
    {
        thread_t *tc = thread_current();
        if (tc && tc->vfork_parent_tid >= 0) {
            qemu_debug_printf("execve: child %llu has vfork_parent_tid=%d mem_backup=%p\n",
                (unsigned long long)(tc->tid ? tc->tid : 1),
                tc->vfork_parent_tid, tc->vfork_parent_mem_backup);
            if (!tc->vfork_parent_mem_backup) {
                qemu_debug_printf("execve: waking vfork parent %d (no mem backup)\n", tc->vfork_parent_tid);
                thread_unblock(tc->vfork_parent_tid);
                tc->vfork_parent_tid = -1;
            } else {
                qemu_debug_printf("execve: NOT waking vfork parent %d (mem backup active, will wake on exit)\n",
                    tc->vfork_parent_tid);
            }
        } else {
            qemu_debug_printf("execve: child %llu has no vfork_parent_tid\n",
                (unsigned long long)(tc ? (tc->tid ? tc->tid : 1) : 0));
        }
    }

    /* Diagnostic: dump a few bytes at the entry and physical mapping to help debug PFs */
    if ((uintptr_t)entry < (uintptr_t)MMIO_IDENTITY_LIMIT) {
        uint64_t phys = virt_to_phys(entry);
        qemu_debug_printf("execve: DEBUG entry=0x%llx virt_phys=0x%llx final_stack=0x%llx\n",
                          (unsigned long long)entry, (unsigned long long)phys, (unsigned long long)final_stack);
        unsigned char dbuf[32];
        for (int i = 0; i < (int)sizeof(dbuf); i++) {
            dbuf[i] = *((unsigned char*)(uintptr_t)(entry + i));
        }
        qemu_debug_printf("execve: entry_bytes:");
        for (int i = 0; i < (int)sizeof(dbuf); i++) qemu_debug_printf("%02x", (unsigned int)dbuf[i]);
        qemu_debug_printf("\n");
    } else {
        qemu_debug_printf("execve: DEBUG entry outside identity map: 0x%llx\n", (unsigned long long)entry);
    }

    /* Temporary diagnostic: ensure low memory and broad user ranges are marked
       user-accessible to test whether PFs are caused by missing PG_US. */
    mark_broad_user_ranges_for_exec();
    /* Mark 0..ELF_ET_DYN_BASE (0..4MiB) as user-accessible for diagnostic */
    (void)mark_user_identity_range_2m(0, ELF_ET_DYN_BASE);

    /* Transfer to user mode (does not return on success). */
    enter_user_mode(entry, final_stack);
    return 0; /* not reached */
}


