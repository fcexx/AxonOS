#include <axonos.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fs.h>
#include <exec.h>
#include <heap.h>
#include <mmio.h>
#include <thread.h>
#include <gdt.h>
#include <paging.h>
#include <elf.h>
#include <vga.h>

extern uint8_t _end[]; /* kernel end symbol from linker */

/* Fixed base to load ET_DYN (PIE) style executables when full relocation/loader
   support isn't available. */
static const uint64_t ELF_ET_DYN_BASE = 0x00400000ULL; /* 4MiB */

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

int elf_load_from_memory(const void *buf, size_t len, uint64_t *out_entry) {
    if (!buf || len < sizeof(Elf64_Ehdr)) return -1;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr*)buf;
    if (!elf_validate_header(eh, len)) return -1;
    if (eh->e_phoff == 0 || eh->e_phnum == 0) return -1;

    /* For ET_DYN (PIE) load at a fixed base within identity-mapped region. */
    uint64_t load_base = 0;
    if (eh->e_type == 3) load_base = ELF_ET_DYN_BASE;

    /* Basic safety: do not allow loading segments that overlap kernel image */
    uintptr_t kernel_start = (uintptr_t)0x100000; /* from linker.ld */
    uintptr_t kernel_end = (uintptr_t)_end;

    /* iterate program headers */
    const Elf64_Phdr *ph = (const Elf64_Phdr*)((const char*)buf + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++) {
        if ((const char*)ph + sizeof(Elf64_Phdr) > (const char*)buf + len) return -1;
        if (ph->p_type != 1) { ph++; continue; } /* PT_LOAD */

        /* Check bounds */
        uint64_t vstart = ph->p_vaddr + load_base;
        uint64_t vend = ph->p_vaddr + load_base + ph->p_memsz;
        if (vend < vstart) return -1;
        /* Hard limit for user image virtual range.
           We currently load user binaries into the low identity-mapped region by copying to p_vaddr.
           Keep them below the heap floor (64MiB) to prevent corrupting kernel heap. */
        const uint64_t USER_IMAGE_LIMIT = 64ULL * 1024ULL * 1024ULL;
        if (vend > USER_IMAGE_LIMIT) {
            kprintf("elf: user image too high (segment 0x%llx..0x%llx, limit 0x%llx)\n",
                    (unsigned long long)vstart, (unsigned long long)vend,
                    (unsigned long long)USER_IMAGE_LIMIT);
            return -4;
        }
        if (vstart < kernel_end && vend > kernel_start) {
            kprintf("elf: segment overlaps kernel (vaddr 0x%llx..0x%llx kernel 0x%llx..0x%llx)\n",
                (unsigned long long)vstart, (unsigned long long)vend,
                (unsigned long long)kernel_start, (unsigned long long)kernel_end);
            return -2;
        }
        if (vstart + ph->p_filesz > MMIO_IDENTITY_LIMIT) {
            /* avoid writing above identity-mapped region for now */
            kprintf("elf: segment outside identity-mapped range, unsupported vaddr=0x%llx\n", (unsigned long long)vstart);
            return -3;
        }

        /* Copy file data into target vaddr (assumes identity mapping) */
        if (ph->p_offset + ph->p_filesz > len) return -1;
        void *dst = (void*)(uintptr_t)(ph->p_vaddr + load_base);
        const void *src = (const char*)buf + ph->p_offset;
        /* copy filesz bytes */
        if (ph->p_filesz > 0) memcpy(dst, src, (size_t)ph->p_filesz);
        /* zero remaining (bss) */
        if (ph->p_memsz > ph->p_filesz) {
            memset((char*)dst + ph->p_filesz, 0, (size_t)(ph->p_memsz - ph->p_filesz));
        }

        /* Ensure pages are user-accessible: set PG_US on existing page-table entries
           (handles large 1GiB/2MiB mappings created at bootstrap). We don't attempt
           to split large pages; instead mark the existing mapping as user-accessible. */
        extern uint64_t page_table_l4[];
        uint64_t va_begin = ph->p_vaddr & ~(PAGE_SIZE_2M - 1);
        uint64_t va_end = (ph->p_vaddr + ph->p_memsz + PAGE_SIZE_2M - 1) & ~(PAGE_SIZE_2M - 1);
        for (uint64_t va = va_begin; va < va_end; va += PAGE_SIZE_2M) {
            uint64_t l4i = (va >> 39) & 0x1FF;
            uint64_t l3i = (va >> 30) & 0x1FF;
            uint64_t l2i = (va >> 21) & 0x1FF;
            uint64_t l1i = (va >> 12) & 0x1FF;
            uint64_t *l4 = (uint64_t*)page_table_l4;
            if (!(l4[l4i] & PG_PRESENT)) {
                kprintf("elf: no L4 entry for va=0x%llx\n", (unsigned long long)va);
                return -1;
            }
            /* Make sure the PML4 entry itself permits user access (parent entries must not block) */
            l4[l4i] |= PG_US;
            l4[l4i] &= ~PG_NX;
            invlpg((void*)(uintptr_t)va);

            uint64_t *l3 = (uint64_t*)(uintptr_t)(l4[l4i] & ~0xFFFULL);
            if (!(l3[l3i] & PG_PRESENT)) {
                kprintf("elf: no L3 entry for va=0x%llx\n", (unsigned long long)va);
                return -1;
            }
            /* PDPT entry must also allow user access, иначе будет #PF err=0x5 при fetch/чтении из ring3. */
            l3[l3i] |= PG_US;
            l3[l3i] &= ~PG_NX;
            uint64_t l3e = l3[l3i];
            if (l3e & PG_PS_2M) {
                /* 1GiB mapping at L3: set US and clear NX on L3 entry */
                l3[l3i] |= PG_US;
                l3[l3i] &= ~PG_NX;
                invlpg((void*)(uintptr_t)va);
                continue;
            }
            uint64_t *l2 = (uint64_t*)(uintptr_t)(l3e & ~0xFFFULL);
            if (!(l2[l2i] & PG_PRESENT)) {
                kprintf("elf: no L2 entry for va=0x%llx\n", (unsigned long long)va);
                return -1;
            }
            uint64_t l2e = l2[l2i];
            if (l2e & PG_PS_2M) {
                /* 2MiB mapping at L2: set US and clear NX on L2 entry */
                l2[l2i] |= PG_US;
                l2[l2i] &= ~PG_NX;
                invlpg((void*)(uintptr_t)va);
                continue;
            }
            uint64_t *l1 = (uint64_t*)(uintptr_t)(l2e & ~0xFFFULL);
            /* set US and clear NX on L1 entry covering this 4KiB range */
            l1[l1i] |= PG_US;
            l1[l1i] &= ~PG_NX;
            invlpg((void*)(uintptr_t)va);
        }
        ph++;
    }

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

int elf_load_from_path(const char *path, uint64_t *out_entry) {
    struct fs_file *f = fs_open(path);
    if (!f) return -1;
    size_t sz = f->size;
    if (sz == 0 || sz > 16*1024*1024) { fs_file_free(f); return -1; } /* limit 16MB */
    void *buf = kmalloc(sz);
    if (!buf) { fs_file_free(f); return -1; }
    ssize_t r = fs_read(f, buf, sz, 0);
    fs_file_free(f);
    if (r <= 0 || (size_t)r != sz) { kfree(buf); return -1; }
    int rc = elf_load_from_memory(buf, sz, out_entry);
    kfree(buf);
    return rc;
}

/* Kernel execve: load ELF and prepare user stack then transfer to user mode.
   Simple implementation: expects identity mapping for all segments and stack
   under USER_STACK_TOP (<4GiB). Returns negative on error; on success does not return. */
int kernel_execve_from_path(const char *path, const char *const argv[], const char *const envp[]) {
    if (!path) return -1;
    /* Resolve symlinks (follow up to 16 levels) */
    char *curpath = (char*)kmalloc(strlen(path) + 1);
    if (!curpath) return -1;
    strcpy(curpath, path);
    for (int depth = 0; depth < 16; depth++) {
        struct stat st;
        if (vfs_stat(curpath, &st) != 0) break;
        if ((st.st_mode & S_IFLNK) == S_IFLNK) {
            /* read link target */
            struct fs_file *lf = fs_open(curpath);
            if (!lf) break;
            size_t tsize = (size_t)lf->size;
            if (tsize == 0) { fs_file_free(lf); break; }
            size_t cap = tsize + 1;
            char *tbuf = (char*)kmalloc(cap);
            if (!tbuf) { fs_file_free(lf); break; }
            ssize_t rr = fs_read(lf, tbuf, tsize, 0);
            fs_file_free(lf);
            if (rr <= 0) { kfree(tbuf); break; }
            tbuf[rr] = '\\0';
            /* build new absolute path */
            char *newpath = NULL;
            if (tbuf[0] == '/') {
                newpath = (char*)kmalloc(strlen(tbuf) + 1);
                if (newpath) strcpy(newpath, tbuf);
            } else {
                /* relative: parent dir of curpath + '/' + tbuf */
                const char *slash = strrchr(curpath, '/');
                size_t plen = slash ? (size_t)(slash - curpath) : 0;
                if (plen == 0) plen = 1; /* root */
                size_t nlen = plen + 1 + strlen(tbuf) + 1;
                newpath = (char*)kmalloc(nlen);
                if (newpath) {
                    if (plen == 1) {
                        /* parent is root */
                        newpath[0] = '/'; newpath[1] = '\\0';
                    } else {
                        strncpy(newpath, curpath, plen);
                        newpath[plen] = '\\0';
                    }
                    /* ensure trailing slash */
                    size_t curl = strlen(newpath);
                    if (newpath[curl-1] != '/') strncat(newpath, "/", nlen - curl - 1);
                    strncat(newpath, tbuf, nlen - strlen(newpath) - 1);
                }
            }
            kfree(tbuf);
            if (!newpath) break;
            kfree(curpath);
            curpath = newpath;
            /* continue resolving */
            continue;
        }
        break;
    }
    uint64_t entry = 0;
    int r = elf_load_from_path(curpath, &entry);
    if (curpath) kfree(curpath);
    if (r != 0) {
        kprintf("execve: elf_load_from_path failed for %s (rc=%d)\n", path, r);
        return -1;
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
        kprintf("execve: required stack size too large %u\n", (unsigned)total);
        return -1;
    }

    /* Align stack_top downward to 16 bytes */
    uintptr_t stack_top = (uintptr_t)USER_STACK_TOP;
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
        uintptr_t stack_base = ((uintptr_t)USER_STACK_TOP - USER_STACK_SIZE) & ~0xFFFULL;
        uintptr_t stack_end = (uintptr_t)USER_STACK_TOP;
        if (mark_user_identity_range_2m((uint64_t)stack_base, (uint64_t)stack_end) != 0) {
            kprintf("execve: failed to mark user stack range user-accessible\n");
            return -1;
        }
    }

    /* Seed an initial TLS base + stack canary guard before entering userspace.
       Some libcs may execute stack-protected code before they set up TLS. If FS base is 0,
       GCC's stack protector reads canary from fs:0x28, which is physical address 0x28 under
       identity mapping and may change -> false "*** stack smashing detected ***".
       We ensure FS points to a stable, user-accessible TLS page with a guard at +0x28. */
    enum { MSR_FS_BASE_LOCAL = 0xC0000100u };
    const uintptr_t user_tls_base = (uintptr_t)USER_TLS_BASE; /* reserved TLS region (see inc/exec.h) */
    {
        if (user_tls_base + 0x1000u >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
            kprintf("execve: tls base outside identity map\n");
            return -1;
        }
        if (mark_user_identity_range_2m((uint64_t)user_tls_base, (uint64_t)(user_tls_base + 0x1000u)) != 0) {
            kprintf("execve: failed to mark TLS range user-accessible\n");
            return -1;
        }
        memset((void*)user_tls_base, 0, 0x1000u);
        uint64_t guard = 0;
        if (random_addr + 16 <= (uintptr_t)MMIO_IDENTITY_LIMIT) guard = *(uint64_t*)(uintptr_t)random_addr;
        else guard = 0x8b13f00d2a11c0deULL;
        /* glibc uses a "terminator canary": least-significant byte is 0 */
        guard &= ~0xFFULL;
        *(volatile uint64_t*)(uintptr_t)(user_tls_base + 0x28u) = guard;
        msr_write_u64_local(MSR_FS_BASE_LOCAL, (uint64_t)user_tls_base);
    }


    /* register user thread info for debugger/listing purposes and allocate kernel stack */
    thread_t *ut = thread_register_user(entry, final_stack, path);
    if (ut) {
        ut->user_fs_base = (uint64_t)user_tls_base;
        /* allocate kernel stack for the user thread so hardware can switch to a valid RSP0 */
        void *kst = kmalloc(8192 + 16);
        if (kst) {
            ut->kernel_stack = (uint64_t)kst + 8192 + 16;
            tss_set_rsp0(ut->kernel_stack);
        } else {
            /* keep going (less safe), but avoid noisy warnings */
        }
    } else {
        /* keep going without a registered user thread */
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

    /* If this thread was created via vfork, wake parent now (child is about to exec). */
    {
        thread_t *tc = thread_current();
        if (tc && tc->vfork_parent_tid >= 0) {
            thread_unblock(tc->vfork_parent_tid);
            tc->vfork_parent_tid = -1;
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

    /* Transfer to user mode (does not return) */
    enter_user_mode(entry, final_stack);
    return 0; /* not reached */
}


