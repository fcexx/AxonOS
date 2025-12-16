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

extern uint8_t _end[]; /* kernel end symbol from linker */

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
static uint64_t virt_to_phys(uint64_t va) {
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
    if (eh->e_type != 2 && eh->e_type != 3) {
        /* allow ET_EXEC and ET_DYN */
        /* but continue — position-independent recommended */
    }
    return 1;
}

int elf_load_from_memory(const void *buf, size_t len, uint64_t *out_entry) {
    if (!buf || len < sizeof(Elf64_Ehdr)) return -1;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr*)buf;
    if (!elf_validate_header(eh, len)) return -1;
    if (eh->e_phoff == 0 || eh->e_phnum == 0) return -1;

    /* Basic safety: do not allow loading segments that overlap kernel image */
    uintptr_t kernel_start = (uintptr_t)0x100000; /* from linker.ld */
    uintptr_t kernel_end = (uintptr_t)_end;

    /* iterate program headers */
    const Elf64_Phdr *ph = (const Elf64_Phdr*)((const char*)buf + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++) {
        if ((const char*)ph + sizeof(Elf64_Phdr) > (const char*)buf + len) return -1;
        if (ph->p_type != 1) { ph++; continue; } /* PT_LOAD */

        /* Check bounds */
        uint64_t vstart = ph->p_vaddr;
        uint64_t vend = ph->p_vaddr + ph->p_memsz;
        if (vend < vstart) return -1;
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
        void *dst = (void*)(uintptr_t)ph->p_vaddr;
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

    if (out_entry) *out_entry = eh->e_entry;
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
    uint64_t entry = 0;
    int r = elf_load_from_path(path, &entry);
    if (r != 0) {
        kprintf("execve: elf_load_from_path failed for %s (rc=%d)\n", path, r);
        return -1;
    }
    /* Create a private PML4 for the new process and map PT_LOAD segments into it.
       We re-open the ELF file and iterate program headers to map pages into the new PML4. */
    void *new_pml4 = create_process_pml4();
    if (!new_pml4) { kprintf("execve: failed to alloc new pml4\n"); return -1; }
    struct fs_file *f = fs_open(path);
    if (!f) { kfree(new_pml4); return -1; }
    size_t fsz = f->size;
    if (fsz == 0 || fsz > 16*1024*1024) { fs_file_free(f); kfree(new_pml4); return -1; }
    void *buf = kmalloc(fsz);
    if (!buf) { fs_file_free(f); kfree(new_pml4); return -1; }
    ssize_t rr = fs_read(f, buf, fsz, 0);
    fs_file_free(f);
    if (rr <= 0 || (size_t)rr != fsz) { kfree(buf); kfree(new_pml4); return -1; }
    const Elf64_Ehdr *eh = (const Elf64_Ehdr*)buf;
    const Elf64_Phdr *ph = (const Elf64_Phdr*)((const char*)buf + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph->p_type != 1) { ph++; continue; }
        /* map each 4KiB page of the segment into new_pml4 */
        uint64_t seg_va = ph->p_vaddr;
        uint64_t seg_pa = ph->p_paddr ? ph->p_paddr : ph->p_vaddr; /* prefer p_paddr if present */
        uint64_t seg_memsz = ph->p_memsz;
        for (uint64_t off = 0; off < seg_memsz; off += PAGE_SIZE_4K) {
            uint64_t va = (seg_va + off) & ~((uint64_t)0xFFF);
            uint64_t phys_frame = virt_to_phys(va);
            if (phys_frame == 0) {
                kprintf("execve: cannot translate va=0x%llx to phys\n", (unsigned long long)va);
                kfree(buf);
                kfree(new_pml4);
                return -1;
            }
            uint64_t flags = PG_PRESENT | PG_RW | PG_US;
            /* if segment is not executable, set NX */
            if (!(ph->p_flags & 0x1)) flags |= PG_NX; /* PF_X == 1 */
            if (pml4_map_one(new_pml4, va, phys_frame, flags) != 0) {
                kprintf("execve: pml4_map_one failed va=0x%llx phys=0x%llx\n", (unsigned long long)va, (unsigned long long)phys_frame);
                kfree(buf);
                kfree(new_pml4);
                return -1;
            }
        }
        ph++;
    }
    kfree(buf);

    /* Switch CR3 to new PML4 (physical == virtual in identity region) */
    /* Map user stack region in new_pml4 so RSP after switch is valid */
    uintptr_t stack_base = ((uintptr_t)USER_STACK_TOP - USER_STACK_SIZE) & ~0xFFFULL;
    for (uintptr_t a = stack_base; a < (uintptr_t)USER_STACK_TOP; a += PAGE_SIZE_4K) {
        uint64_t phys = virt_to_phys(a);
        if (phys == 0) {
            kprintf("execve: cannot translate stack page va=0x%llx\n", (unsigned long long)a);
            return -1;
        }
        if (pml4_map_one(new_pml4, a, phys, PG_PRESENT | PG_RW | PG_US) != 0) {
            kprintf("execve: failed to map user stack va=0x%llx phys=0x%llx\n", (unsigned long long)a, (unsigned long long)phys);
            return -1;
        }
    }

    /* CR3 must contain physical address of PML4. Translate virtual->physical */
    uint64_t phys_pml4 = virt_to_phys((uint64_t)(uintptr_t)new_pml4);
    if (phys_pml4 == 0) {
        kprintf("execve: cannot translate new_pml4 virt->phys, abort\n");
        return -1;
    }
    asm volatile("mov %0, %%cr3" :: "r"(phys_pml4) : "memory");
    kprintf("execve: switched CR3 to phys=0x%llx (virt=0x%llx)\n", (unsigned long long)phys_pml4, (unsigned long long)(uintptr_t)new_pml4);

    /* Build argv strings and pointers in kernel, then copy into user stack area.
       We must ensure the final RSP passed to user mode is 16-byte aligned to avoid
       misaligned iret frame / ABI issues. Compute aligned base accordingly. */
    int argc = 0;
    while (argv && argv[argc]) argc++;

    /* compute total strings size */
    size_t strings_size = 0;
    for (int i = 0; i < argc; i++) strings_size += strlen(argv[i]) + 1;
    size_t env_strings_size = 0; /* env not supported for now */

    /* pointer area: argv pointers + NULL + env NULL */
    size_t ptrs = (size_t)(argc + 1 + 1);
    size_t ptrs_bytes = ptrs * sizeof(uint64_t);

    /* total needed on stack: pointers + strings + small padding */
    size_t total = ptrs_bytes + strings_size + 16;
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

    /* layout: pointers at [base .. base+ptrs_bytes), strings at [base+ptrs_bytes .. ) */
    uintptr_t ptrs_addr = base;
    uintptr_t strings_addr = base + ptrs_bytes;

    /* Ensure addresses are within identity-mapped range */
    if (strings_addr + strings_size > (uintptr_t)MMIO_IDENTITY_LIMIT) {
        kprintf("execve: stack region outside identity map\n");
        return -1;
    }

    /* copy strings into their place */
    char *str_dst = (char*)(uintptr_t)strings_addr;
    char **argv_ptrs = (char**)(uintptr_t)ptrs_addr;
    for (int i = 0; i < argc; i++) {
        size_t l = strlen(argv[i]) + 1;
        memcpy(str_dst, argv[i], l);
        argv_ptrs[i] = (char*)(uintptr_t)str_dst;
        str_dst += l;
    }
    argv_ptrs[argc] = NULL;
    argv_ptrs[argc+1] = NULL; /* envp NULL */

    /* write argc at final_stack (RSP will point here) */
    *((uint64_t*)(uintptr_t)final_stack) = (uint64_t)argc;


    /* register user thread info for debugger/listing purposes and allocate kernel stack */
    thread_t *ut = thread_register_user(entry, final_stack, path);
    if (ut) {
        /* allocate kernel stack for the user thread so hardware can switch to a valid RSP0 */
        void *kst = kmalloc(8192 + 16);
        if (kst) {
            ut->kernel_stack = (uint64_t)kst + 8192 + 16;
            tss_set_rsp0(ut->kernel_stack);
            kprintf("execve: allocated kernel_stack=%p for user thread tid=%llu\n", (void*)(uintptr_t)ut->kernel_stack, (unsigned long long)ut->tid);
        } else {
            kprintf("execve: WARNING: failed to allocate kernel stack for user thread\n");
        }
    } else {
        kprintf("execve: WARNING: thread_register_user failed\n");
    }

    /* Sanity checks & probes before entering user mode to avoid silent triple-faults.
       - Verify entry and stack are within identity-mapped region.
       - Touch stack memory and read first byte at entry (if readable). */
    kprintf("execve: entry=0x%llx final_stack=0x%llx argc=%d\n",
        (unsigned long long)entry, (unsigned long long)final_stack, argc);

    /* Debug: print CR3, GDTR base and kernel rsp0 to help debug privilege switch */
    {
        uint64_t cr3 = 0;
        asm volatile("mov %%cr3, %0" : "=r"(cr3));
        struct { uint16_t limit; uint64_t base; } gdtr;
        asm volatile("sgdt %0" : "=m"(gdtr));
        extern uint64_t syscall_kernel_rsp0;
        kprintf("execve: CR3=0x%llx GDTR.base=0x%llx GDTR.limit=%u rsp0=0x%llx\n",
            (unsigned long long)cr3, (unsigned long long)gdtr.base, (unsigned)gdtr.limit,
            (unsigned long long)syscall_kernel_rsp0);
    }

    /* Debug helper: dump page-table entries for a virtual address */
    {
        extern uint64_t page_table_l4[];
        void dump_va(uint64_t va) {
            uint64_t l4i = (va >> 39) & 0x1FF;
            uint64_t l3i = (va >> 30) & 0x1FF;
            uint64_t l2i = (va >> 21) & 0x1FF;
            uint64_t l1i = (va >> 12) & 0x1FF;
            uint64_t *l4 = (uint64_t*)page_table_l4;
            kprintf("pte dump for va=0x%llx: L4[%llu]=0x%016llx\n", (unsigned long long)va, (unsigned long long)l4i, (unsigned long long)l4[l4i]);
            if (!(l4[l4i] & PG_PRESENT)) return;
            uint64_t *l3 = (uint64_t*)(uintptr_t)(l4[l4i] & ~0xFFFULL);
            kprintf(" L3[%llu]=0x%016llx\n", (unsigned long long)l3i, (unsigned long long)l3[l3i]);
            if (l3[l3i] & PG_PS_2M) return;
            uint64_t *l2 = (uint64_t*)(uintptr_t)(l3[l3i] & ~0xFFFULL);
            kprintf("  L2[%llu]=0x%016llx\n", (unsigned long long)l2i, (unsigned long long)l2[l2i]);
            if (l2[l2i] & PG_PS_2M) return;
            uint64_t *l1 = (uint64_t*)(uintptr_t)(l2[l2i] & ~0xFFFULL);
            kprintf("   L1[%llu]=0x%016llx\n", (unsigned long long)l1i, (unsigned long long)l1[l1i]);
        }
        kprintf("PTEs for entry:\n"); dump_va((uint64_t)entry);
        kprintf("PTEs for final_stack:\n"); dump_va((uint64_t)final_stack);
    }

    if ((uintptr_t)entry >= (uintptr_t)MMIO_IDENTITY_LIMIT || (uintptr_t)final_stack >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
        kprintf("execve: entry or stack outside identity-mapped region, abort\n");
        return -1;
    }

    /* touch stack pages (write to several words to ensure allocation/mapping) */
    volatile uint64_t *stk = (volatile uint64_t*)(uintptr_t)final_stack;
    for (int i = 0; i < 8; i++) {
        stk[i] = 0xDEADBEEFu ^ (uint64_t)i;
    }
    
    /* try to read first byte of entry */
    volatile uint8_t *entry_b = (volatile uint8_t*)(uintptr_t)entry;
    uint8_t first = 0;
    /* wrap read in a benign check */
    first = entry_b[0];
    kprintf("execve: entry[0]=0x%02x\n", (unsigned)first);

    /* Transfer to user mode (does not return) */
    enter_user_mode(entry, final_stack);
    return 0; /* not reached */
}


