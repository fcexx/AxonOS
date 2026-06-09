#pragma once

#include <stdint.h>
#include <stddef.h>

/* Minimal ELF64 types used by loader */
typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

typedef struct {
    int64_t d_tag;
    uint64_t d_un;
} Elf64_Dyn;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t r_addend;
} Elf64_Rela;

#define ELF64_R_TYPE(i)   ((uint32_t)((i) & 0xffffffffu))
#define ELF64_R_SYM(i)    ((uint32_t)((i) >> 32))

enum {
    ELF_PT_LOAD    = 1,
    ELF_PT_DYNAMIC = 2,
    ELF_DT_NULL    = 0,
    ELF_DT_RELA    = 7,
    ELF_DT_RELASZ  = 8,
    ELF_DT_RELAENT = 9,
    ELF_R_X86_64_RELATIVE = 8,
};

typedef struct {
    uint64_t vaddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
} elf_tls_info_t;

typedef struct {
    uint64_t entry;
    uint64_t load_base;
    uint64_t brk_end;
    uint64_t phdr;
    uint64_t phent;
    uint64_t phnum;
    uint64_t loaded_lo;
    uint64_t loaded_hi;
    uint16_t e_type;
    int has_interp;
    int has_dynamic;
    char interp_path[192];
} elf_load_info_t;

/* Parse ELF file in memory and load PT_LOAD segments into target virtual addresses.
   The loader is careful not to overwrite kernel region. Loaded segments are copied
   into the segment's p_vaddr (assumes identity mapping for VA < 4GiB). */
int elf_load_from_memory(const void *buf, size_t len, uint64_t *out_entry);

/* Convenience: load ELF from filesystem path (reads whole file).
   If out_brk_end is non-NULL, stores the program break end (end of last PT_LOAD) there. */
int elf_load_from_path(const char *path, uint64_t *out_entry, uintptr_t *out_brk_end, elf_tls_info_t *out_tls);

int elf_load_from_path_info(const char *path, uint64_t load_base_override,
                            elf_load_info_t *out_info, elf_tls_info_t *out_tls);


