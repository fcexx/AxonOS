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

/* Parse ELF file in memory and load PT_LOAD segments into target virtual addresses.
   The loader is careful not to overwrite kernel region. Loaded segments are copied
   into the segment's p_vaddr (assumes identity mapping for VA < 4GiB). */
int elf_load_from_memory(const void *buf, size_t len, uint64_t *out_entry);

/* Convenience: load ELF from filesystem path (reads whole file). */
int elf_load_from_path(const char *path, uint64_t *out_entry);


