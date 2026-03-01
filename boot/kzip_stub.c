#include <stdint.h>
#include <stddef.h>

extern const unsigned char _binary_build_payload_lz4_start[];
extern const unsigned char _binary_build_payload_lz4_end[];

typedef struct __attribute__((packed)) {
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
} elf64_ehdr_t;

typedef struct __attribute__((packed)) {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} elf64_phdr_t;

enum {
    PT_LOAD = 1,
    LZ4F_MAGIC = 0x184D2204u
};

enum {
    MB2_COPY_ADDR = 0x3F000000u,
    MB2_COPY_MAX  = 2u * 1024u * 1024u
};

static void *memcpy_local(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

static void *memset_local(void *dst, int c, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    for (size_t i = 0; i < n; i++) d[i] = (uint8_t)c;
    return dst;
}

enum {
    VGA_COLS = 80,
    VGA_ROWS = 25,
    VGA_ATTR = 0x07
};

static uint16_t g_vga_col = 0;
static uint16_t g_vga_row = 2;

static inline void io_out8(uint16_t port, uint8_t val) {
    __asm__ volatile("outb %0, %1" :: "a"(val), "Nd"(port));
}

static inline uint8_t io_in8(uint16_t port) {
    uint8_t v;
    __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

static uint16_t vga_hw_get_cursor_cell(void) {
    io_out8(0x3D4, 14);
    uint16_t hi = (uint16_t)io_in8(0x3D5);
    io_out8(0x3D4, 15);
    uint16_t lo = (uint16_t)io_in8(0x3D5);
    return (uint16_t)((hi << 8) | lo);
}

static void vga_hw_set_cursor_cell(uint16_t cell) {
    io_out8(0x3D4, 14);
    io_out8(0x3D5, (uint8_t)(cell >> 8));
    io_out8(0x3D4, 15);
    io_out8(0x3D5, (uint8_t)(cell & 0xFF));
}

static void vga_cursor_sync_hw(void) {
    uint16_t cell = (uint16_t)(g_vga_row * VGA_COLS + g_vga_col);
    vga_hw_set_cursor_cell(cell);
}

static void vga_cursor_init(void) {
    uint16_t cell = vga_hw_get_cursor_cell();
    uint16_t row = (uint16_t)(cell / VGA_COLS);
    uint16_t col = (uint16_t)(cell % VGA_COLS);
    if (row >= VGA_ROWS) {
        g_vga_row = 2;
        g_vga_col = 0;
    } else {
        g_vga_row = row;
        g_vga_col = col;
        if (g_vga_row < 2) g_vga_row = 2;
    }
    vga_cursor_sync_hw();
}

static void vga_scroll_up_one(void) {
    volatile uint8_t *vga = (volatile uint8_t *)(uintptr_t)0xB8000;
    size_t row_bytes = VGA_COLS * 2;
    for (size_t r = 1; r < VGA_ROWS; r++) {
        for (size_t i = 0; i < row_bytes; i++) {
            vga[(r - 1) * row_bytes + i] = vga[r * row_bytes + i];
        }
    }
    size_t base = (VGA_ROWS - 1) * row_bytes;
    for (size_t c = 0; c < VGA_COLS; c++) {
        vga[base + c * 2] = ' ';
        vga[base + c * 2 + 1] = VGA_ATTR;
    }
    g_vga_row = VGA_ROWS - 1;
    g_vga_col = 0;
    vga_cursor_sync_hw();
}

static void vga_cursor_newline(void) {
    g_vga_col = 0;
    g_vga_row++;
    if (g_vga_row >= VGA_ROWS) vga_scroll_up_one();
    vga_cursor_sync_hw();
}

static void vga_putc(char ch) {
    volatile uint8_t *vga = (volatile uint8_t *)(uintptr_t)0xB8000;
    if (ch == '\n') {
        vga_cursor_newline();
        return;
    }
    if (ch == '\r') {
        g_vga_col = 0;
        vga_cursor_sync_hw();
        return;
    }
    if (ch == '\t') {
        uint16_t next = (uint16_t)((g_vga_col + 8) & ~7u);
        if (next >= VGA_COLS) {
            vga_cursor_newline();
        } else {
            g_vga_col = next;
            vga_cursor_sync_hw();
        }
        return;
    }
    if (ch == '\b') {
        if (g_vga_col > 0) g_vga_col--;
        size_t idxb = (size_t)(g_vga_row * VGA_COLS + g_vga_col) * 2;
        vga[idxb] = ' ';
        vga[idxb + 1] = VGA_ATTR;
        vga_cursor_sync_hw();
        return;
    }

    if (g_vga_col >= VGA_COLS) vga_cursor_newline();
    size_t idx = (size_t)(g_vga_row * VGA_COLS + g_vga_col) * 2;
    vga[idx] = (uint8_t)ch;
    vga[idx + 1] = VGA_ATTR;
    g_vga_col++;
    if (g_vga_col >= VGA_COLS) vga_cursor_newline();
    else vga_cursor_sync_hw();
}

static void vga_puts(const char *s) {
    while (*s) vga_putc(*s++);
}

static void boot_line(const char *s) {
    vga_puts(s);
}

static int is_elf64_image(const uint8_t *p, size_t n) {
    if (!p || n < 6) return 0;
    if (p[0] != 0x7F || p[1] != 'E' || p[2] != 'L' || p[3] != 'F') return 0;
    return (p[4] == 2 && p[5] == 1);
}

__attribute__((noreturn)) static void panic_msg(const char *msg) {
    boot_line(msg);
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) {
    uint64_t lo = rd32(p);
    uint64_t hi = rd32(p + 4);
    return lo | (hi << 32);
}

/* The payload is loaded at low addresses (around 1 MiB) and can overwrite
   the original Multiboot2 info block placed by GRUB in low memory.
   Preserve MB2 info before ELF loading and pass relocated pointer onward. */
static uint64_t preserve_multiboot_info(uint64_t multiboot_info) {
    if (multiboot_info == 0) return 0;
    const uint8_t *src = (const uint8_t *)(uintptr_t)multiboot_info;
    uint32_t total_size = rd32(src);
    if (total_size < 16 || total_size > MB2_COPY_MAX) {
        return multiboot_info;
    }
    uint8_t *dst = (uint8_t *)(uintptr_t)MB2_COPY_ADDR;
    memcpy_local(dst, src, (size_t)total_size);
    return (uint64_t)(uintptr_t)dst;
}

static int lz4_raw_decompress_block(const uint8_t *src, size_t src_len,
                                    uint8_t *dst, size_t dst_cap,
                                    size_t *out_written) {
    const uint8_t *ip = src;
    const uint8_t *iend = src + src_len;
    uint8_t *op = dst;
    uint8_t *oend = dst + dst_cap;

    while (ip < iend) {
        uint8_t token = *ip++;
        size_t lit_len = (size_t)(token >> 4);
        if (lit_len == 15) {
            for (;;) {
                if (ip >= iend) return -1;
                uint8_t s = *ip++;
                lit_len += (size_t)s;
                if (s != 255) break;
            }
        }

        if ((size_t)(iend - ip) < lit_len) return -1;
        if ((size_t)(oend - op) < lit_len) return -1;
        memcpy_local(op, ip, lit_len);
        ip += lit_len;
        op += lit_len;

        if (ip >= iend) break;

        if ((size_t)(iend - ip) < 2) return -1;
        uint32_t offset = (uint32_t)ip[0] | ((uint32_t)ip[1] << 8);
        ip += 2;
        if (offset == 0 || offset > (uint32_t)(op - dst)) return -1;

        size_t match_len = (size_t)(token & 0x0F);
        if (match_len == 15) {
            for (;;) {
                if (ip >= iend) return -1;
                uint8_t s = *ip++;
                match_len += (size_t)s;
                if (s != 255) break;
            }
        }
        match_len += 4;
        if ((size_t)(oend - op) < match_len) return -1;

        uint8_t *m = op - offset;
        for (size_t i = 0; i < match_len; i++) op[i] = m[i];
        op += match_len;
    }

    *out_written = (size_t)(op - dst);
    return 0;
}

static int lz4f_decompress(const uint8_t *src, size_t src_len,
                           uint8_t *dst, size_t dst_cap,
                           size_t *out_size) {
    const uint8_t *p = src;
    const uint8_t *end = src + src_len;
    uint64_t content_size = 0;

    if ((size_t)(end - p) < 7) return -1;
    if (rd32(p) != LZ4F_MAGIC) return -1;
    p += 4;

    uint8_t flg = *p++;
    uint8_t bd = *p++;
    (void)bd;

    if (((flg >> 6) & 0x3) != 0x1) return -1;

    if (flg & 0x08) {
        if ((size_t)(end - p) < 8) return -1;
        content_size = rd64(p);
        p += 8;
    }
    if (flg & 0x01) {
        if ((size_t)(end - p) < 4) return -1;
        p += 4;
    }
    if ((size_t)(end - p) < 1) return -1;
    p += 1; /* header checksum */

    size_t out_off = 0;
    for (;;) {
        if ((size_t)(end - p) < 4) return -1;
        uint32_t blk = rd32(p);
        p += 4;
        if (blk == 0) break;

        uint32_t is_raw = blk & 0x80000000u;
        uint32_t blk_size = blk & 0x7FFFFFFFu;
        if (blk_size == 0 || (size_t)(end - p) < blk_size) return -1;

        if (is_raw) {
            if (out_off + blk_size > dst_cap) return -1;
            memcpy_local(dst + out_off, p, blk_size);
            out_off += blk_size;
        } else {
            size_t wrote = 0;
            if (lz4_raw_decompress_block(p, blk_size, dst + out_off, dst_cap - out_off, &wrote) != 0) return -1;
            out_off += wrote;
        }
        p += blk_size;
    }

    if (content_size != 0 && out_off != (size_t)content_size) return -1;
    *out_size = out_off;
    return 0;
}

static int load_elf_image(const uint8_t *img, size_t img_len, uint64_t *entry_out) {
    if (img_len < sizeof(elf64_ehdr_t)) return -1;
    const elf64_ehdr_t *eh = (const elf64_ehdr_t *)img;
    if (eh->e_ident[0] != 0x7F || eh->e_ident[1] != 'E' || eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F') return -1;
    if (eh->e_ident[4] != 2 || eh->e_ident[5] != 1) return -1;
    if (eh->e_phoff == 0 || eh->e_phnum == 0 || eh->e_phentsize != sizeof(elf64_phdr_t)) return -1;
    if ((uint64_t)eh->e_phoff + (uint64_t)eh->e_phnum * (uint64_t)sizeof(elf64_phdr_t) > (uint64_t)img_len) return -1;

    const elf64_phdr_t *ph = (const elf64_phdr_t *)(img + eh->e_phoff);
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_offset + ph[i].p_filesz > (uint64_t)img_len) return -1;

        uintptr_t dst = (uintptr_t)(ph[i].p_vaddr ? ph[i].p_vaddr : ph[i].p_paddr);
        if (dst == 0) return -1;

        memcpy_local((void *)dst, img + ph[i].p_offset, (size_t)ph[i].p_filesz);
        if (ph[i].p_memsz > ph[i].p_filesz) {
            memset_local((void *)(dst + (uintptr_t)ph[i].p_filesz), 0, (size_t)(ph[i].p_memsz - ph[i].p_filesz));
        }
    }

    *entry_out = eh->e_entry;
    return 0;
}

void kernel_main(uint64_t multiboot_magic, uint64_t multiboot_info) {
    const uint8_t *payload_lz4 = _binary_build_payload_lz4_start;
    size_t payload_lz4_len = (size_t)(_binary_build_payload_lz4_end - _binary_build_payload_lz4_start);

    uint8_t *decomp = (uint8_t *)(uintptr_t)0x30000000u;
    const size_t decomp_cap = 128u * 1024u * 1024u;
    size_t decomp_len = 0;
    uint64_t entry = 0;
    uint64_t preserved_multiboot_info = preserve_multiboot_info(multiboot_info);

    vga_cursor_init();
    if (payload_lz4_len == 0) panic_msg("KZIP: empty payload");
    if (rd32(payload_lz4) == LZ4F_MAGIC) {
        boot_line("Decompressing kernel...");
        if (lz4f_decompress(payload_lz4, payload_lz4_len, decomp, decomp_cap, &decomp_len) != 0) {
            panic_msg("KZIP: lz4 decode fail");
        }
        boot_line("ok\n");
    } else if (is_elf64_image(payload_lz4, payload_lz4_len)) {
        boot_line("Loading kernel without compression... ok\n");
        decomp = (uint8_t *)(uintptr_t)payload_lz4;
        decomp_len = payload_lz4_len;
    } else {
        panic_msg("KZIP: unknown payload format!");
    }

    boot_line("Parsing ELF...");
    if (load_elf_image(decomp, decomp_len, &entry) != 0) panic_msg("KZIP: ELF load fail!");
    boot_line("ok\n");
    if (entry == 0) panic_msg("KZIP: bad entry!");

    boot_line("Jumping to kernel entry... ok\n");
    ((void (*)(uint64_t, uint64_t))(uintptr_t)entry)(multiboot_magic, preserved_multiboot_info);
    panic_msg("KZIP: payload returned.");
}
