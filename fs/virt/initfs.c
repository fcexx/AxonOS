/*
 * fs/virt/initfs.c
 * Initfs unpacker: find Multiboot2 module named "initfs" and extract cpio (newc) into VFS
 * Author: fcexx
*/

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <axonos.h>
#include <fs.h>
#include <ramfs.h>
#include <heap.h>
#include <vga.h>
#include <initfs.h>

/* cpio newc header (ASCII hex fields) - 110 bytes total */
struct cpio_newc_header {
    char c_magic[6];
    char c_ino[8];
    char c_mode[8];
    char c_uid[8];
    char c_gid[8];
    char c_nlink[8];
    char c_mtime[8];
    char c_filesize[8];
    char c_devmajor[8];
    char c_devminor[8];
    char c_rdevmajor[8];
    char c_rdevminor[8];
    char c_namesize[8];
    char c_check[8];
};

static uint32_t hex_to_uint(const char *hex, size_t length) {
    uint32_t r = 0;
    for (size_t i = 0; i < length; i++) {
        r <<= 4;
        char c = hex[i];
        if (c >= '0' && c <= '9') r |= (uint32_t)(c - '0');
        else if (c >= 'A' && c <= 'F') r |= (uint32_t)(c - 'A' + 10);
        else if (c >= 'a' && c <= 'f') r |= (uint32_t)(c - 'a' + 10);
        else /* ignore unexpected */ ;
    }
    return r;
}

/* Check that a buffer contains only ASCII hex digits (0-9A-Fa-f) */
static int is_hex_string(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

/* Quick plausibility check for a cpio newc header.
   remaining = bytes available from header start to end of module. */
static int plausible_cpio_header(const struct cpio_newc_header *h, size_t remaining) {
    /* need at least header present */
    if (remaining < sizeof(*h)) return 0;
    /* all numeric fields are ASCII hex strings */
    if (!is_hex_string(h->c_ino, 8)) return 0;
    if (!is_hex_string(h->c_mode, 8)) return 0;
    if (!is_hex_string(h->c_uid, 8)) return 0;
    if (!is_hex_string(h->c_gid, 8)) return 0;
    if (!is_hex_string(h->c_nlink, 8)) return 0;
    if (!is_hex_string(h->c_mtime, 8)) return 0;
    if (!is_hex_string(h->c_filesize, 8)) return 0;
    if (!is_hex_string(h->c_devmajor, 8)) return 0;
    if (!is_hex_string(h->c_devminor, 8)) return 0;
    if (!is_hex_string(h->c_rdevmajor, 8)) return 0;
    if (!is_hex_string(h->c_rdevminor, 8)) return 0;
    if (!is_hex_string(h->c_namesize, 8)) return 0;
    /* parse namesize/filesize and verify bounds */
    uint32_t namesize = hex_to_uint(h->c_namesize, 8);
    uint32_t filesize = hex_to_uint(h->c_filesize, 8);
    /* namesize must be at least 1 (includes terminating NUL) and reasonably small */
    if (namesize == 0 || namesize > 65536) return 0;
    /* header + namesize must fit */
    if (sizeof(*h) + namesize > remaining) return 0;
    /* file data must fit (with 4-byte alignment for data start) */
    size_t after_name = sizeof(*h) + namesize;
    size_t file_data_offset = (after_name + 3) & ~3u;
    if (file_data_offset + (size_t)filesize > remaining) return 0;
    return 1;
}

/* Check that a CPIO filename looks like a sane path. This helps avoid false
   positives when "070701" appears inside binary data. */
static int plausible_cpio_name(const char *name, uint32_t namesize) {
    if (!name || namesize == 0) return 0;
    /* name must be NUL-terminated within namesize */
    if (name[namesize - 1] != '\0') return 0;
    /* allow TRAILER!!! marker */
    if (strcmp(name, "TRAILER!!!") == 0) return 1;
    /* basic character whitelist */
    for (uint32_t i = 0; i + 1 < namesize; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c == 0) break;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) continue;
        if (c == '_' || c == '-' || c == '.' || c == '/') continue;
        return 0;
    }
    return 1;
}

/* Find a reliable starting offset of a cpio newc stream within a buffer.
   Prefer offset 0 if it looks valid; otherwise scan for a header that is
   plausible AND is followed by another header at the computed next offset. */
static size_t find_cpio_start(const uint8_t *base, size_t archive_size) {
    if (!base || archive_size < sizeof(struct cpio_newc_header)) return (size_t)-1;

    /* fast path: archive begins with magic */
    if ((memcmp(base, "070701", 6) == 0 || memcmp(base, "070702", 6) == 0) &&
        plausible_cpio_header((const struct cpio_newc_header*)base, archive_size)) {
        const struct cpio_newc_header *h0 = (const struct cpio_newc_header*)base;   
        uint32_t namesize0 = hex_to_uint(h0->c_namesize, 8);
        const char *name0 = (const char*)(base + sizeof(*h0));
        if (namesize0 > 0 && sizeof(*h0) + (size_t)namesize0 <= archive_size &&
            plausible_cpio_name(name0, namesize0)) {
            return 0;
        }
    }

    /* scan for candidate headers */
    for (size_t i = 0; i + sizeof(struct cpio_newc_header) <= archive_size; i++) {
        if (!(memcmp(base + i, "070701", 6) == 0 || memcmp(base + i, "070702", 6) == 0)) continue;
        const struct cpio_newc_header *h = (const struct cpio_newc_header*)(base + i);
        if (!plausible_cpio_header(h, archive_size - i)) continue;
        uint32_t namesize = hex_to_uint(h->c_namesize, 8);
        uint32_t filesize = hex_to_uint(h->c_filesize, 8);
        if (sizeof(*h) + (size_t)namesize > archive_size - i) continue;
        const char *name = (const char*)(base + i + sizeof(*h));
        if (!plausible_cpio_name(name, namesize)) continue;

        /* verify that the computed next header boundary also has magic */
        size_t after_name = sizeof(*h) + (size_t)namesize;
        size_t file_data_offset = (after_name + 3) & ~3u;
        size_t next = file_data_offset + (size_t)filesize;
        next = (next + 3) & ~3u;
        if (next <= file_data_offset) continue;
        if (i + next + 6 <= archive_size) {
            const uint8_t *nm = base + i + next;
            if (memcmp(nm, "070701", 6) == 0 || memcmp(nm, "070702", 6) == 0) {
                return i;
            }
        }
    }

    return (size_t)-1;
}

/* Ensure all parent directories for `path` exist. Path must be absolute. */
static void ensure_parent_dirs(const char *path) {
    if (!path || path[0] != '/') return;
    /* iterate through path and call ramfs_mkdir for each prefix */
    size_t len = strlen(path);
    char tmp[512];
    if (len >= sizeof(tmp)) return;
    strcpy(tmp, path);
    /* remove trailing slash if any */
    if (len > 1 && tmp[len-1] == '/') tmp[len-1] = '\0';
    for (size_t i = 1; i < strlen(tmp); i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            ramfs_mkdir(tmp);
            tmp[i] = '/';
        }
    }
    /* also ensure full parent (directory containing the file) */
    char *slash = strrchr(tmp, '/');
    if (slash && slash != tmp) {
        *slash = '\0';
        ramfs_mkdir(tmp);
    } else {
        /* parent is root - already exists */
    }
}

/* Create file at path and write data (size bytes). Returns 0 on success. */
static int create_file_with_data(const char *path, const void *data, size_t size) {
    struct fs_file *f = fs_create_file(path);
    if (!f) {
        return -1;
    }
    /* Ensure the created handle is recognized as a regular file by VFS/drivers.
       Some drivers may return ambiguous types; force FS_TYPE_REG for initfs-created files. */
    f->type = FS_TYPE_REG;
    ssize_t written = fs_write(f, data, size, 0);
    fs_file_free(f);
    if (written < 0 || (size_t)written != size) {
        klogprintf("initfs: write failed %s\n", path);
        return -2;
    }
    return 0;
}

/* Unpack cpio newc archive at archive (size bytes) into VFS root. */
static int unpack_cpio_newc(const void *archive, size_t archive_size) {
    const uint8_t *base = (const uint8_t*)archive;
    size_t offset = 0;
    /* Find reliable start of a CPIO stream. */
    size_t found = find_cpio_start(base, archive_size);
    if (found == (size_t)-1) {
        klogprintf("initfs: cpio magic not found in module (size %u)\n", (unsigned)archive_size);
        return -1;
    }
    if (found != 0) klogprintf("initfs: cpio magic found\n");
    offset = found;

    while (offset + sizeof(struct cpio_newc_header) <= archive_size) {
        const struct cpio_newc_header *h = (const struct cpio_newc_header*)(base + offset);
        /* header.magic is 6 bytes ASCII "070701" (newc) or "070702" (newc with CRC).
           Compare raw bytes from the module to avoid any struct/padding surprises. */
        const uint8_t *magic = base + offset;
        if (!((memcmp(magic, "070701", 6) == 0) || (memcmp(magic, "070702", 6) == 0))) {
            /* Quietly skip this partial/non-matching occurrence and search forward
               for the next complete ASCII magic. This avoids noisy '.07070' debug lines. */
            size_t next_found = (size_t)-1;
            for (size_t j = offset + 1; j + 6 <= archive_size; j++) {
                if (memcmp(base + j, "070701", 6) == 0 || memcmp(base + j, "070702", 6) == 0) { next_found = j; break; }
            }
            if (next_found != (size_t)-1) {
                offset = next_found;
                continue;
            }
            return -1;
        }
        /* additional plausibility check to avoid false positives where "070701"
           appears inside file data */
        if (!plausible_cpio_header(h, archive_size - offset)) {
            /* header not plausible: search for next magic and continue */
            //kprintf("initfs: header not plausible at offset %u, searching next\n", (unsigned)offset);
            size_t next_found = (size_t)-1;
            for (size_t j = offset + 1; j + 6 <= archive_size; j++) {
                if (memcmp(base + j, "070701", 6) == 0 || memcmp(base + j, "070702", 6) == 0) { next_found = j; break; }
            }
            if (next_found != (size_t)-1) {
                offset = next_found;
                continue;
            }
            return -1;
        }
        uint32_t namesize = hex_to_uint(h->c_namesize, 8);
        uint32_t filesize = hex_to_uint(h->c_filesize, 8);
        size_t header_size = sizeof(struct cpio_newc_header);
        size_t name_offset = offset + header_size;
        if (name_offset + namesize > archive_size) {
            klogprintf("initfs: error: name extends past archive\n");
            return -1;
        }
        const char *name = (const char*)(base + name_offset);
        /* end of archive marker */
        if (strcmp(name, "TRAILER!!!") == 0) break;
        /* compute data offset (header + namesize aligned to 4) */
        size_t after_name = name_offset + namesize;
        size_t file_data_offset = (after_name + 3) & ~3u;
        if (file_data_offset + filesize > archive_size) {
            klogprintf("initfs: error: file data extends past archive for %s\n", name);
            return -1;
        }
        /* build target path: ensure leading slash */
        char target[512];
        if (name[0] == '/') {
            strncpy(target, name, sizeof(target)-1);
            target[sizeof(target)-1] = '\0';
        } else {
            /* make absolute */
            target[0] = '/';
            size_t n = strlen(name);
            if (n > sizeof(target)-2) n = sizeof(target)-2;
            memcpy(target+1, name, n);
            target[1+n] = '\0';
        }
        /* determine mode */
        uint32_t mode = hex_to_uint(h->c_mode, 8);
        if ((mode & 0170000u) == 0040000u || (target[strlen(target)-1] == '/')) {
            /* directory */
            /* strip trailing slash */
            size_t tl = strlen(target);
            if (tl > 1 && target[tl-1] == '/') target[tl-1] = '\0';
            if (ramfs_mkdir(target) < 0) {
                /* ignore existing or other minor errors */
            }
        } else if ((mode & 0170000u) == 0100000u) {
            /* regular file */
            ensure_parent_dirs(target);
            const void *file_data = base + file_data_offset;
            if (create_file_with_data(target, file_data, filesize) != 0) {
                klogprintf("initfs: warning: failed to create %s (ingore)\n", target);
            }
        } else if ((mode & 0170000u) == 0120000u) {
            /* symbolic link: file data contains link target */
            ensure_parent_dirs(target);
            const void *file_data = base + file_data_offset;
            /* make a NUL-terminated copy of link target */
            size_t tlen = filesize;
            char *linkt = (char*)kmalloc(tlen + 1);
            if (linkt) {
                memcpy(linkt, file_data, tlen);
                linkt[tlen] = '\0';
                if (ramfs_symlink(target, linkt) < 0) {
                    klogprintf("initfs: warning: failed to create symlink %s -> %s\n", target, linkt);
                }
                kfree(linkt);
            } else {
                klogprintf("initfs: warning: failed to alloc for symlink %s\n", target);
            }
        } else {
            /* other types (device, fifo...) - skip for now */
            //kprintf("initfs: skipping special file %s (mode %o)\n", target, mode);
        }
        /* advance offset to next header (file data aligned to 4).
           Protect against malformed tag_size/filesize that would yield zero
           or overflow and cause an infinite loop. */
        size_t next = file_data_offset + filesize;
        /* Basic sanity: next must be greater than current offset and within archive */
        if (next <= offset || next > archive_size) {
            return -1;
        }
        next = (next + 3) & ~3u;
        if (next <= offset) {
            return -1;
        }
        offset = next;
    }
    return 0;
}

/* Scan multiboot2 tags for module named `module_name` and unpack it. */
int initfs_process_multiboot_module(uint32_t multiboot_magic, uint64_t multiboot_info, const char *module_name) {
    if (multiboot_magic != 0x36d76289u) {
        klogprintf("initfs: fatal: not multiboot2 magic=0x%x\n", (unsigned)multiboot_magic);
        return 2;
    }
    if (multiboot_info == 0) {
        klogprintf("initfs: fatal: multiboot_info is NULL\n");
        return 3;
    }
    uint8_t *p = (uint8_t*)(uintptr_t)multiboot_info;
    uint32_t total_size = *(uint32_t*)p;
    /* Deep diagnostic: print header + first tags; this helps when some VMs
       pass different structures / pointers. */
    if (total_size < 16 || total_size > (64u * 1024u * 1024u)) {
        klogprintf("initfs: suspicious total_size=%u, aborting mb2 scan\n", (unsigned)total_size);
        return 4;
    }
    uint32_t offset = 8; /* tags start after total_size + reserved */
    uint32_t tag_count = 0;
    while (offset + 8 <= total_size) {
        if (++tag_count > 1024) break;
        uint32_t tag_type = *(uint32_t*)(p + offset);
        uint32_t tag_size = *(uint32_t*)(p + offset + 4);
        /* Basic sanity checks to avoid infinite loops on malformed multiboot data */
        if (tag_size < 8) break;
        if ((uint64_t)offset + (uint64_t)tag_size > (uint64_t)total_size) break;
        if (tag_type == 0) break; /* end */
        if (tag_type == 3) { /* module */
            /* Multiboot2 module tag layout is ALWAYS:
               u32 mod_start, u32 mod_end, then NUL-terminated cmdline string.
               (Even for 64-bit kernels, addresses here are 32-bit physical). */
            if (tag_size < 16) { /* 8 header + 4 + 4 */
                /* malformed */
            } else {
                const uint8_t *field_ptr = p + offset + 8;
                uint32_t ms32 = *(uint32_t*)(field_ptr);
                uint32_t me32 = *(uint32_t*)(field_ptr + 4);
                uint64_t mod_start = (uint64_t)ms32;
                uint64_t mod_end = (uint64_t)me32;
                size_t name_field_offset = offset + 16;
                const char *name = (const char*)(p + name_field_offset);
            if (strcmp(name, module_name) == 0) {
                size_t mod_size = mod_end > mod_start ? (size_t)(mod_end - mod_start) : 0;
                const void *mod_ptr = (const void*)(uintptr_t)mod_start;
                klogprintf("initfs: found module '%s' at %p size %u\n", module_name, mod_ptr, (unsigned)mod_size);
                if (mod_size == 0) return -2;
                /* Diagnostic / robustness: attempt to copy module into heap and unpack from there.
                   This can bypass issues with remapped/readonly regions in some VMs. */
                void *buf = kmalloc(mod_size);
                if (buf) {
                    memcpy(buf, mod_ptr, mod_size);
                    int r = unpack_cpio_newc(buf, mod_size);
                    kfree(buf);
                    if (r == 0) return 0;
                } else {
                    /* kmalloc failed - will try direct unpack */
                }
                /* fallback: try direct unpack from module pointer */
                return unpack_cpio_newc(mod_ptr, mod_size);
            }
            }
        }
        /* align to 8 bytes */
        uint32_t next = (tag_size + 7) & ~7u;
        offset += next;
    }
    /* If we didn't find a multiboot module, attempt a tolerant fallback:
       scan low physical memory for a cpio newc magic ("070701"/"070702")
       and try to unpack from there. This handles environments where the
       bootloader did not provide multiboot module tags (some VMs/loaders). */
    {
        const uintptr_t scan_start = 0x10000; /* 64KB */
        const uintptr_t scan_end = 0x4000000; /* 64MB (increased from 16MB for deeper scan) */
        const uint8_t *mem = (const uint8_t*)(uintptr_t)scan_start;
        for (uintptr_t a = scan_start; a + 6 <= scan_end; a++) {
            const uint8_t *p6 = (const uint8_t*)(uintptr_t)a;
            if (memcmp(p6, "070701", 6) == 0 || memcmp(p6, "070702", 6) == 0) {
                size_t remaining = (size_t)(scan_end - a);
                if (remaining >= sizeof(struct cpio_newc_header) && plausible_cpio_header((const struct cpio_newc_header*)p6, remaining)) {
                    int r = unpack_cpio_newc(p6, remaining);
                    if (r == 0) return 0;
                }
            }
        }
    }
    return 1; /* module not found */
}
