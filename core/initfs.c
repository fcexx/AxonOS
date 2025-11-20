/* initfs unpacker: find Multiboot2 module named "initfs" and extract cpio (newc) into VFS.
   Code style aims to be clear and Linux-like.
*/
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <axonos.h>
#include <fs.h>
#include <ramfs.h>
#include <heap.h>
#include "../inc/initfs.h"

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
        kprintf("initfs: cannot create file %s\n", path);
        return -1;
    }
    ssize_t written = fs_write(f, data, size, 0);
    fs_file_free(f);
    if (written < 0 || (size_t)written != size) {
        kprintf("initfs: write failed %s\n", path);
        return -2;
    }
    return 0;
}

/* Unpack cpio newc archive at archive (size bytes) into VFS root. */
static int unpack_cpio_newc(const void *archive, size_t archive_size) {
    const uint8_t *base = (const uint8_t*)archive;
    size_t offset = 0;
    /* Найдём самое первое вхождение "070701"/"070702" (cpio newc) и дальше
       идём строго последовательно, как по обычному архиву initramfs. */
    if (archive_size < sizeof(struct cpio_newc_header)) {
        kprintf("initfs: module too small for cpio header\n");
        return -1;
    }
    size_t start = (size_t)-1;
    for (size_t i = 0; i + 6 <= archive_size; i++) {
        if (memcmp(base + i, "070701", 6) == 0 || memcmp(base + i, "070702", 6) == 0) {
            start = i;
            break;
        }
    }
    if (start == (size_t)-1) {
        return -1;
    }
    offset = start;

    while (offset + sizeof(struct cpio_newc_header) <= archive_size) {
        const struct cpio_newc_header *h = (const struct cpio_newc_header*)(base + offset);
        if (!(memcmp(h->c_magic, "070701", 6) == 0 || memcmp(h->c_magic, "070702", 6) == 0)) {
            /* Если встретили мусор вместо магии, аккуратно пытаемся найти
               следующий заголовок вперёд по потоку, чтобы не отрезать архив
               после первого файла. */
            size_t scan = offset + 1;
            size_t found = (size_t)-1;
            while (scan + 6 <= archive_size) {
                if (memcmp(base + scan, "070701", 6) == 0 || memcmp(base + scan, "070702", 6) == 0) {
                    found = scan;
                    break;
                }
                scan++;
            }
            if (found == (size_t)-1) {
                break;
            }
            offset = found;
            continue;
        }
        /* We trust headers once we've locked onto the first magic; the archive
           is expected to be well-formed, and we walk sequentially until
           TRAILER!!!. Previous "plausibility" checks sometimes rejected valid
           large files (like /bin/busybox), so they are intentionally removed. */
        uint32_t namesize = hex_to_uint(h->c_namesize, 8);
        uint32_t filesize = hex_to_uint(h->c_filesize, 8);
        size_t header_size = sizeof(struct cpio_newc_header);
        size_t name_offset = offset + header_size;
        if (name_offset + namesize > archive_size) {
            kprintf("initfs: name extends past archive\n");
            return -1;
        }
        const char *name = (const char*)(base + name_offset);
        /* end of archive marker */
        if (strcmp(name, "TRAILER!!!") == 0) {
            break;
        }
        /* пропускаем пустые имена и голый корень */
        if (name[0] == '\0' || (name[0] == '.' && name[1] == '\0')) {
            size_t after_name = name_offset + namesize;
            size_t file_data_offset = (after_name + 3) & ~3u;
            size_t next = (file_data_offset + filesize + 3) & ~3u;
            offset = next;
            continue;
        }
        /* убираем префикс "./" как в обычном initramfs */
        if (name[0] == '.' && name[1] == '/') {
            name += 2;
        }
        /* compute data offset (header + namesize aligned to 4) */
        size_t after_name = name_offset + namesize;
        size_t file_data_offset = (after_name + 3) & ~3u;
        if (file_data_offset + filesize > archive_size) {
            kprintf("initfs: file data extends past archive for %s\n", name);
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
        /* Always ensure parent directories exist for this path.
           Это гарантирует, что /bin появится хотя бы из записи bin/busybox,
           даже если отдельная запись каталога bin будет пропущена. */
        ensure_parent_dirs(target);

        /* determine mode */
        uint32_t mode = hex_to_uint(h->c_mode, 8);
        uint32_t type = mode & 0170000u;
        if (type == 0040000u || (target[strlen(target)-1] == '/')) {
            /* directory */
            /* strip trailing slash */
            size_t tl = strlen(target);
            if (tl > 1 && target[tl-1] == '/') target[tl-1] = '\0';
            if (ramfs_mkdir(target) < 0) {
                /* ignore existing or other minor errors */
            }
        } else if (type == 0100000u) {
            /* regular file */
            const void *file_data = base + file_data_offset;
            if (create_file_with_data(target, file_data, filesize) != 0) {
                kprintf("initfs: failed to create %s\n", target);
            }
        } else if (type == 0120000u) {
            /* symlink: ensure parent directories and create a small text file
               containing the link target. This is not a real VFS symlink yet,
               but at least /bin and /bin/sh appear in the tree. */
            const char *link_target = (const char*)(base + file_data_offset);
            size_t link_len = filesize;
            if (link_len > 0 && link_target[link_len-1] == '\0') link_len--;
            if (create_file_with_data(target, link_target, link_len) != 0) {
                kprintf("initfs: failed to materialize symlink %s -> %.*s\n",
                        target, (int)link_len, link_target);
            }
        } else {
            /* other types (device nodes, fifos, etc.) - skip for now */
            kprintf("initfs: skipping special file %s (mode %o)\n", target, mode);
        }
        /* advance offset to next header (file data aligned to 4) */
        size_t next = file_data_offset + filesize;
        next = (next + 3) & ~3u;
        offset = next;
    }
    return 0;
}

/* Scan multiboot2 tags for module named `module_name` and unpack it. */
int initfs_process_multiboot_module(uint32_t multiboot_magic, uint32_t multiboot_info, const char *module_name) {
    if (multiboot_magic != 0x36d76289u) return 1; /* not multiboot2 */
    if (multiboot_info == 0) return 1;
    uint8_t *p = (uint8_t*)(uintptr_t)multiboot_info;
    uint32_t total_size = *(uint32_t*)p;
    uint32_t offset = 8; /* tags start after total_size + reserved */
    while (offset + 8 <= total_size) {
        uint32_t tag_type = *(uint32_t*)(p + offset);
        uint32_t tag_size = *(uint32_t*)(p + offset + 4);
        if (tag_type == 0) break; /* end */
        if (tag_type == 3) { /* module */
            uint32_t mod_start = *(uint32_t*)(p + offset + 8);
            uint32_t mod_end = *(uint32_t*)(p + offset + 12);
            const char *name = (const char*)(p + offset + 16);
            if (strcmp(name, module_name) == 0) {
                size_t mod_size = mod_end > mod_start ? (size_t)(mod_end - mod_start) : 0;
                const void *mod_ptr = (const void*)(uintptr_t)mod_start;
                kprintf("initfs: found module '%s' at %p size %u\n", module_name, mod_ptr, (unsigned)mod_size);
                if (mod_size == 0) return -2;
                return unpack_cpio_newc(mod_ptr, mod_size);
            }
        }
        /* align to 8 bytes */
        uint32_t next = (tag_size + 7) & ~7u;
        offset += next;
    }
    return 1; /* module not found */
}


