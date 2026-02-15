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
    if (len > 1 && tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
        len--;
    }
    /* IMPORTANT:
       - do not call strlen() inside the loop (O(n^2) on long paths)
       - creating prefixes "/a", "/a/b", "/a/b/c" is enough; no extra parent mkdir needed */
    for (size_t i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            ramfs_mkdir(tmp);
            tmp[i] = '/';
        }
    }
}

/* Create file at path and write data (size bytes). Returns 0 on success. */
static int create_file_with_data(const char *path, const void *data, size_t size) {
    struct fs_file *f = fs_create_file(path);
    if (!f) {
        /* Common in busybox/initramfs trees: duplicates / overwrites. If the path already
           exists, treat it as success to avoid spam and partial extracts. */
        struct stat st;
        if (vfs_stat(path, &st) == 0) {
            return 0;
        }
        klogprintf("initfs: create_file_with_data: fs_create_file returned NULL for %s (heap_used=%llu heap_total=%llu heap_peak=%llu)\n",
                   path,
                   (unsigned long long)heap_used_bytes(),
                   (unsigned long long)heap_total_bytes(),
                   (unsigned long long)heap_peak_bytes());
        return -12;
    }
    /* Ensure the created handle is recognized as a regular file by VFS/drivers.
       Some drivers may return ambiguous types; force FS_TYPE_REG for initfs-created files. */
    f->type = FS_TYPE_REG;
    ssize_t written = fs_write(f, data, size, 0);
    fs_file_free(f);
    if (written < 0 || (size_t)written != size) {
        klogprintf("initfs: write failed %s (size=%u written=%d heap_used=%llu heap_total=%llu)\n",
                   path, (unsigned)size, (int)written,
                   (unsigned long long)heap_used_bytes(),
                   (unsigned long long)heap_total_bytes());
        return -12;
    }
    return 0;
}

static size_t initfs_strnlen_local(const char *s, size_t maxn) {
    size_t n = 0;
    if (!s) return 0;
    while (n < maxn && s[n] != '\0') n++;
    return n;
}

static const char *initfs_basename(const char *p) {
    if (!p) return p;
    const char *b = p;
    for (const char *c = p; *c; c++) {
        if (*c == '/') b = c + 1;
    }
    return b;
}

/* Robust module-name matcher:
   accepts exact "initfs", "initfs.cpio", "/boot/initfs.cpio", and cmdline with args. */
static int initfs_module_name_matches(const char *cmdline, size_t maxlen, const char *want_name) {
    if (!cmdline || !want_name || !want_name[0]) return 0;
    size_t n = initfs_strnlen_local(cmdline, maxlen);
    if (n == 0) return 0;

    /* Skip leading spaces/tabs. */
    size_t i = 0;
    while (i < n && (cmdline[i] == ' ' || cmdline[i] == '\t')) i++;
    if (i >= n) return 0;

    /* First token only (before whitespace). */
    size_t start = i;
    while (i < n && cmdline[i] != ' ' && cmdline[i] != '\t') i++;
    size_t tok_len = i - start;
    if (tok_len == 0 || tok_len > 255) return 0;

    char tok[256];
    memcpy(tok, cmdline + start, tok_len);
    tok[tok_len] = '\0';

    if (strcmp(tok, want_name) == 0) return 1;

    const char *base = initfs_basename(tok);
    if (strcmp(base, want_name) == 0) return 1;

    /* Allow common archive suffixes for basename token. */
    size_t want_len = strlen(want_name);
    if (strncmp(base, want_name, want_len) == 0) {
        if (base[want_len] == '\0' || base[want_len] == '.' || base[want_len] == '-') return 1;
    }
    return 0;
}

static int initfs_has_boot_init(void) {
    struct stat st;
    if (vfs_stat("/sbin/init", &st) == 0) return 1;
    if (vfs_stat("/bin/init", &st) == 0) return 1;
    return 0;
}

/* Normalize archive path to an absolute canonical-ish form suitable for VFS lookup.
   Handles common cpio prefixes like "./", repeated '/', and trailing '/'. */
static void initfs_normalize_target(char *out, size_t out_sz, const char *name) {
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (!name || !name[0]) {
        if (out_sz >= 2) { out[0] = '/'; out[1] = '\0'; }
        return;
    }

    const char *src = name;
    while (src[0] == '.') {
        if (src[1] == '/') {
            src += 2; /* trim leading "./" */
            continue;
        }
        if (src[1] == '\0') { /* "." entry */
            src += 1;
            break;
        }
        break;
    }

    size_t w = 0;
    out[w++] = '/';
    int last_was_slash = 1;
    while (*src && w + 1 < out_sz) {
        char c = *src++;
        if (c == '/') {
            if (last_was_slash) continue;
            out[w++] = '/';
            last_was_slash = 1;
            continue;
        }
        if (c == '.' && (src[0] == '/' || src[0] == '\0') && last_was_slash) {
            /* skip "/./" and trailing "/." segments */
            continue;
        }
        out[w++] = c;
        last_was_slash = 0;
    }

    if (w > 1 && out[w - 1] == '/') w--;
    out[w] = '\0';
}

/* Unpack cpio newc archive at archive (size bytes) into VFS root. */
static int unpack_cpio_newc(const void *archive, size_t archive_size) {
    const uint8_t *base = (const uint8_t*)archive;
    size_t offset = 0;
    /* Ensure /dev exists before unpacking - kernel may have failed to create it (OOM etc).
       Critical for ls / to show dev and for init's mount -t devtmpfs /dev. */
    (void)ramfs_mkdir("/dev");
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
        initfs_normalize_target(target, sizeof(target), name);
        if (strcmp(target, "/") == 0) {
            /* Ignore root pseudo-entry like "." */
            size_t next_root = file_data_offset + filesize;
            if (next_root <= offset || next_root > archive_size) return -1;
            next_root = (next_root + 3) & ~3u;
            if (next_root <= offset) return -1;
            offset = next_root;
            continue;
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
            /* Apply exact mode bits from archive (includes S_IFDIR + perms). */
            (void)fs_chmod(target, (mode_t)mode);
        } else if ((mode & 0170000u) == 0100000u) {
            /* regular file */
            ensure_parent_dirs(target);
            const void *file_data = base + file_data_offset;
            int cr = create_file_with_data(target, file_data, filesize);
            if (cr != 0) {
                if (cr == -12) {
                    klogprintf("initfs: fatal: OOM while extracting %s\n", target);
                    return -12;
                }
                klogprintf("initfs: warning: failed to create %s (ignore)\n", target);
            } else {
                /* Apply exact mode bits from archive (includes S_IFREG + perms, esp. +x). */
                (void)fs_chmod(target, (mode_t)mode);
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
                int sr = ramfs_symlink(target, linkt);
                if (sr < 0) {
                    /* ramfs_symlink() return codes:
                       -4: already exists (EEXIST) -> ignore quietly (busybox trees often include duplicates)
                       -5/-6: OOM -> fatal
                       others: warn, but rate-limit to avoid spamming console */
                    if (sr == -4) {
                        /* ignore */
                    } else if (sr == -5 || sr == -6) {
                        klogprintf("initfs: fatal: OOM while creating symlink %s\n", target);
                        kfree(linkt);
                        return -12;
                    } else {
                        static int symlink_warn_count = 0;
                        if (symlink_warn_count < 8) {
                            klogprintf("initfs: warning: failed to create symlink %s -> %s (rc=%d)\n",
                                       target, linkt, sr);
                            symlink_warn_count++;
                            if (symlink_warn_count == 8) {
                                klogprintf("initfs: warning: more symlink errors suppressed\n");
                            }
                        }
                    }
                }
                kfree(linkt);
            } else {
                klogprintf("initfs: fatal: OOM alloc for symlink %s (heap_used=%llu heap_total=%llu)\n",
                           target,
                           (unsigned long long)heap_used_bytes(),
                           (unsigned long long)heap_total_bytes());
                return -12;
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
    /* total_size 0 или слишком большой — отказ. 1..15: возможно загрузчик передал указатель
       на первый тег (в p+0 тип тега), тогда стандартный цикл не войдёт — ниже пробуем alt layout. */
    if (total_size == 0 || total_size > (256u * 1024u * 1024u)) {
        klogprintf("initfs: suspicious total_size=%u, aborting mb2 scan\n", (unsigned)total_size);
        return 4;
    }
    uint32_t offset = 8; /* tags start after total_size + reserved */
    uint32_t tag_count = 0;
    int module_tags_seen = 0;
    while (offset + 8 <= total_size) {
        if (++tag_count > 1024) break;
        uint32_t tag_type = *(uint32_t*)(p + offset);
        uint32_t tag_size = *(uint32_t*)(p + offset + 4);
        /* Basic sanity checks to avoid infinite loops on malformed multiboot data */
        if (tag_size < 8) break;
        if ((uint64_t)offset + (uint64_t)tag_size > (uint64_t)total_size) break;
        if (tag_type == 0) break; /* end */
        if (tag_type == 3) { /* module */
            module_tags_seen++;
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
                size_t name_max = (size_t)tag_size - 16u;
                size_t name_len = initfs_strnlen_local(name, name_max);
                char shown[128];
                size_t sn = name_len;
                if (sn >= sizeof(shown)) sn = sizeof(shown) - 1;
                memcpy(shown, name, sn);
                shown[sn] = '\0';
                klogprintf("initfs: mb2 module cmdline=\"%s\" start=0x%llx end=0x%llx size=%u\n",
                           shown, (unsigned long long)mod_start, (unsigned long long)mod_end,
                           (unsigned)(mod_end > mod_start ? (mod_end - mod_start) : 0));

            if (initfs_module_name_matches(name, name_max, module_name)) {
                size_t mod_size = mod_end > mod_start ? (size_t)(mod_end - mod_start) : 0;
                const void *mod_ptr = (const void*)(uintptr_t)mod_start;
                klogprintf("initfs: found module '%s' at %p size %u\n", module_name, mod_ptr, (unsigned)mod_size);
                if (mod_size == 0) return -2;
                /* Prefer unpacking directly from the module pointer.
                   Copying the whole module into heap can easily OOM while we are also
                   allocating extracted files into ramfs. */
                int r_direct = unpack_cpio_newc(mod_ptr, mod_size);
                if (r_direct == 0) return 0;

                /* Fallback: copy module into heap and unpack from there for environments
                   where direct reads from the module region are unreliable. */
                klogprintf("initfs: direct unpack failed (%d), trying heap copy fallback\n", r_direct);
                void *buf = kmalloc(mod_size);
                if (!buf) {
                    klogprintf("initfs: heap copy fallback failed (kmalloc %u)\n", (unsigned)mod_size);
                    return r_direct;
                }
                memcpy(buf, mod_ptr, mod_size);
                int r_copy = unpack_cpio_newc(buf, mod_size);
                kfree(buf);
                return r_copy;
            }
            }
        }
        /* align to 8 bytes */
        uint32_t next = (tag_size + 7) & ~7u;
        offset += next;
    }
    /* В VMware загрузчик может передать указатель на первый тег (в p+0 тип 3), а не на заголовок.
       Пробуем разбор с offset=0 при любой неудаче — при стандартном layout (p+0=total_size) сразу выйдем. */
    {
        const uint32_t alt_max = 65536u;
        uint32_t alt_off = 0;
        while (alt_off + 8 <= alt_max) {
            uint32_t tag_type = *(uint32_t*)(p + alt_off);
            uint32_t tag_size = *(uint32_t*)(p + alt_off + 4);
            if (tag_size < 8 || tag_size > alt_max) break;
            if (tag_type == 0) break;
            if (tag_type == 3 && tag_size >= 16) {
                const uint8_t *field_ptr = p + alt_off + 8;
                uint32_t ms32 = *(uint32_t*)(field_ptr);
                uint32_t me32 = *(uint32_t*)(field_ptr + 4);
                uint64_t mod_start = (uint64_t)ms32;
                uint64_t mod_end = (uint64_t)me32;
                size_t name_max = (size_t)tag_size - 16u;
                const char *name = (const char*)(p + alt_off + 16);
                if (initfs_module_name_matches(name, name_max, module_name)) {
                    size_t mod_size = mod_end > mod_start ? (size_t)(mod_end - mod_start) : 0;
                    const void *mod_ptr = (const void*)(uintptr_t)mod_start;
                    klogprintf("initfs: found module '%s' at %p size %u (alt mb2 layout)\n",
                               module_name, mod_ptr, (unsigned)mod_size);
                    if (mod_size == 0) return -2;
                    int r = unpack_cpio_newc(mod_ptr, mod_size);
                    if (r == 0) return 0;
                    void *buf = kmalloc(mod_size);
                    if (buf) {
                        memcpy(buf, mod_ptr, mod_size);
                        int r2 = unpack_cpio_newc(buf, mod_size);
                        kfree(buf);
                        if (r2 == 0) return 0;
                    }
                }
            }
            alt_off += (tag_size + 7) & ~7u;
        }
    }

    /* Fallback: некоторые загрузчики дают битую/обрезанную цепочку тегов (например, end-tag
       раньше module). В таком случае пробуем "рыхлый" поиск module-tag (type=3) только
       в небольшом окне около multiboot_info, без глобального сканирования памяти. */
    {
        const uint32_t meta_scan = 65536u; /* 64 KiB */
        for (uint32_t off = 0; off + 16u <= meta_scan; off += 4u) {
            uint32_t tag_type = *(uint32_t *)(p + off);
            if (tag_type != 3u) continue;
            uint32_t tag_size = *(uint32_t *)(p + off + 4u);
            if (tag_size < 16u || tag_size > 4096u) continue;
            if (off + tag_size > meta_scan) continue;

            const uint8_t *field_ptr = p + off + 8u;
            uint32_t ms32 = *(uint32_t *)(field_ptr);
            uint32_t me32 = *(uint32_t *)(field_ptr + 4u);
            if (me32 <= ms32) continue;

            uint64_t mod_start = (uint64_t)ms32;
            uint64_t mod_end = (uint64_t)me32;
            size_t mod_size = (size_t)(mod_end - mod_start);
            if (mod_size == 0 || mod_size > (512u * 1024u * 1024u)) continue;

            const char *name = (const char *)(p + off + 16u);
            size_t name_max = (size_t)tag_size - 16u;
            if (!initfs_module_name_matches(name, name_max, module_name)) continue;

            const void *mod_ptr = (const void *)(uintptr_t)mod_start;
            klogprintf("initfs: found module '%s' at %p size %u (loose mb2 tag scan)\n",
                       module_name ? module_name : "(null)",
                       mod_ptr, (unsigned)mod_size);
            int r = unpack_cpio_newc(mod_ptr, mod_size);
            if (r == 0) return 0;
            void *buf = kmalloc(mod_size);
            if (!buf) return r;
            memcpy(buf, mod_ptr, mod_size);
            int r2 = unpack_cpio_newc(buf, mod_size);
            kfree(buf);
            return r2;
        }
    }

    /* Последняя попытка: часть загрузчиков передаёт в multiboot_info адрес initrd напрямую
       (по указателю сразу cpio magic). Не сканируем память — только один адрес. */
    if ((memcmp(p, "070701", 6) == 0 || memcmp(p, "070702", 6) == 0)) {
        const size_t direct_max = 64u * 1024u * 1024u; /* не читать дальше 64 MiB */
        if (plausible_cpio_header((const struct cpio_newc_header *)p, direct_max)) {
            int r = unpack_cpio_newc(p, direct_max);
            if (r == 0 && initfs_has_boot_init()) {
                klogprintf("initfs: found cpio at multiboot_info (direct initrd)\n");
                return 0;
            }
        }
    }

    klogprintf("initfs: module '%s' not found in mb2 tags (tags=%u modules=%d)\n",
               module_name ? module_name : "(null)", (unsigned)tag_count, module_tags_seen);
    return 1; /* module not found */
}
