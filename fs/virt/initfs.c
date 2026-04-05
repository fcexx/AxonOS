/*
 * fs/virt/initfs.c
 * Initfs: initrd region from Linux boot_params (ramdisk_image/size + ext_*), cpio newc → VFS
 * Author: fcexx
*/

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <axonos.h>
#include <fs.h>
#include <ramfs.h>
#include <heap.h>
#include <string.h>
#include <vga.h>
#include <initfs.h>
#include <bootparam.h>
#include <klog.h>
#include <debug.h>
#include <sysinfo.h>
#include <ext2.h>

void initfs_normalize_target(char *out, size_t out_sz, const char *name);

/* Kernel link end (see linker.ld); identity-mapped, same numeric value as physical. */
extern char _end[];

/* cpio newc hard links: same c_ino as first file; body only on first entry, later filesize==0.
 * BusyBox initramfs uses this for /bin/mount, /sbin/getty, etc. -> busybox. */
struct initfs_ino_ent {
    uint32_t ino;
    char *path;
};
static struct initfs_ino_ent *s_ino_map;
static size_t s_ino_n;
static size_t s_ino_cap;

struct initfs_pending_hlink {
    char path[512];
    uint32_t ino;
    struct initfs_pending_hlink *next;
};
static struct initfs_pending_hlink *s_pending_hl;

static void initfs_ino_map_clear(void) {
    if (s_ino_map) {
        for (size_t i = 0; i < s_ino_n; i++) {
            if (s_ino_map[i].path)
                kfree(s_ino_map[i].path);
        }
        kfree(s_ino_map);
    }
    s_ino_map = NULL;
    s_ino_n = 0;
    s_ino_cap = 0;
    while (s_pending_hl) {
        struct initfs_pending_hlink *d = s_pending_hl;
        s_pending_hl = d->next;
        kfree(d);
    }
}

static const char *initfs_ino_lookup(uint32_t ino) {
    if (ino == 0)
        return NULL;
    for (size_t i = 0; i < s_ino_n; i++) {
        if (s_ino_map[i].ino == ino)
            return s_ino_map[i].path;
    }
    return NULL;
}

static int initfs_ino_remember(uint32_t ino, const char *path) {
    if (ino == 0 || !path)
        return 0;
    for (size_t i = 0; i < s_ino_n; i++) {
        if (s_ino_map[i].ino == ino)
            return 0;
    }
    if (s_ino_n >= s_ino_cap) {
        size_t ncap = s_ino_cap ? s_ino_cap * 2 : 256u;
        struct initfs_ino_ent *n = (struct initfs_ino_ent *)kmalloc(ncap * sizeof(*n));
        if (!n)
            return -1;
        if (s_ino_map)
            memcpy(n, s_ino_map, s_ino_n * sizeof(*n));
        kfree(s_ino_map);
        s_ino_map = n;
        s_ino_cap = ncap;
    }
    size_t pl = strlen(path) + 1;
    char *copy = (char *)kmalloc(pl);
    if (!copy)
        return -1;
    memcpy(copy, path, pl);
    s_ino_map[s_ino_n].ino = ino;
    s_ino_map[s_ino_n].path = copy;
    s_ino_n++;
    return 0;
}

static void initfs_pending_hl_drain(void) {
    for (int round = 0; round < 4096 && s_pending_hl; round++) {
        struct initfs_pending_hlink **pp = &s_pending_hl;
        int progress = 0;
        while (*pp) {
            const char *src = initfs_ino_lookup((*pp)->ino);
            if (!src) {
                pp = &(*pp)->next;
                continue;
            }
            int lr = ramfs_link(src, (*pp)->path);
            if (lr != 0)
                klogprintf("initfs: hardlink %s -> %s rc=%d\n", (*pp)->path, src, lr);
            struct initfs_pending_hlink *d = *pp;
            *pp = d->next;
            kfree(d);
            progress = 1;
        }
        if (!progress)
            break;
    }
}

/* cpio newc header: exactly 110 bytes on the wire; must be packed — if the compiler
 * inserts padding after c_magic[6], plausible_cpio_header(0) fails while memcmp still
 * sees 070701, and find_cpio_start scans into file data (~MiB false offset). */
struct __attribute__((packed)) cpio_newc_header {
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
typedef char initfs_cpio_hdr_sz_chk[sizeof(struct cpio_newc_header) == 110u ? 1 : -1];

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

/* Walk newc stream from `start` (must point at a header) until TRAILER!!! or error.
 * Mirrors unpack_cpio_newc stepping rules so a match here means unpack can complete. */
static int cpio_newc_walk_reaches_trailer_from(const uint8_t *base, size_t lim, size_t start) {
    if (!base || lim < sizeof(struct cpio_newc_header) || start > lim) return 0;
    if (start + sizeof(struct cpio_newc_header) > lim) return 0;
    size_t offset = start;
    while (offset + sizeof(struct cpio_newc_header) <= lim) {
        const struct cpio_newc_header *h = (const struct cpio_newc_header *)(base + offset);
        const uint8_t *magic = base + offset;
        if (!((memcmp(magic, "070701", 6) == 0) || (memcmp(magic, "070702", 6) == 0))) return 0;
        if (!plausible_cpio_header(h, lim - offset)) return 0;
        uint32_t namesize = hex_to_uint(h->c_namesize, 8);
        uint32_t filesize = hex_to_uint(h->c_filesize, 8);
        size_t header_size = sizeof(struct cpio_newc_header);
        size_t name_offset = offset + header_size;
        if (name_offset + namesize > lim) return 0;
        const char *name = (const char *)(base + name_offset);
        if (strcmp(name, "TRAILER!!!") == 0) return 1;
        char target[512];
        initfs_normalize_target(target, sizeof(target), name);
        size_t after_name = name_offset + namesize;
        size_t file_data_offset = (after_name + 3) & ~3u;
        if (file_data_offset + filesize > lim) return 0;
        if (strcmp(target, "/") == 0) {
            size_t next_root = file_data_offset + filesize;
            if (next_root <= offset || next_root > lim) return 0;
            next_root = (next_root + 3) & ~3u;
            if (next_root <= offset) return 0;
            offset = next_root;
            continue;
        }
        size_t next = file_data_offset + filesize;
        if (next <= offset || next > lim) return 0;
        next = (next + 3) & ~3u;
        if (next <= offset) return 0;
        offset = next;
    }
    return 0;
}

/* Find a reliable starting offset of a cpio newc stream within a buffer.
   Prefer offset 0 if magic + plausible header (do not require plausible_cpio_name on
   entry 0 — rejecting it pushed find_cpio_start to a false "070701" inside file data).
   For i>0: cheap next-header heuristic, then full walk to TRAILER!!! (walk is authoritative).
   Do not require plausible_cpio_name here — it could skip the real stream and match a later
   accidental 070701 inside the same prefix. */
static size_t find_cpio_start(const uint8_t *base, size_t archive_size) {
    if (!base || archive_size < sizeof(struct cpio_newc_header)) return (size_t)-1;

    /* fast path: archive begins with magic + plausible header (packed struct required). */
    if ((memcmp(base, "070701", 6) == 0 || memcmp(base, "070702", 6) == 0) &&
        plausible_cpio_header((const struct cpio_newc_header *)base, archive_size)) {
        return 0;
    }

    /* Slow scan: bounded prefix only (aligned steps). Allow large prepended blobs
       (e.g. microcode, vendor headers) before the main newc ramdisk. */
    size_t scan_limit = archive_size;
    if (scan_limit > (16u * 1024u * 1024u)) scan_limit = (16u * 1024u * 1024u);
    for (size_t i = 0; i + sizeof(struct cpio_newc_header) <= scan_limit; i += 4) {
        if (!(memcmp(base + i, "070701", 6) == 0 || memcmp(base + i, "070702", 6) == 0)) continue;
        const struct cpio_newc_header *h = (const struct cpio_newc_header *)(base + i);
        if (!plausible_cpio_header(h, archive_size - i)) continue;
        uint32_t namesize = hex_to_uint(h->c_namesize, 8);
        uint32_t filesize = hex_to_uint(h->c_filesize, 8);
        if (sizeof(*h) + (size_t)namesize > archive_size - i) continue;
        const char *name = (const char *)(base + i + sizeof(*h));
        if (namesize == 0 || name[namesize - 1] != '\0') continue;

        /* Empty cpio: single TRAILER record (no following header). */
        if (strcmp(name, "TRAILER!!!") == 0) {
            if (cpio_newc_walk_reaches_trailer_from(base, archive_size, i)) return i;
            continue;
        }

        /* Otherwise require a plausible next newc header (file or TRAILER). */
        size_t after_name = sizeof(*h) + (size_t)namesize;
        size_t file_data_offset = (after_name + 3) & ~3u;
        size_t next = file_data_offset + (size_t)filesize;
        next = (next + 3) & ~3u;
        if (next <= file_data_offset) continue;
        if (i + next + 6 <= archive_size) {
            const uint8_t *nm = base + i + next;
            if (memcmp(nm, "070701", 6) == 0 || memcmp(nm, "070702", 6) == 0) {
                if (cpio_newc_walk_reaches_trailer_from(base, archive_size, i)) return i;
            }
        }
    }

    return (size_t)-1;
}

/* Ensure all parent directories for `path` exist. Path must be absolute. */
static void ensure_parent_dirs(const char *path) {
    if (!path || path[0] != '/') return;
    size_t len = strlen(path);
    char tmp[512];
    if (len >= sizeof(tmp)) return;
    strcpy(tmp, path);
    if (len > 1 && tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
        len--;
    }
    for (size_t i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            (void)ramfs_mkdir(tmp);
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
void initfs_normalize_target(char *out, size_t out_sz, const char *name) {
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

/* Collapse /./, /../, duplicate slashes for an absolute path (segments point into `work`). */
static int initfs_normalize_abs_into_buf(const char *work, char *out, size_t outsz) {
    if (!work || work[0] != '/' || !out || outsz < 2)
        return -1;
    const char *parts[96];
    size_t plen[96];
    int pc = 0;
    const char *p = work;
    while (*p) {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        const char *seg = p;
        while (*p && *p != '/')
            p++;
        size_t len = (size_t)(p - seg);
        if (len == 1 && seg[0] == '.')
            continue;
        if (len == 2 && seg[0] == '.' && seg[1] == '.') {
            if (pc > 0)
                pc--;
            continue;
        }
        if (pc < 96) {
            parts[pc] = seg;
            plen[pc] = len;
            pc++;
        }
    }
    if (pc == 0) {
        out[0] = '/';
        out[1] = '\0';
        return 0;
    }
    size_t w = 0;
    out[w++] = '/';
    for (int i = 0; i < pc; i++) {
        if (w > 1u && out[w - 1u] != '/')
            out[w++] = '/';
        if (w + plen[i] >= outsz)
            return -1;
        memcpy(out + w, parts[i], plen[i]);
        w += plen[i];
    }
    if (w >= outsz)
        return -1;
    out[w] = '\0';
    return 0;
}

/* BusyBox cpio often stores applet symlinks as relative targets ("busybox", "../../bin/busybox").
 * ramfs_lookup() resolves those using ramfs_build_path(parent); if that fails (512-byte cap or
 * deep trees), it wrongly assumes parent "/" and breaks exec. Store absolute normalized targets. */
static int initfs_symlink_make_absolute(const char *symlink_path, const char *raw, char *out,
                                        size_t outsz) {
    if (!symlink_path || !raw || !out || outsz < 4)
        return -1;
    char work[768];
    if (raw[0] == '/') {
        size_t rl = strlen(raw);
        if (rl >= sizeof(work))
            return -1;
        memcpy(work, raw, rl + 1);
    } else {
        char parent[512];
        size_t sl = strlen(symlink_path);
        if (sl == 0 || sl >= sizeof(parent))
            return -1;
        memcpy(parent, symlink_path, sl + 1);
        char *slash = strrchr(parent, '/');
        if (!slash)
            return -1;
        if (slash == parent) {
            if ((size_t)snprintf(work, sizeof(work), "/%s", raw) >= sizeof(work))
                return -1;
        } else {
            *slash = '\0';
            if ((size_t)snprintf(work, sizeof(work), "%s/%s", parent, raw) >= sizeof(work))
                return -1;
        }
    }
    return initfs_normalize_abs_into_buf(work, out, outsz);
}

/* Unpack cpio newc archive at archive (size bytes) into VFS root. */
static int unpack_cpio_newc(const void *archive, size_t archive_size) {
    const uint8_t *base = (const uint8_t*)archive;
    size_t offset = 0;
    int files_created = 0, dirs_created = 0, symlinks_created = 0;
    int cpio_entry_num = 0;
    /* Some symlinks depend on other symlinks in parent path. If processed too
       early, ramfs_symlink() fails with -2. Keep them pending and retry after
       the first scan. */
    struct pending_symlink {
        char target[512];
        char *linkt;
        struct pending_symlink *next;
    };
    struct pending_symlink *pending = NULL;
    /* Ensure /dev exists before unpacking - kernel may have failed to create it (OOM etc).
       Critical for ls / to show dev and for init's mount -t devtmpfs /dev. */
    (void)ramfs_mkdir("/dev");
    initfs_ino_map_clear();
    /* Find reliable start of a CPIO stream. */
    size_t found = find_cpio_start(base, archive_size);
    if (found == (size_t)-1) {
        klogprintf("initfs: cpio magic not found in module (size %u)\n", (unsigned)archive_size);
        return -1;
    }
    if (found != 0)
        klogprintf("initfs: cpio stream offset %zu (embedded / prefixed)\n", found);
    offset = found;
    qemu_debug_printf("initfs: --- cpio entries (before unpack) ---\n");

    int saw_trailer = 0;
    while (offset + sizeof(struct cpio_newc_header) <= archive_size) {
        const struct cpio_newc_header *h = (const struct cpio_newc_header*)(base + offset);
        /* header.magic is 6 bytes ASCII "070701" (newc) or "070702" (newc with CRC).
           Compare raw bytes from the module to avoid any struct/padding surprises. */
        const uint8_t *magic = base + offset;
        if (!((memcmp(magic, "070701", 6) == 0) || (memcmp(magic, "070702", 6) == 0))) {
            klogprintf("initfs: cpio bad magic at offset %u entry #%d\n",
                       (unsigned)offset, cpio_entry_num);
            return -1;
        }
        /* additional plausibility check to avoid false positives where "070701"
           appears inside file data */
        if (!plausible_cpio_header(h, archive_size - offset)) {
            klogprintf("initfs: cpio implausible header at offset %u entry #%d\n",
                       (unsigned)offset, cpio_entry_num);
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
        if (strcmp(name, "TRAILER!!!") == 0) {
            saw_trailer = 1;
            break;
        }
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
        cpio_entry_num++;
        uint32_t mode = hex_to_uint(h->c_mode, 8);
        const char *etype = "?";
        if ((mode & 0170000u) == 0040000u || (strlen(target) > 1 && target[strlen(target)-1] == '/')) etype = "dir";
        else if ((mode & 0170000u) == 0100000u) etype = "file";
        else if ((mode & 0170000u) == 0120000u) etype = "symlink";
        qemu_debug_printf("initfs: cpio #%d: %s [%s] mode=%o size=%u\n",
                          cpio_entry_num, target, etype,
                          (unsigned)mode, (unsigned)filesize);

        if (strcmp(target, "/") == 0) {
            /* Ignore root pseudo-entry like "." */
            size_t next_root = file_data_offset + filesize;
            if (next_root <= offset || next_root > archive_size) {
                klogprintf("initfs: cpio bad root skip at offset %u\n", (unsigned)offset);
                return -1;
            }
            next_root = (next_root + 3) & ~3u;
            if (next_root <= offset) {
                klogprintf("initfs: cpio root align wrap at offset %u\n", (unsigned)offset);
                return -1;
            }
            offset = next_root;
            continue;
        }
        /* mode already parsed above for debug */
        if ((mode & 0170000u) == 0040000u ||
            (strlen(target) > 1u && target[strlen(target) - 1u] == '/')) {
            /* directory */
            /* strip trailing slash */
            size_t tl = strlen(target);
            if (tl > 1 && target[tl-1] == '/') target[tl-1] = '\0';
            if (ramfs_mkdir(target) >= 0) {
                dirs_created++;
            }
            /* Apply exact mode bits from archive (includes S_IFDIR + perms). */
            (void)fs_chmod(target, (mode_t)mode);
        } else if ((mode & 0170000u) == 0100000u) {
            /* regular file (or cpio hard link: same inode, filesize 0, body on first entry) */
            ensure_parent_dirs(target);
            const void *file_data = base + file_data_offset;
            uint32_t ino = hex_to_uint(h->c_ino, 8);

            if (filesize == 0) {
                const char *src = initfs_ino_lookup(ino);
                if (src) {
                    int lr = ramfs_link(src, target);
                    if (lr != 0)
                        klogprintf("initfs: hardlink %s -> %s rc=%d\n", target, src, lr);
                    else {
                        files_created++;
                        (void)fs_chmod(target, (mode_t)mode);
                    }
                } else {
                    uint32_t nlink = hex_to_uint(h->c_nlink, 8);
                    /* nlink>1 with no body yet: hard link before canonical file in archive order */
                    if (nlink <= 1u) {
                        int cr = create_file_with_data(target, file_data, 0);
                        if (cr != 0) {
                            if (cr == -12) {
                                klogprintf("initfs: fatal: OOM while extracting %s\n", target);
                                return -12;
                            }
                            klogprintf("initfs: warning: failed to create %s (rc=%d)\n", target, cr);
                        } else {
                            files_created++;
                            (void)fs_chmod(target, (mode_t)mode);
                            if (ino != 0)
                                (void)initfs_ino_remember(ino, target);
                            initfs_pending_hl_drain();
                        }
                    } else {
                        struct initfs_pending_hlink *ph =
                            (struct initfs_pending_hlink *)kmalloc(sizeof(*ph));
                        if (!ph) {
                            klogprintf("initfs: OOM pending hardlink %s\n", target);
                        } else {
                            memset(ph, 0, sizeof(*ph));
                            strncpy(ph->path, target, sizeof(ph->path) - 1);
                            ph->path[sizeof(ph->path) - 1] = '\0';
                            ph->ino = ino;
                            ph->next = s_pending_hl;
                            s_pending_hl = ph;
                        }
                    }
                }
            } else {
                int cr = create_file_with_data(target, file_data, filesize);
                if (cr != 0) {
                    if (cr == -12) {
                        klogprintf("initfs: fatal: OOM while extracting %s\n", target);
                        return -12;
                    }
                    klogprintf("initfs: warning: failed to create %s (rc=%d)\n", target, cr);
                } else {
                    files_created++;
                    (void)fs_chmod(target, (mode_t)mode);
                    if (ino != 0 && initfs_ino_remember(ino, target) != 0)
                        klogprintf("initfs: warning: ino map OOM for %s\n", target);
                    initfs_pending_hl_drain();
                }
            }
        } else if ((mode & 0170000u) == 0120000u) {
            /* symbolic link: file data contains link target */
            ensure_parent_dirs(target);
            const void *file_data = base + file_data_offset;
            size_t tlen = filesize;
            char *linkt = (char*)kmalloc(tlen + 1);
            if (linkt) {
                memcpy(linkt, file_data, tlen);
                linkt[tlen] = '\0';
                char abs_buf[768];
                const char *store_tgt = linkt;
                if (initfs_symlink_make_absolute(target, linkt, abs_buf, sizeof(abs_buf)) == 0)
                    store_tgt = abs_buf;
                /* Ensure parents exist for absolute targets (e.g. /bin/busybox). */
                if (store_tgt[0] == '/' && store_tgt[1] != '\0')
                    ensure_parent_dirs(store_tgt);
                int sr = ramfs_symlink(target, store_tgt);
                if (sr < 0) {
                    /* -4: already exists, count as success. -5/-6: OOM, fatal. */
                    if (sr == -4) {
                        symlinks_created++;
                    } else if (sr == -5 || sr == -6) {
                        klogprintf("initfs: fatal: OOM while creating symlink %s\n", target);
                        kfree(linkt);
                        return -12;
                    } else {
                        /* -2 parent not found, -3 parent not dir, -1 invalid: retry later
                           after more dirs/symlinks are created (e.g. /bin comes after bin/mount in cpio). */
                        struct pending_symlink *ps = (struct pending_symlink*)kmalloc(sizeof(*ps));
                        if (!ps) {
                            klogprintf("initfs: fatal: OOM pending symlink %s\n", target);
                            kfree(linkt);
                            return -12;
                        }
                        memset(ps, 0, sizeof(*ps));
                        strncpy(ps->target, target, sizeof(ps->target) - 1);
                        ps->target[sizeof(ps->target) - 1] = '\0';
                        ps->linkt = linkt; /* keep ownership */
                        ps->next = pending;
                        pending = ps;
                        linkt = NULL;
                    }
                } else {
                    symlinks_created++;
                }
                if (linkt) kfree(linkt);
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
            klogprintf("initfs: cpio bad next offset=%u next=%zu fsz=%u path tail (see debug)\n",
                       (unsigned)offset, (size_t)next, (unsigned)filesize);
            return -1;
        }
        next = (next + 3) & ~3u;
        if (next <= offset) {
            klogprintf("initfs: cpio next align wrap at offset %u\n", (unsigned)offset);
            return -1;
        }
        offset = next;
    }
    if (!saw_trailer) {
        klogprintf("initfs: error: cpio has no TRAILER!!! (initrd truncated or wrong size? archive_size=%u offset=%u)\n",
                   (unsigned)archive_size, (unsigned)offset);
        return -1;
    }
    initfs_pending_hl_drain();
    if (s_pending_hl) {
        int left = 0;
        for (struct initfs_pending_hlink *q = s_pending_hl; q; q = q->next) left++;
        klogprintf("initfs: warning: %d hard links unresolved (missing inode body earlier in archive?)\n", left);
        while (s_pending_hl) {
            struct initfs_pending_hlink *d = s_pending_hl;
            s_pending_hl = d->next;
            kfree(d);
        }
    }
    /* Retry pending symlinks now that parents should exist. */
    if (pending) {
        int round = 0;
        while (pending && round < 128) {
            int progress = 0;
            struct pending_symlink **pp = &pending;
            while (*pp) {
                struct pending_symlink *ps = *pp;
                ensure_parent_dirs(ps->target);
                char abs_buf[768];
                const char *store_tgt = ps->linkt;
                if (initfs_symlink_make_absolute(ps->target, ps->linkt, abs_buf, sizeof(abs_buf)) == 0)
                    store_tgt = abs_buf;
                if (store_tgt[0] == '/' && store_tgt[1] != '\0')
                    ensure_parent_dirs(store_tgt);
                int sr = ramfs_symlink(ps->target, store_tgt);
                if (sr == 0 || sr == -4) {
                    *pp = ps->next;
                    if (ps->linkt) kfree(ps->linkt);
                    kfree(ps);
                    symlinks_created++;
                    progress++;
                    continue;
                }
                pp = &(*pp)->next;
            }
            if (!progress) break;
            round++;
        }
        if (pending) {
            int left = 0;
            for (struct pending_symlink *ps = pending; ps; ps = ps->next) left++;
            klogprintf("initfs: warning: %d symlinks still pending after retries (dropping)\n", left);
            while (pending) {
                struct pending_symlink *ps = pending;
                pending = ps->next;
                if (ps->linkt) kfree(ps->linkt);
                kfree(ps);
            }
        }
    }
    qemu_debug_printf("initfs: --- end cpio (%d entries) ---\n", cpio_entry_num);
    qemu_debug_printf("initfs: extracted %d files, %d dirs, %d symlinks\n", files_created, dirs_created, symlinks_created);
    initfs_ino_map_clear();
    return 0;
}

/* Initrd image and kernel heap are identity-mapped; if ranges are disjoint, unpack
 * from loader memory like Linux (no memcpy, no extra 100+ MiB allocation). */
static inline uintptr_t initfs_align_up(uintptr_t v, uintptr_t a) {
    return (v + (a - 1)) & ~(a - 1);
}

static int initfs_module_overlaps_heap(uintptr_t mod_start, size_t mod_size) {
    uintptr_t mod_end;
    if (mod_size == 0)
        return 0;
    if (__builtin_add_overflow(mod_start, mod_size, &mod_end))
        return 1;
    uintptr_t h0 = heap_base_addr();
    size_t ht = heap_total_bytes();
    if (h0 == 0 || ht == 0)
        return 1;
    uintptr_t h1 = h0 + ht;
    if (mod_end <= mod_start)
        return 1;
    return mod_start < h1 && mod_end > h0;
}

static int initfs_unpack_ramdisk_region(const void *mod_ptr, size_t mod_size) {
    uintptr_t a = (uintptr_t)mod_ptr;
    /* Do not kmalloc+memcpy whole initrd (~35+ MiB): risks OOM, corrupts canaries on huge
     * single blocks, and has caused triple-faults here. Reloc arena (kzip) is disjoint from
     * heap if mods_end was applied; unpack in place is safe. */
    if (!initfs_module_overlaps_heap(a, mod_size)) {
        klogprintf("initfs: unpack in place (%u bytes, no heap copy)\n", (unsigned)mod_size);
        return unpack_cpio_newc(mod_ptr, mod_size);
    }
    void *buf = kmalloc(mod_size);
    if (!buf) {
        uint64_t end64;
        if (__builtin_add_overflow((uint64_t)a, (uint64_t)mod_size, &end64))
            end64 = (uint64_t)-1;
        klogprintf(
            "initfs: OOM for module buffer (%u bytes); heap overlaps initrd [0x%llx..0x%llx) — "
            "unpack in place would corrupt the archive\n",
            (unsigned)mod_size, (unsigned long long)a, (unsigned long long)end64);
        return -12;
    }
    memcpy(buf, mod_ptr, mod_size);
    int r = unpack_cpio_newc(buf, mod_size);
    kfree(buf);
    return r;
}

/* Recursively list VFS entries via qemu_debug_printf for debugging. */
static void initfs_debug_list_vfs_dir(const char *dirpath, int depth, int *count, int max_entries) {
    if (depth > 4 || *count >= max_entries) return;
    struct fs_file *d = fs_open(dirpath);
    if (!d) return;
    uint8_t buf[512];
    size_t file_off = 0;
    for (;;) {
        ssize_t nr = fs_read(d, buf, sizeof(buf), file_off);
        if (nr <= 0) break;
        size_t rr = (size_t)nr;
        size_t off = 0;
        while (off + 8 <= rr && *count < max_entries) {
            struct ext2_dir_entry *de = (struct ext2_dir_entry*)(buf + off);
            if (de->rec_len < 8) break;
            size_t reclen = (size_t)de->rec_len;
            if (off + reclen > rr) break;
            if (de->name_len > 0 && de->name_len < 256) {
                char name[260];
                size_t nlen = de->name_len < sizeof(name) - 1 ? de->name_len : sizeof(name) - 1;
                memcpy(name, (char*)(de + 1), nlen);
                name[nlen] = '\0';
                if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                    char full[512];
                    if (strcmp(dirpath, "/") == 0)
                        snprintf(full, sizeof(full), "/%s", name);
                    else
                        snprintf(full, sizeof(full), "%s/%s", dirpath, name);
                    const char *t = (de->file_type == EXT2_FT_DIR) ? "dir" :
                                   (de->file_type == EXT2_FT_SYMLINK) ? "lnk" : "reg";
                    qemu_debug_printf("initfs: vfs  %s [%s]\n", full, t);
                    (*count)++;
                    if (de->file_type == EXT2_FT_DIR && *count < max_entries)
                        initfs_debug_list_vfs_dir(full, depth + 1, count, max_entries);
                }
            }
            off += reclen;
        }
        file_off += off;
        if (off == 0 || (size_t)nr < sizeof(buf)) break;
    }
    fs_file_free(d);
}

void initfs_debug_list_vfs(void) {
    qemu_debug_printf("initfs: --- VFS contents after unpack ---\n");
    int count = 0;
    initfs_debug_list_vfs_dir("/", 0, &count, 500);
    qemu_debug_printf("initfs: --- VFS total %d entries ---\n", count);
}

uintptr_t initfs_linux_ramdisk_exclusive_end(uint64_t boot_params_phys) {
    uintptr_t st = 0;
    size_t sz = 0;
    const void *bp = (const void *)(uintptr_t)boot_params_phys;
    if (linux_bootparams_ramdisk(bp, &st, &sz) != 0)
        return 0;
    uintptr_t end = st + sz;
    if (end < st)
        return 0;
    return initfs_align_up(end, 0x1000);
}

/* boot_params_phys: physical address of Linux zeropage (identity-mapped). */
int initfs_process_linux_bootparams(uint64_t boot_params_phys) {
    const void *bp = (const void *)(uintptr_t)boot_params_phys;
    uintptr_t rd_pa = 0;
    size_t rd_sz = 0;
    int v = linux_bootparams_ramdisk(bp, &rd_pa, &rd_sz);
    if (v == -2) {
        klogprintf("initfs: boot_params: missing HdrS (0x%x) at +0x%x\n",
                   LINUX_BOOTPARAM_HEADER_MAGIC, LINUX_BOOTPARAM_OFF_HDR_MAGIC);
        return 2;
    }
    if (v != 0) {
        klogprintf("initfs: boot_params: no initrd (ramdisk_size=0 or invalid)\n");
        return 3;
    }
    {
        uint64_t rd_end64;
        if (__builtin_add_overflow((uint64_t)rd_pa, (uint64_t)rd_sz, &rd_end64)) {
            klogprintf("initfs: ramdisk start+size overflow\n");
            return 5;
        }
        int ram_mb = sysinfo_ram_mb();
        if (ram_mb > 0) {
            uint64_t ram_end = (uint64_t)(unsigned)ram_mb * 1024ULL * 1024ULL;
            if (rd_end64 > ram_end) {
                klogprintf(
                    "initfs: ramdisk [0x%llx..0x%llx) past RAM end 0x%llx (%d MiB). "
                    "If load address looks like 0x20000000, use 0x02000000 (32 MiB) for reloc base.\n",
                    (unsigned long long)rd_pa, (unsigned long long)rd_end64,
                    (unsigned long long)ram_end, ram_mb);
                return 5;
            }
        }
    }
    klogprintf("initfs: Linux initrd phys 0x%llx size %llu\n",
               (unsigned long long)rd_pa, (unsigned long long)rd_sz);
    /* Multiboot2 often reports a module base just above 1 MiB (e.g. 0x103000) while the
     * decompressed payload ELF covers [0x100000, &_end). linker.payload.ld must place _end
     * after *all* BSS (incl. .bss.* and COMMON) or this skip is too small and initrd still
     * starts with kernel bytes (e.g. 53 55 56 57… = push rbx,rbp,…). */
    {
        uintptr_t ke = (uintptr_t)(void *)_end;
        klogprintf("initfs: kernel &_end %p (ramdisk start %p)\n", (void *)ke, (void *)rd_pa);
        if (rd_pa < ke) {
            if (rd_pa + rd_sz <= ke) {
                klogprintf("initfs: ramdisk region lies entirely under kernel _end %p\n", (void *)ke);
                return 4;
            }
            size_t skip = (size_t)(ke - rd_pa);
            if (skip >= rd_sz) {
                klogprintf("initfs: ramdisk skip past _end would exhaust image\n");
                return 4;
            }
            klogprintf("initfs: skipping %zu bytes overlapped by kernel (to _end %p)\n", skip, (void *)ke);
            rd_pa += skip;
            rd_sz -= skip;
        }
    }
    if (rd_sz >= 6) {
        const uint8_t *h = (const uint8_t *)rd_pa;
        klogprintf("initfs: ramdisk head %02x %02x %02x %02x %02x %02x (newc ASCII 070701 = 30 37 30 37 30 31)\n",
                   h[0], h[1], h[2], h[3], h[4], h[5]);
    }
    const void *mod_ptr = (const void *)rd_pa;
    return initfs_unpack_ramdisk_region(mod_ptr, rd_sz);
}
