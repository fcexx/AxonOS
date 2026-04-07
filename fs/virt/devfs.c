#include <devfs.h>
#include <heap.h>
#include <fs.h>
#include <ramfs.h>
#include <vga.h>
#include <vbe.h>
#include <console.h>
#include <keyboard.h>
#include <thread.h>
#include <smp.h>
#include <string.h>
#include <stddef.h>
#include <spinlock.h>
#include <ext2.h>
#include <keyboard.h>
#include <disk.h>
#include <stat.h>
#include <usb.h>
#include <fbdev.h>
#include <cirrusfb.h>

#define DEVFS_TTY_COUNT 6


static struct devfs_tty dev_ttys[DEVFS_TTY_COUNT];
static int devfs_active = 0;
static int devfs_ready = 0;

static struct fs_driver devfs_driver;
static struct fs_driver_ops devfs_ops;
static void *devfs_driver_data = NULL;

/* forward declarations (used by devfs_unlink) */
static int devfs_open(const char *path, struct fs_file **out_file);
static void devfs_release(struct fs_file *file);

/* devfs is a virtual filesystem: device nodes are not removable from userspace.
   However we must implement unlink() so tools like BusyBox rm report EPERM
   instead of ENOENT (which happens when VFS falls through to other drivers). */
static int devfs_unlink(const char *path) {
    if (!path) return -3; /* ENOENT */
    /* If this path is a valid devfs node, deny removal (EPERM). */
    struct fs_file *f = NULL;
    if (devfs_open(path, &f) == 0 && f) {
        devfs_release(f);
        return -1; /* EPERM */
    }
    return -3; /* ENOENT */
}

static inline uint32_t devfs_tty_cols(void) {
    int c = console_max_cols();
    if (c <= 0) c = MAX_COLS;
    /* vmwgfx/VBE can report a very large character grid; uncapped cols*rows*2
     * makes devfs_register() kmalloc and clear loop effectively hang boot. */
    if (c > 512) c = 512;
    return (uint32_t)c;
}

static inline uint32_t devfs_tty_rows(void) {
    int r = console_max_rows();
    if (r <= 0) r = MAX_ROWS;
    if (r > 512) r = 512;
    return (uint32_t)r;
}

static inline size_t devfs_tty_screen_bytes(void) {
    return (size_t)devfs_tty_rows() * (size_t)devfs_tty_cols() * 2u;
}

/* Fast clear for tty backing buffer: fill cells as packed VGA words. */
static inline void devfs_tty_clear_backing_fast(struct devfs_tty *tty, uint8_t attr) {
    if (!tty || !tty->screen) return;
    uint32_t cells = devfs_tty_rows() * devfs_tty_cols();
    uint16_t cell = (uint16_t)' ' | ((uint16_t)attr << 8);
    uint16_t *dst = (uint16_t*)tty->screen;
    for (uint32_t i = 0; i < cells; i++) {
        dst[i] = cell;
    }
}

/* Erase tty backing from (from_x, y) through end of line (for non-visible VC). */
static void devfs_tty_buf_erase_eol(struct devfs_tty *tty, uint32_t from_x, uint32_t y, uint8_t attr) {
    uint32_t cols = devfs_tty_cols();
    uint32_t rows = devfs_tty_rows();
    if (!tty || !tty->screen || cols == 0 || rows == 0 || y >= rows || from_x >= cols) return;
    for (uint32_t rx = from_x; rx < cols; rx++) {
        size_t off = ((size_t)y * cols + rx) * 2;
        tty->screen[off] = ' ';
        tty->screen[off + 1] = attr;
    }
}

/* Minimal tty output into backing store only (no VGA), for non-active virtual consoles. */
static void devfs_tty_virtual_putc(struct devfs_tty *tty, uint8_t c) {
    uint32_t cols = devfs_tty_cols();
    uint32_t rows = devfs_tty_rows();
    if (!tty || !tty->screen || cols == 0 || rows == 0) return;

    if (c == '\n') {
        tty->cursor_x = 0;
        if (tty->cursor_y + 1 < rows) tty->cursor_y++;
        return;
    }
    if (c == '\r') {
        tty->cursor_x = 0;
        return;
    }
    if (c == '\b' || c == 0x7F) {
        if (tty->cursor_x > 0) {
            tty->cursor_x--;
            size_t off = ((size_t)tty->cursor_y * cols + tty->cursor_x) * 2;
            tty->screen[off] = ' ';
            tty->screen[off + 1] = tty->current_attr;
        }
        return;
    }
    if (c == '\t') {
        uint32_t n = 8u - (tty->cursor_x % 8u);
        if (n == 0) n = 8;
        for (uint32_t k = 0; k < n; k++) {
            devfs_tty_virtual_putc(tty, ' ');
        }
        return;
    }
    if (tty->cursor_y >= rows) tty->cursor_y = rows - 1;
    if (tty->cursor_x >= cols) {
        tty->cursor_x = 0;
        if (tty->cursor_y + 1 < rows) tty->cursor_y++;
        else tty->cursor_y = rows - 1;
    }
    size_t off = ((size_t)tty->cursor_y * cols + tty->cursor_x) * 2;
    tty->screen[off] = c;
    tty->screen[off + 1] = tty->current_attr;
    tty->cursor_x++;
    if (tty->cursor_x >= cols) {
        tty->cursor_x = 0;
        if (tty->cursor_y + 1 < rows) tty->cursor_y++;
        else tty->cursor_y = rows - 1;
    }
}

/* Active-VC putc through console abstraction.
   We sync driver cursor from tty->cursor_x/y before emitting, then pull it back,
   so the backend (VGA text vs framebuffer) can't get out of step. */
static inline void devfs_console_putc_at_tty_cursor(struct devfs_tty *tty, uint8_t c) {
    if (!tty) return;
    console_set_cursor((uint32_t)tty->cursor_x, (uint32_t)tty->cursor_y);
    console_putc_tty_literal(c, tty->current_attr);
    console_get_cursor(&tty->cursor_x, &tty->cursor_y);
}

/* simple block device node registry for /dev/hdN */
struct devfs_block {
    char path[32];
    int device_id;
    uint32_t start_lba;
    uint32_t sectors;
    spinlock_t io_lock; /* сериализация read/write для стабильности */
};
static struct devfs_block dev_blocks[16];
static int dev_block_count = 0;
/* character device nodes (e.g., /dev/fb0) */
struct devfs_char {
    char path[32];
    void *driver_private;
};
static struct devfs_char dev_chars[16];
static int dev_char_count = 0;
static uint32_t devfs_rand_state = 0x12345678;
/* special device names exposed under /dev */
static const char * const devfs_special_names[] = {
    "null", "zero", "random",
    "stdin", "stdout", "stderr",
    "tty",          /* controlling tty (alias to thread-attached tty) */
    "urandom"
};
static const int devfs_special_count = sizeof(devfs_special_names) / sizeof(devfs_special_names[0]);

/* entropy and RNG state */
static uint32_t devfs_entropy = 0;
static int devfs_random_waiters[16];
static int devfs_random_waiters_count = 0;

/* simple ring buffers for /dev/stdout and /dev/stderr to allow reading */
typedef struct {
    char *buf;
    size_t head;
    size_t tail;
    size_t cap;
    spinlock_t lock;
    int waiters[8];
    int waiters_count;
} stdio_ring_t;
static stdio_ring_t stdio_bufs[2]; /* 0 = stdout, 1 = stderr */

/* helper: get tty index from path like /dev/ttyN */
static int devfs_path_to_tty(const char *path) {
    if (!path) return -1;
    if (strcmp(path, "/dev/console") == 0) return 0;
    /* /dev/N -> ttyN (getty/inittab sometimes passes "1" = tty1 = first VC) */
    if (strncmp(path, "/dev/", 5) == 0 && path[5] >= '0' && path[5] <= '9' && path[6] == '\0') {
        int n = path[5] - '0';
        if (n >= 1 && n <= DEVFS_TTY_COUNT) return n - 1;  /* 1->0, 2->1, ... */
        if (n == 0) return 0;
    }
    /* /dev/vc/N -> ttyN (BusyBox CURRENT_VC = /dev/vc/0) */
    if (strncmp(path, "/dev/vc/", 8) == 0 && path[8] >= '0' && path[8] < '0' + DEVFS_TTY_COUNT && path[9] == '\0')
        return path[8] - '0';
    if (strncmp(path, "/dev/tty", 8) == 0) {
        /* /dev/ttyS0 -> map to tty0 (serial console alias) */
        if (path[8] == 'S' && path[9] >= '0' && path[9] <= '9' && path[10] == '\0') {
            int sn = path[9] - '0';
            if (sn >= 0 && sn < DEVFS_TTY_COUNT) return sn;
            return 0;
        }
        /* /dev/ttyN: Linux tty1 = first VC, tty2 = second VC. Our index 0 = first VC. */
        if (path[8] >= '0' && path[8] <= '9' && path[9] == '\0') {
            int n = path[8] - '0';
            if (n >= 1 && n <= DEVFS_TTY_COUNT) return n - 1;  /* tty1->0, tty2->1, ... */
            if (n == 0) return 0;  /* tty0 = current = first at boot */
        }
    }
    return -1;
}

static struct fs_file *devfs_alloc_file(const char *path, int tty) {
    struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
    if (!f) return NULL;
    memset(f, 0, sizeof(*f));
    size_t plen = strlen(path) + 1;
    char *pp = (char*)kmalloc(plen);
    if (!pp) { kfree(f); return NULL; }
    memcpy(pp, path, plen);
    f->path = (const char*)pp;
    f->fs_private = &devfs_driver_data;
    f->driver_private = (void*)&dev_ttys[tty];
    f->type = FS_TYPE_REG;
    f->size = 0;
    f->pos = 0;
    return f;
}

static int devfs_create(const char *path, struct fs_file **out_file) {
    (void)path; (void)out_file;
    /* devfs does not support file creation */
    return -1;
}

static int devfs_open(const char *path, struct fs_file **out_file) {
    if (!path) return -1;
    /* directory /dev */
    if (strcmp(path, "/dev") == 0 || strcmp(path, "/dev/") == 0) {
        struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
        if (!f) return -1;
        memset(f, 0, sizeof(*f));
        size_t plen = strlen(path) + 1;
        char *pp = (char*)kmalloc(plen);
        if (!pp) { kfree(f); return -1; }
        memcpy(pp, path, plen);
        f->path = (const char*)pp;
        f->fs_private = NULL;
        /* allocate a simple handle to mark directory */
        struct { int is_dir; int dir_count; } *h = kmalloc(sizeof(*h));
        if (!h) { kfree((void*)f->path); kfree(f); return -1; }
        h->is_dir = 1;
        h->dir_count = DEVFS_TTY_COUNT + 1; /* console + ttyN */
        f->driver_private = (void*)h;
        f->type = FS_TYPE_DIR;
        f->size = 0;
        f->pos = 0;
        /* opened directory */
        f->fs_private = &devfs_driver_data;
        *out_file = f;
        return 0;
    }
    /* block device? */
    int bi = devfs_find_block_by_path(path);
    if (bi >= 0) {
        struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
        if (!f) return -1;
        memset(f, 0, sizeof(*f));
        size_t plen = strlen(path) + 1;
        char *pp = (char*)kmalloc(plen);
        if (!pp) { kfree(f); return -1; }
        memcpy(pp, path, plen);
        f->path = (const char*)pp;
        f->fs_private = &devfs_driver_data;
        f->driver_private = (void*)&dev_blocks[bi];
        f->type = FS_TYPE_REG;
        f->size = (off_t)dev_blocks[bi].sectors * 512;
        f->pos = 0;
        *out_file = f;
        return 0;
    }
    /* character device nodes (registered via devfs_create_char_node) */
    for (int ci = 0; ci < dev_char_count; ci++) {
        if (strcmp(path, dev_chars[ci].path) == 0) {
            struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
            if (!f) return -1;
            memset(f, 0, sizeof(*f));
            size_t plen = strlen(path) + 1;
            char *pp = (char*)kmalloc(plen);
            if (!pp) { kfree(f); return -1; }
            memcpy(pp, path, plen);
            f->path = (const char*)pp;
            f->fs_private = &devfs_driver_data;
            f->driver_private = dev_chars[ci].driver_private;
            f->type = FS_TYPE_REG;
            f->size = (strcmp(path, "/dev/fb0") == 0) ? (size_t)fbdev_byte_len() : 0;
            f->pos = 0;
            *out_file = f;
            return 0;
        }
    }
    /* special device nodes like /dev/null, /dev/zero, /dev/random, /dev/stdin/out/err */
    for (int si = 0; si < devfs_special_count; si++) {
        char spath[32];
        snprintf(spath, sizeof(spath), "/dev/%s", devfs_special_names[si]);
        if (strcmp(path, spath) == 0) {
            struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
            if (!f) return -1;
            memset(f, 0, sizeof(*f));
            size_t plen = strlen(path) + 1;
            char *pp = (char*)kmalloc(plen);
            if (!pp) { kfree(f); return -1; }
            memcpy(pp, path, plen);
            f->path = (const char*)pp;
            f->fs_private = &devfs_driver_data;
            int *ptype = (int*)kmalloc(sizeof(int));
            if (!ptype) { kfree((void*)f->path); kfree(f); return -1; }
            *ptype = 0x80000000 | si;
            f->driver_private = (void*)ptype;
            f->type = FS_TYPE_REG;
            f->size = 0;
            *out_file = f;
            return 0;
        }
    }
    int tty = devfs_path_to_tty(path);
    if (tty < 0) return -1;
    struct fs_file *f = devfs_alloc_file(path, tty);
    if (!f) return -1;
    *out_file = f;
    return 0;
}

struct fs_file *devfs_open_direct(const char *path) {
    struct fs_file *f = NULL;
    if (devfs_open(path, &f) == 0) return f;
    return NULL;
}

static ssize_t devfs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    if (!file || !buf) return -1;
    if (usb_is_devfs_file(file)) return usb_devfs_read(file, buf, size, offset);
    if (file->path && strcmp(file->path, "/dev/fb0") == 0) {
        if (!fbdev_is_active()) return -1;
        size_t flen = fbdev_byte_len();
        if (offset >= flen) return 0;
        if (offset + size > flen) size = flen - offset;
        fbdev_copy_to(buf, offset, size);
        return (ssize_t)size;
    }
    /* block device file handling: батч-чтение по 64 KB для стабильности при множестве операций */
    for (int bi = 0; bi < dev_block_count; bi++) {
        if (file->driver_private == &dev_blocks[bi]) {
            struct devfs_block *b = (struct devfs_block*)file->driver_private;
            unsigned long flags = 0;
            acquire_irqsave(&b->io_lock, &flags);
            uint64_t dev_size_bytes = (uint64_t)b->sectors * 512ULL;
            if (offset >= dev_size_bytes) { release_irqrestore(&b->io_lock, flags); return 0; }
            if ((uint64_t)offset + size > dev_size_bytes) size = (size_t)(dev_size_bytes - offset);
            uint32_t start_sector = (uint32_t)(offset / 512);
            uint32_t nsectors = (uint32_t)((offset + size + 511) / 512) - start_sector;
            size_t off_in_first = offset % 512;
            size_t copied = 0;
#define DEVFS_BLOCK_CHUNK_SECTORS 128
#define DEVFS_BLOCK_CHUNK_BYTES   (DEVFS_BLOCK_CHUNK_SECTORS * 512)
            void *chunk = kmalloc(DEVFS_BLOCK_CHUNK_BYTES);
            if (!chunk) { release_irqrestore(&b->io_lock, flags); return -1; }
            uint32_t s = 0;
            while (s < nsectors) {
                if (keyboard_ctrlc_pending()) {
                    keyboard_consume_ctrlc();
                    kfree(chunk);
                    release_irqrestore(&b->io_lock, flags);
                    return -1;
                }
                uint32_t chunk_sectors = nsectors - s;
                if (chunk_sectors > DEVFS_BLOCK_CHUNK_SECTORS) chunk_sectors = DEVFS_BLOCK_CHUNK_SECTORS;
                memset(chunk, 0, (size_t)chunk_sectors * 512);
                if (disk_read_sectors(b->device_id, b->start_lba + start_sector + s, chunk, chunk_sectors) != 0) {
                    kfree(chunk);
                    release_irqrestore(&b->io_lock, flags);
                    return -1;
                }
                uint8_t *src = (uint8_t*)chunk;
                for (uint32_t i = 0; i < chunk_sectors && copied < size; i++) {
                    size_t src_off = (s == 0 && i == 0) ? off_in_first : 0;
                    size_t seg = (size_t)(512 - (uint32_t)src_off);
                    if (seg > size - copied) seg = size - copied;
                    memcpy((uint8_t*)buf + copied, src + (size_t)(i * 512) + src_off, seg);
                    copied += seg;
                }
                s += chunk_sectors;
                if (s < nsectors) thread_yield();
            }
            kfree(chunk);
            release_irqrestore(&b->io_lock, flags);
            return (ssize_t)copied;
        }
    }
    /* special devices via driver_private marker */
    if (file->driver_private) {
        int marker = *(int*)file->driver_private;
        if ((marker & 0x80000000) == 0x80000000) {
            int si = marker & 0x7FFFFFFF;
            switch (si) {
                case 0: return 0; /* /dev/null */
                case 1: memset(buf, 0, size); return (ssize_t)size; /* /dev/zero */
                case 2: { /* /dev/random: non-blocking like /dev/urandom (always generate) */
                    uint8_t *p = (uint8_t*)buf;
                    for (size_t i = 0; i < size; i++) {
                        devfs_rand_state ^= devfs_rand_state << 13;
                        devfs_rand_state ^= devfs_rand_state >> 17;
                        devfs_rand_state ^= devfs_rand_state << 5;
                        p[i] = (uint8_t)(devfs_rand_state & 0xFF);
                    }
                    return (ssize_t)size;
                }
                case 3: { /* /dev/stdin -> map to console tty */
                    /* Map /dev/stdin to the tty attached to current thread if present,
                       otherwise to the active console. */
                    thread_t *cur = thread_current();
                    int tty_idx = (cur && cur->attached_tty >= 0) ? cur->attached_tty : devfs_get_active();
                    struct devfs_tty *tstdin = &dev_ttys[tty_idx];
                    file->driver_private = (void*)tstdin;
                    break;
                }
                case 6: { /* /dev/tty -> map to controlling tty (same logic as stdin) */
                    thread_t *cur = thread_current();
                    int tty_idx = (cur && cur->attached_tty >= 0) ? cur->attached_tty : devfs_get_active();
                    struct devfs_tty *tstdin = &dev_ttys[tty_idx];
                    file->driver_private = (void*)tstdin;
                    break;
                }
                case 7: { /* /dev/urandom - non-blocking random */
                    uint8_t *p = (uint8_t*)buf;
                    for (size_t i=0;i<size;i++) {
                        devfs_rand_state ^= devfs_rand_state << 13;
                        devfs_rand_state ^= devfs_rand_state >> 17;
                        devfs_rand_state ^= devfs_rand_state << 5;
                        p[i] = (uint8_t)(devfs_rand_state & 0xFF);
                    }
                    return (ssize_t)size;
                }
                default: break;
            }
        }
    }
    /* Support reading from /dev/stdout and /dev/stderr ring buffers */
    if (file->path) {
        if (strcmp(file->path, "/dev/stdout") == 0 || strcmp(file->path, "/dev/stderr") == 0) {
            int which = (strcmp(file->path, "/dev/stdout") == 0) ? 0 : 1;
            stdio_ring_t *rb = &stdio_bufs[which];
            size_t got = 0;
            char *outp = (char*)buf;
            for (;;) {
                unsigned long flags = 0;
                acquire_irqsave(&rb->lock, &flags);
                if (rb->head != rb->tail) {
                    outp[got++] = rb->buf[rb->head];
                    rb->head = (rb->head + 1) % rb->cap;
                    /* wake writers not needed */
                    release_irqrestore(&rb->lock, flags);
                    if (got >= size) break;
                    continue;
                }
                /* empty: block current thread until data written */
                thread_t *cur = thread_current();
                if (cur && cur->tid != 0) {
                    if (rb->waiters_count < (int)(sizeof(rb->waiters)/sizeof(rb->waiters[0]))) {
                        rb->waiters[rb->waiters_count++] = (int)cur->tid;
                    }
                    release_irqrestore(&rb->lock, flags);
                    thread_block((int)cur->tid);
                    thread_yield();
                    continue;
                } else {
                    release_irqrestore(&rb->lock, flags);
                    break;
                }
            }
            return (ssize_t)got;
        }
    }
    /* directory read */
    if (file->type == FS_TYPE_DIR && file->driver_private) {
        uint8_t *out = (uint8_t*)buf;
        size_t pos = 0;
        size_t written = 0;
        /* Emit "." and ".." first for POSIX/readdir compatibility */
        static const char *const dot_entries[] = { ".", ".." };
        for (int di = 0; di < 2; di++) {
            const char *nm = dot_entries[di];
            size_t namelen = strlen(nm);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (rec_len < sizeof(struct ext2_dir_entry)) rec_len = sizeof(struct ext2_dir_entry);
            if (pos + rec_len <= (size_t)offset) { pos += rec_len; continue; }
            if (written >= size) break;
            uint8_t tmp[64];
            for (size_t zi = 0; zi < sizeof(tmp); zi++) tmp[zi] = 0;
            struct ext2_dir_entry de;
            memset(&de, 0, sizeof(de));
            de.inode = 1;
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_DIR;
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, nm, namelen);
            size_t entry_off = ((size_t)offset > pos) ? (size_t)offset - pos : 0;
            size_t avail = size - written;
            size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
            if (tocopy > avail) tocopy = avail;
            memcpy(out + written, tmp + entry_off, tocopy);
            written += tocopy;
            pos += rec_len;
        }
        /* include ttys + console + any registered block devices */
        int total_with_special = (DEVFS_TTY_COUNT + 1) + devfs_special_count + dev_block_count + dev_char_count;
        for (int i = 0; i < total_with_special; i++) {
            const char *nm;
            char tmpn[64];
            if (i == 0) {
                nm = "console";
            } else if (i <= DEVFS_TTY_COUNT) {
                tmpn[0] = 't'; tmpn[1] = 't'; tmpn[2] = 'y';
                tmpn[3] = '0' + (char)(i-1);
                tmpn[4] = '\0';
                nm = tmpn;
            } else if (i <= DEVFS_TTY_COUNT + devfs_special_count) {
                int si = i - (DEVFS_TTY_COUNT + 1);
                if (si >=0 && si < devfs_special_count) nm = devfs_special_names[si];
                else nm = "";
            } else {
                /* block device entries stored in dev_blocks[] and character devices in dev_chars[] */
                int bi = i - (DEVFS_TTY_COUNT + 1 + devfs_special_count);
                const char *path = NULL;
                if (bi < dev_block_count)
                    path = dev_blocks[bi].path;
                else if (bi - dev_block_count < dev_char_count)
                    path = dev_chars[bi - dev_block_count].path;
                if (path) {
                    /* /dev directory listing must include only direct children.
                       Skip nested paths like /dev/bus/usb/001/001 (they belong to subdirs). */
                    if (strncmp(path, "/dev/", 5) == 0) {
                        const char *rest = path + 5;
                        if (strchr(rest, '/')) {
                            pos += 8;
                            continue;
                        }
                    }
                    /* Bounded copy so we never read past path[31] or emit garbage from uninitialized bytes */
                    char safe_path[32];
                    size_t plen = 0;
                    while (plen < sizeof(safe_path) - 1 && path[plen] != '\0') plen++;
                    safe_path[plen] = '\0';
                    if (plen > 0) memcpy(safe_path, path, plen);
                    const char *last = strrchr(safe_path, '/');
                    const char *base = last ? (last + 1) : safe_path;
                    size_t blen = strlen(base);
                    if (blen >= sizeof(tmpn)) blen = sizeof(tmpn) - 1;
                    memcpy(tmpn, base, blen);
                    tmpn[blen] = '\0';
                    /* Sanitize: only printable ASCII to avoid ls "?X?..." garbage */
                    for (size_t k = 0; k < blen; k++) {
                        unsigned char c = (unsigned char)tmpn[k];
                        if (c < 32 || c > 126) tmpn[k] = '?';
                    }
                    nm = tmpn;
                } else {
                    nm = "";
                }
            }
            size_t namelen = strlen(nm);
            if (namelen == 0) { pos += 8; continue; } /* skip empty names */
            size_t rec_len = 8 + namelen;
            /* pad to 4-byte boundary like ext2 dirent */
            rec_len = (rec_len + 3) & ~3u;
            if (rec_len < sizeof(struct ext2_dir_entry)) rec_len = sizeof(struct ext2_dir_entry);
            if (pos + rec_len <= (size_t)offset) { pos += rec_len; continue; }
            if (written >= size) break;
            uint8_t tmp[512];
            if (rec_len > sizeof(tmp)) {
                /* name too long for our entry buffer -> skip safely */
                pos += rec_len;
                continue;
            }
            /* initialize buffer and ext2_dir_entry */
            for (size_t zi = 0; zi < rec_len; zi++) tmp[zi] = 0;
            struct ext2_dir_entry de;
            memset(&de, 0, sizeof(de));
            de.inode = (uint32_t)(i + 1);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_REG_FILE;
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, nm, namelen);
            size_t entry_off = 0;
            if ((size_t)offset > pos) entry_off = (size_t)offset - pos;
            size_t avail = size - written;
            size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
            if (tocopy > avail) tocopy = avail;
            memcpy(out + written, tmp + entry_off, tocopy);
            written += tocopy;
            pos += rec_len;
        }
        return (ssize_t)written;
    }
    /* regular device read (tty) */
    struct devfs_tty *t = (struct devfs_tty*)file->driver_private;
    if (!t) return -1;
    size_t got = 0;
    char *out = (char*)buf;
    while (got < size) {
        unsigned long flags = 0;
        acquire_irqsave(&t->in_lock, &flags);
        if (t->in_count > 0) {
            /* pop one */
            /* Decide mode: canonical vs non-canonical */
            int is_canonical = (t->term_lflag & 0x00000002u) ? 1 : 0; /* ICANON bit (kernel mapping) */
            if (is_canonical) {
                /* canonical: deliver one char, stop on newline */
                char c = t->inbuf[t->in_head];
                t->in_head = (t->in_head + 1) % (int)sizeof(t->inbuf);
                t->in_count--;
                release_irqrestore(&t->in_lock, flags);
                if (c == '\r') c = '\n';
                out[got++] = c;
                if (c == '\n') break;
                continue;
            } else {
                /* non-canonical: deliver ONE byte per lock hold so ISR never drops keypresses.
                 * (Holding lock for N bytes caused next N keypresses to be dropped.) */
                char c = t->inbuf[t->in_head];
                t->in_head = (t->in_head + 1) % (int)sizeof(t->inbuf);
                t->in_count--;
                release_irqrestore(&t->in_lock, flags);
                out[got++] = c;
                if (got > 0) break;
                continue;
            }
        }
        /* no data: block current thread until pushed */
        thread_t* cur = thread_current();
        if (cur) {
            /* If current is main kernel thread (tid 0), fall back to direct blocking kgetc */
            if (cur->tid == 0) {
                release_irqrestore(&t->in_lock, flags);
                char c = kgetc();
                if (c == '\r') c = '\n';
                /* deliver character (including backspace) to userspace and do not echo here */
                out[got++] = c;
                if (c == '\n') break;
                continue;
            }
            /* add to waiters if not already */
            int tid = (int)cur->tid;
            int already = 0;
            for (int i = 0; i < t->waiters_count; i++) if (t->waiters[i] == tid) { already = 1; break; }
            if (!already && t->waiters_count < (int)(sizeof(t->waiters)/sizeof(t->waiters[0]))) {
                t->waiters[t->waiters_count++] = tid;
            }
            release_irqrestore(&t->in_lock, flags);
            thread_block((int)cur->tid);
            thread_yield();
            /* Woke: if still no data but have pending SIGINT (Ctrl+C), return EINTR
               so read() returns and maybe_deliver_pending_signal can terminate the process. */
            acquire_irqsave(&t->in_lock, &flags);
            if (t->in_count == 0) {
                thread_t *me = thread_current();
                if (me && (me->pending_signals & (1ULL << 1))) { /* SIGINT=2, bit 1 */
                    release_irqrestore(&t->in_lock, flags);
                    return got > 0 ? (ssize_t)got : (ssize_t)-4; /* -EINTR */
                }
            }
            release_irqrestore(&t->in_lock, flags);
            /* when unblocked with data, loop to try again */
            continue;
        } else {
            release_irqrestore(&t->in_lock, flags);
            return (ssize_t)got;
        }
    }
    return (ssize_t)got;
}

static ssize_t devfs_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
    if (!file || !buf) return -1;
    if (usb_is_devfs_file(file)) return usb_devfs_write(file, buf, size, offset);
    if (file->path && strcmp(file->path, "/dev/fb0") == 0) {
        if (!fbdev_is_active()) return -1;
        size_t flen = fbdev_byte_len();
        if (offset >= flen) return -1;
        if (offset + size > flen) size = flen - offset;
        fbdev_copy_from(offset, buf, size);
        return (ssize_t)size;
    }
    /* special devices via driver_private marker: handle /dev/null, /dev/zero, /dev/random writes */
    if (file->driver_private) {
        uintptr_t dp = (uintptr_t)file->driver_private;
        if (!(dp >= (uintptr_t)&dev_ttys[0] && dp < (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT])) {
            /* likely a marker pointer */
            int marker = *(int*)file->driver_private;
            if ((marker & 0x80000000) == 0x80000000) {
                int si = marker & 0x7FFFFFFF;
                switch (si) {
                    case 0: /* /dev/null */ return (ssize_t)size;
                    case 1: /* /dev/zero */ return (ssize_t)size;
                    case 2: /* /dev/random - mix written bytes into RNG state and accept */
                    {
                        const uint8_t *p = (const uint8_t*)buf;
                        for (size_t i = 0; i < size; i++) {
                            devfs_rand_state ^= (uint32_t)p[i];
                            devfs_rand_state = (devfs_rand_state << 5) | (devfs_rand_state >> 27);
                        }
                        /* increase entropy estimate and wake any random waiters */
                        devfs_entropy += (uint32_t)size;
                        if (devfs_random_waiters_count > 0) {
                            for (int wi = 0; wi < devfs_random_waiters_count; wi++) {
                                int tid = devfs_random_waiters[wi];
                                if (tid >= 0) thread_unblock(tid);
                            }
                            devfs_random_waiters_count = 0;
                        }
                        return (ssize_t)size;
                    }
                    default: break;
                }
            }
        }
    }
    /* block device write: чанками по 64 KB, чтобы не исчерпывать кучу и не зависать */
    for (int bi = 0; bi < dev_block_count; bi++) {
        if (file->driver_private == &dev_blocks[bi]) {
            struct devfs_block *b = (struct devfs_block*)file->driver_private;
            unsigned long flags = 0;
            acquire_irqsave(&b->io_lock, &flags);
            uint64_t dev_size_bytes = (uint64_t)b->sectors * 512ULL;
            if (offset >= dev_size_bytes) { release_irqrestore(&b->io_lock, flags); return -1; }
            if ((uint64_t)offset + size > dev_size_bytes) size = (size_t)(dev_size_bytes - offset);
            uint32_t start_sector = (uint32_t)(offset / 512);
            uint32_t nsectors = (uint32_t)((offset + size + 511) / 512) - start_sector;
            size_t off_in_first = offset % 512;
#define DEVFS_WRITE_CHUNK_SECTORS 128
#define DEVFS_WRITE_CHUNK_BYTES   (DEVFS_WRITE_CHUNK_SECTORS * 512)
            void *tmp = kmalloc(DEVFS_WRITE_CHUNK_BYTES);
            if (!tmp) { release_irqrestore(&b->io_lock, flags); return -1; }
            size_t written = 0;
            uint32_t cur_sector = 0;
            while (cur_sector < nsectors) {
                if (keyboard_ctrlc_pending()) {
                    keyboard_consume_ctrlc();
                    kfree(tmp);
                    release_irqrestore(&b->io_lock, flags);
                    return -1;
                }
                uint32_t chunk_sectors = nsectors - cur_sector;
                if (chunk_sectors > DEVFS_WRITE_CHUNK_SECTORS) chunk_sectors = DEVFS_WRITE_CHUNK_SECTORS;
                if (disk_read_sectors(b->device_id, b->start_lba + start_sector + cur_sector, tmp, chunk_sectors) != 0) {
                    kfree(tmp);
                    release_irqrestore(&b->io_lock, flags);
                    return -1;
                }
                size_t merge_off = (cur_sector == 0) ? off_in_first : 0;
                size_t merge_max = (size_t)chunk_sectors * 512 - merge_off;
                size_t merge_len = size - written;
                if (merge_len > merge_max) merge_len = merge_max;
                memcpy((uint8_t*)tmp + merge_off, (const uint8_t*)buf + written, merge_len);
                written += merge_len;
                if (disk_write_sectors(b->device_id, b->start_lba + start_sector + cur_sector, tmp, chunk_sectors) != 0) {
                    kfree(tmp);
                    release_irqrestore(&b->io_lock, flags);
                    return -1;
                }
                cur_sector += chunk_sectors;
                if (cur_sector < nsectors) thread_yield();
            }
            kfree(tmp);
            release_irqrestore(&b->io_lock, flags);
            return (ssize_t)size;
        }
    }
    /* Resolve driver_private: it may be either a pointer into dev_ttys (tty handle)
       or a pointer to an allocated int marker for special devices (/dev/null, /dev/stdout, etc). */
    void *dp = file->driver_private;
    if (!dp) return -1;
    struct devfs_tty *t = NULL;
    uintptr_t p = (uintptr_t)dp;
    if (p >= (uintptr_t)&dev_ttys[0] && p < (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT]) {
        /* already a tty pointer */
        t = (struct devfs_tty*)dp;
    } else {
        /* assume marker pointer (allocated int) */
        int marker = *(int*)dp;
        if ((marker & 0x80000000) == 0x80000000) {
            int si = marker & 0x7FFFFFFF;
            if (si == 4 || si == 5) { /* stdout or stderr */
                thread_t *cur = thread_current();
                int tty = (cur && cur->attached_tty >= 0) ? cur->attached_tty : devfs_get_active();
                t = &dev_ttys[tty];
                /* update file handle to point directly to tty to avoid repeated marker derefs */
                file->driver_private = (void*)t;
            } else if (si == 3 || si == 6) {
                /* /dev/stdin used for writing — map to console tty */
                thread_t *cur = thread_current();
                int tty = (cur && cur->attached_tty >= 0) ? cur->attached_tty : devfs_get_active();
                t = &dev_ttys[tty];
                file->driver_private = (void*)t;
            } else {
                /* other special devices are not writable here */
                return -1;
            }
        } else {
            return -1;
        }
    }
    if (!t) return -1;
    /* Route any tty-like output to the currently visible VC.
       This is the "single fbcon" mode expected by early init/userspace consoles:
       regardless of which tty handle a program has, writes must land on devfs_active. */
    if (devfs_is_tty_file(file)) {
        t = &dev_ttys[devfs_get_active()];
    }
    int idx = t->id;
    const char *s = (const char*)buf;
    for (size_t i = 0; i < size; i++) {
        char ch = s[i];
        {
            const int tty_on_vga = (idx == devfs_active);
            /* Parse ANSI for every VC; drive VGA only when this tty is visible. */
            struct devfs_tty *tty = t;
            /* Hot path: ESC[2JESC[H (clear then home) - many apps use this */
            if (tty->ansi_escape_state == 0 &&
                i + 7 <= size &&
                (unsigned char)s[i + 0] == 0x1B && s[i + 1] == '[' && s[i + 2] == '2' && s[i + 3] == 'J' &&
                (unsigned char)s[i + 4] == 0x1B && s[i + 5] == '[' && s[i + 6] == 'H') {
                devfs_tty_clear_backing_fast(tty, tty->current_attr);
                tty->cursor_x = 0;
                tty->cursor_y = 0;
                if (tty_on_vga) {
                    console_clear_screen_attr(tty->current_attr);
                    console_set_cursor(0, 0);
                }
                i += 6;
                continue;
            }
            /* Hot path: ESC[H (cursor home) - getty/login prompt */
            if (tty->ansi_escape_state == 0 &&
                i + 3 <= size &&
                (unsigned char)s[i + 0] == 0x1B && s[i + 1] == '[' && s[i + 2] == 'H') {
                tty->cursor_x = 0;
                tty->cursor_y = 0;
                if (tty_on_vga) console_set_cursor(0, 0);
                i += 2;
                continue;
            }
            /* Hot path: ESC[HESC[J (BusyBox getty/clear: home then erase to end) */
            if (tty->ansi_escape_state == 0 &&
                i + 6 <= size &&
                (unsigned char)s[i + 0] == 0x1B && s[i + 1] == '[' && s[i + 2] == 'H' &&
                (unsigned char)s[i + 3] == 0x1B && s[i + 4] == '[' && s[i + 5] == 'J') {
                devfs_tty_clear_backing_fast(tty, tty->current_attr);
                tty->cursor_x = 0;
                tty->cursor_y = 0;
                if (tty_on_vga) {
                    console_clear_screen_attr(tty->current_attr);
                    console_set_cursor(0, 0);
                }
                i += 5;
                continue;
            }
            /* simple streaming ANSI CSI parser for a subset of sequences */
            if (tty->ansi_escape_state == 0) {
                if ((unsigned char)ch == 0x1B) {
                    tty->ansi_escape_state = 1; /* ESC seen */
                } else if (ch == '[' && i + 1 < size && s[i + 1] == 'H') {
                    tty->cursor_x = 0;
                    tty->cursor_y = 0;
                    if (tty_on_vga) console_set_cursor(0, 0);
                    i += 1;
                    continue;
                } else if (ch == '\r') {
                    /* carriage return: erase from cursor to EOL (no cursor advance), then move to start of line */
                    uint32_t tty_cols = devfs_tty_cols();
                    if (tty_cols == 0) tty_cols = MAX_COLS;
                    if (tty_on_vga) {
                        console_clear_line_segment(tty->cursor_x, tty_cols - 1, tty->cursor_y, tty->current_attr);
                        tty->cursor_x = 0;
                        console_set_cursor(0, tty->cursor_y);
                    } else {
                        devfs_tty_buf_erase_eol(tty, tty->cursor_x, tty->cursor_y, tty->current_attr);
                        tty->cursor_x = 0;
                    }
                } else if (ch == '\b' || (unsigned char)ch == 0x7F) {
                    /* backspace / DEL: move cursor left and clear cell (app line editor) */
                    if (tty_on_vga) {
                        devfs_console_putc_at_tty_cursor(tty, (uint8_t)'\b');
                    } else {
                        devfs_tty_virtual_putc(tty, (uint8_t)'\b');
                    }
                } else {
                    /* normal character output using current attribute */
                    if (tty_on_vga) {
                        devfs_console_putc_at_tty_cursor(tty, (uint8_t)ch);
                    } else {
                        devfs_tty_virtual_putc(tty, (uint8_t)ch);
                    }
                }
            } else if (tty->ansi_escape_state == 1) {
                if ((unsigned char)ch == '[') {
                    tty->ansi_escape_state = 2; /* CSI start */
                    tty->ansi_param_count = 0;
                    tty->ansi_current_param = 0;
                    if (i + 1 < size && s[i + 1] == 'H') {
                        tty->cursor_x = 0;
                        tty->cursor_y = 0;
                        if (tty_on_vga) console_set_cursor(0, 0);
                        tty->ansi_escape_state = 0;
                        i += 1;
                        continue;
                    }
                } else if ((unsigned char)ch == 'O') {
                    tty->ansi_escape_state = 3; /* SS3 (ESC O A/B/C/D) */
                } else {
                    /* unknown sequence, reset and output the ESC as literal */
                    tty->ansi_escape_state = 0;
                    if (tty_on_vga) {
                        devfs_console_putc_at_tty_cursor(tty, (uint8_t)0x1B);
                        devfs_console_putc_at_tty_cursor(tty, (uint8_t)ch);
                    } else {
                        devfs_tty_virtual_putc(tty, 0x1B);
                        devfs_tty_virtual_putc(tty, (uint8_t)ch);
                    }
                }
            } else if (tty->ansi_escape_state == 3) {
                /* SS3: single final byte (e.g. A=up, B=down, C=right, D=left) */
                unsigned char fc = (unsigned char)ch;
                if (fc == 'A') {
                    if (tty->cursor_y > 0) tty->cursor_y--;
                    if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                } else if (fc == 'B') {
                    uint32_t tty_rows = devfs_tty_rows();
                    if (tty->cursor_y + 1 < tty_rows) tty->cursor_y++;
                    if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                } else if (fc == 'C') {
                    uint32_t tty_cols = devfs_tty_cols();
                    if (tty->cursor_x + 1 < tty_cols) tty->cursor_x++;
                    if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                } else if (fc == 'D') {
                    if (tty->cursor_x > 0) tty->cursor_x--;
                    if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                }
                tty->ansi_escape_state = 0;
            } else if (tty->ansi_escape_state == 2) {
                /* CSI parsing: accumulate parameters until final byte */
                if (ch >= '0' && ch <= '9') {
                    tty->ansi_current_param = tty->ansi_current_param * 10 + (ch - '0');
                } else if (ch == '?' || ch == '>') {
                    /* DEC/HP private mode marker - skip, continue parsing */
                } else if (ch == ';') {
                    if (tty->ansi_param_count < (int)(sizeof(tty->ansi_param)/sizeof(tty->ansi_param[0]))) {
                        tty->ansi_param[tty->ansi_param_count++] = tty->ansi_current_param;
                    }
                    tty->ansi_current_param = 0;
                } else {
                    /* final byte of CSI */
                    if (tty->ansi_param_count < (int)(sizeof(tty->ansi_param)/sizeof(tty->ansi_param[0]))) {
                        tty->ansi_param[tty->ansi_param_count++] = tty->ansi_current_param;
                    }
                    unsigned char final_byte = (unsigned char)ch;
                    if (final_byte == 'm') {
                        /* SGR - simple color management */
                        if (tty->ansi_param_count == 0) {
                            tty->current_attr = GRAY_ON_BLACK;
                            tty->ansi_bold = 0;
                        } else {
                            int bright = tty->ansi_bold ? 1 : 0;
                            for (int pi = 0; pi < tty->ansi_param_count; pi++) {
                                int code = tty->ansi_param[pi];
                                if (code == 0) {
                                    tty->current_attr = GRAY_ON_BLACK;
                                    bright = 0;
                                } else if (code == 1) {
                                    bright = 1;
                                } else if (code == 22) {
                                    bright = 0;
                                } else if (code == 39) {
                                    /* default foreground: keep current BG, set FG to white (7) */
                                    int bg = (tty->current_attr & 0xF0) >> 4;
                                    int fg = 7;
                                    if (bright) fg |= 8;
                                    tty->current_attr = (bg << 4) | (fg & 0x0F);
                                } else if (code >= 30 && code <= 37) {
                                    /* Map ANSI colors to VGA palette indexes */
                                    static const uint8_t ansi_to_vga[8] = {0, 4, 2, 6, 1, 5, 3, 7};
                                    int ansi = code - 30;
                                    int fg_vga = ansi_to_vga[ansi & 7];
                                    if (bright) fg_vga |= 8;
                                    int bg = (tty->current_attr & 0xF0) >> 4;
                                    tty->current_attr = (uint8_t)((bg << 4) | (fg_vga & 0x0F));
                                } else if (code >= 40 && code <= 47) {
                                    static const uint8_t ansi_to_vga_bg[8] = {0, 4, 2, 6, 1, 5, 3, 0};
                                    int ansi_bg = code - 40;
                                    int bg_vga = ansi_to_vga_bg[ansi_bg & 7];
                                    int fg = tty->current_attr & 0x0F;
                                    tty->current_attr = (uint8_t)((bg_vga << 4) | (fg & 0x0F));
                                } else {
                                    /* ignore other codes for simplicity */
                                }
                            }
                            tty->ansi_bold = bright ? 1 : 0;
                        }
                    } else if (final_byte == 'H' || final_byte == 'f') {
                        /* Cursor position: ESC [ <row> ; <col> H (1-based) */
                        int row = 1, col = 1;
                        if (tty->ansi_param_count >= 1) row = tty->ansi_param[0];
                        if (tty->ansi_param_count >= 2) col = tty->ansi_param[1];
                        if (row < 1) row = 1;
                        if (col < 1) col = 1;
                        uint32_t tty_rows = devfs_tty_rows();
                        uint32_t tty_cols = devfs_tty_cols();
                        if ((uint32_t)row > tty_rows) row = (int)tty_rows;
                        if ((uint32_t)col > tty_cols) col = (int)tty_cols;
                        tty->cursor_y = row - 1;
                        tty->cursor_x = col - 1;
                        if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                    } else if (final_byte == 'J') {
                        int param = (tty->ansi_param_count > 0) ? tty->ansi_param[0] : 0;
                        if (param == 2 || param == 3) {
                            /* 2=clear entire screen; 3=clear entire screen + scrollback (same behavior).
                               Fast path: clear visible console in one call and reset tty backing store. */
                            devfs_tty_clear_backing_fast(tty, tty->current_attr);
                            tty->cursor_x = 0;
                            tty->cursor_y = 0;
                            if (tty_on_vga) {
                                console_clear_screen_attr(tty->current_attr);
                                console_set_cursor(0, 0);
                            }
                        } else if (param == 0) {
                            /* Clear from cursor to end of screen */
                            uint32_t cy = tty->cursor_y;
                            uint32_t tty_rows = devfs_tty_rows();
                            uint32_t tty_cols = devfs_tty_cols();
                            for (uint32_t ry = cy; ry < tty_rows; ry++) {
                                uint32_t x0 = (ry == cy) ? tty->cursor_x : 0;
                                uint32_t x1 = tty_cols - 1;
                                for (uint32_t rx = x0; rx <= x1; rx++) {
                                    uint16_t off = (uint16_t)((ry * tty_cols + rx) * 2);
                                    if (tty->screen) {
                                        tty->screen[off] = ' ';
                                        tty->screen[off + 1] = tty->current_attr;
                                    }
                                }
                                if (tty_on_vga) console_clear_line_segment((uint32_t)x0, x1, ry, tty->current_attr);
                            }
                            if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                        } else if (param == 1) {
                            /* Clear from start of screen to cursor */
                            uint32_t cy = tty->cursor_y;
                            uint32_t tty_cols = devfs_tty_cols();
                            for (uint32_t ry = 0; ry <= cy; ry++) {
                                uint32_t x0 = 0;
                                uint32_t x1 = (ry == cy) ? tty->cursor_x : tty_cols - 1;
                                for (uint32_t rx = x0; rx <= x1; rx++) {
                                    uint16_t off = (uint16_t)((ry * tty_cols + rx) * 2);
                                    if (tty->screen) {
                                        tty->screen[off] = ' ';
                                        tty->screen[off + 1] = tty->current_attr;
                                    }
                                }
                                if (tty_on_vga) console_clear_line_segment(x0, x1, ry, tty->current_attr);
                            }
                            if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                        }
                    } else if (final_byte == 'K') {
                        /* Erase in line: 0=from cursor to EOL, 1=BOL to cursor, 2=whole line.
                         * For active tty: clear on VGA so sh (and other apps) can redraw the line. */
                        int param = (tty->ansi_param_count > 0) ? tty->ansi_param[0] : 0;
                        if (tty_on_vga) {
                            uint32_t cy = tty->cursor_y;
                            uint32_t tty_cols = devfs_tty_cols();
                            uint32_t x0 = 0, x1 = tty_cols - 1;
                            if (param == 0) {
                                x0 = tty->cursor_x;
                            } else if (param == 1) {
                                x1 = tty->cursor_x;
                                tty->cursor_x = 0;
                            } else {
                                /* param == 2 or default: whole line */
                                tty->cursor_x = 0;
                            }
                            console_clear_line_segment(x0, x1, cy, tty->current_attr);
                            console_set_cursor(tty->cursor_x, tty->cursor_y);
                        } else {
                            uint32_t cy = tty->cursor_y;
                            uint32_t tty_cols = devfs_tty_cols();
                            uint32_t x0 = 0, x1 = (tty_cols > 0) ? tty_cols - 1 : 0;
                            if (param == 0) {
                                x0 = tty->cursor_x;
                            } else if (param == 1) {
                                x1 = tty->cursor_x;
                                tty->cursor_x = 0;
                            } else {
                                tty->cursor_x = 0;
                            }
                            if (tty->screen && tty_cols > 0) {
                                for (uint32_t rx = x0; rx <= x1 && rx < tty_cols; rx++) {
                                    uint16_t off = (uint16_t)((cy * tty_cols + rx) * 2);
                                    tty->screen[off] = ' ';
                                    tty->screen[off + 1] = tty->current_attr;
                                }
                            }
                        }
                    } else if (final_byte == 'A' || final_byte == 'B' || final_byte == 'C' || final_byte == 'D') {
                        /* Cursor movement: CUU A=up, CUD B=down, CUF C=forward/right, CUB D=back/left */
                        int n = (tty->ansi_param_count > 0 && tty->ansi_param[0] > 0) ? tty->ansi_param[0] : 1;
                        if (final_byte == 'A') {
                            if ((int)tty->cursor_y >= n) tty->cursor_y -= n; else tty->cursor_y = 0;
                        } else if (final_byte == 'B') {
                            uint32_t tty_rows = devfs_tty_rows();
                            if (tty->cursor_y + (uint32_t)n < tty_rows) tty->cursor_y += (uint32_t)n; else tty->cursor_y = tty_rows - 1;
                        } else if (final_byte == 'C') {
                            uint32_t tty_cols = devfs_tty_cols();
                            if (tty->cursor_x + (uint32_t)n < tty_cols) tty->cursor_x += (uint32_t)n; else tty->cursor_x = tty_cols - 1;
                        } else {
                            if ((int)tty->cursor_x >= n) tty->cursor_x -= n; else tty->cursor_x = 0;
                        }
                        if (tty_on_vga) console_set_cursor(tty->cursor_x, tty->cursor_y);
                    }
                    /* reset CSI parser state after handling final byte */
                    tty->ansi_escape_state = 0;
                    tty->ansi_param_count = 0;
                    tty->ansi_current_param = 0;
                }
            }
        }
    }
    /* Also append written chars to stdout/stderr ring buffers if applicable */
    if (file->path) {
        int which = -1;
        if (strcmp(file->path, "/dev/stdout") == 0) which = 0;
        else if (strcmp(file->path, "/dev/stderr") == 0) which = 1;
        if (which >= 0) {
            stdio_ring_t *rb = &stdio_bufs[which];
            unsigned long flags = 0;
            acquire_irqsave(&rb->lock, &flags);
            for (size_t ii = 0; ii < size; ii++) {
                char ch2 = ((const char*)buf)[ii];
                size_t next = (rb->tail + 1) % rb->cap;
                if (next != rb->head) {
                    rb->buf[rb->tail] = ch2;
                    rb->tail = next;
                } else {
                    /* buffer full: drop oldest */
                    rb->head = (rb->head + 1) % rb->cap;
                    rb->buf[rb->tail] = ch2;
                    rb->tail = (rb->tail + 1) % rb->cap;
                }
            }
            /* wake readers */
            for (int wi = 0; wi < rb->waiters_count; wi++) {
                int tid = rb->waiters[wi];
                if (tid >= 0) thread_unblock(tid);
            }
            rb->waiters_count = 0;
            release_irqrestore(&rb->lock, flags);
        }
    }
    return (ssize_t)size;
}

static void devfs_release(struct fs_file *file) {
    if (!file) return;
    // free driver_private if it was allocated for special device markers
    if (file->driver_private) {
        uintptr_t dp = (uintptr_t)file->driver_private;
        uintptr_t base_tty = (uintptr_t)&dev_ttys[0];
        uintptr_t end_tty = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
        uintptr_t base_blk = (uintptr_t)&dev_blocks[0];
        uintptr_t end_blk = (uintptr_t)&dev_blocks[dev_block_count];
        int is_allocated_marker = 1;
        /* if driver_private points into tty array or block array, don't free */
        if (dp >= base_tty && dp < end_tty) is_allocated_marker = 0;
        if (dp >= base_blk && dp < end_blk) is_allocated_marker = 0;
        /* if driver_private matches any registered dev_chars entry, do not free (it's owned by caller) */
        for (int ci = 0; ci < dev_char_count; ci++) {
            if (file->driver_private == dev_chars[ci].driver_private) { is_allocated_marker = 0; break; }
        }
        if (is_allocated_marker) {
            kfree(file->driver_private);
        }
    }
    if (file->path) kfree((void*)file->path);
    kfree(file);
}

int devfs_block_count(void) {
    return dev_block_count;
}

int devfs_block_get(int index, char *out_name, size_t out_cap, int *out_device_id, uint32_t *out_sectors) {
    if (index < 0 || index >= dev_block_count) return -1;
    if (!out_name || out_cap == 0) return -1;
    const char *path = dev_blocks[index].path;
    const char *last = path ? strrchr(path, '/') : NULL;
    const char *nm = last ? (last + 1) : (path ? path : "");
    strncpy(out_name, nm, out_cap - 1);
    out_name[out_cap - 1] = '\0';
    if (out_device_id) *out_device_id = dev_blocks[index].device_id;
    if (out_sectors) *out_sectors = dev_blocks[index].sectors;
    return 0;
}

int devfs_fill_stat(struct fs_file *file, struct stat *st) {
    if (!file || !st) return -1;
    memset(st, 0, sizeof(*st));

    const char *p = file->path ? file->path : "";
    /* directory /dev */
    if (strcmp(p, "/dev") == 0 || strcmp(p, "/dev/") == 0 || file->type == FS_TYPE_DIR) {
        st->st_ino = 2;
        st->st_mode = (mode_t)(S_IFDIR | 0755);
        st->st_nlink = 2;
        st->st_uid = 0;
        st->st_gid = 0;
        st->st_size = 0;
        return 0;
    }

    /* block device node? */
    int did = devfs_get_device_id(p);
    if (did >= 0) {
        st->st_ino = (ino_t)(1000u + (unsigned)did);
        st->st_mode = (mode_t)(S_IFBLK | 0600);
        st->st_nlink = 1;
        st->st_uid = 0;
        st->st_gid = 0;
        st->st_size = (off_t)file->size;
        return 0;
    }

    /* /dev/fb0: size = framebuffer bytes (Linux fbdev-like) */
    if (strcmp(p, "/dev/fb0") == 0) {
        st->st_ino = 2100;
        st->st_mode = (mode_t)(S_IFCHR | 0666);
        st->st_nlink = 1;
        st->st_uid = 0;
        st->st_gid = 0;
        st->st_size = (off_t)fbdev_byte_len();
        return 0;
    }

    /* tty and special devices behave like character devices */
    st->st_ino = 2000;
    st->st_mode = (mode_t)(S_IFCHR | 0666);
    st->st_nlink = 1;
    st->st_uid = 0;
    st->st_gid = 0;
    st->st_size = 0;
    return 0;
}

int devfs_register(void) {
    /* init ttys */
    for (int i = 0; i < DEVFS_TTY_COUNT; i++) {
        dev_ttys[i].id = i;
        dev_ttys[i].cursor_x = 0;
        dev_ttys[i].cursor_y = 0;
        dev_ttys[i].in_head = dev_ttys[i].in_tail = dev_ttys[i].in_count = 0;
        dev_ttys[i].in_lock.lock = 0;
        dev_ttys[i].waiters_count = 0;
        dev_ttys[i].fg_pgrp = -1;
        size_t scr_sz = devfs_tty_screen_bytes();
        dev_ttys[i].screen = (uint8_t*)kmalloc(scr_sz);
        if (dev_ttys[i].screen) {
            for (size_t j = 0; j + 1 < scr_sz; j += 2) { dev_ttys[i].screen[j] = ' '; dev_ttys[i].screen[j + 1] = GRAY_ON_BLACK; }
        }
        /* initialize ANSI/escape parsing state and current attribute */
        dev_ttys[i].current_attr = GRAY_ON_BLACK;
        dev_ttys[i].ansi_escape_state = 0;
        dev_ttys[i].ansi_param_count = 0;
        dev_ttys[i].ansi_current_param = 0;
        dev_ttys[i].controlling_sid = -1;
        dev_ttys[i].echo_escape_state = 0;
        dev_ttys[i].unget_char = -1;
    }
    /* init stdio ring buffers */
    for (int si = 0; si < 2; si++) {
        stdio_bufs[si].cap = 4096;
        stdio_bufs[si].buf = (char*)kmalloc(stdio_bufs[si].cap);
        stdio_bufs[si].head = stdio_bufs[si].tail = 0;
        stdio_bufs[si].lock.lock = 0;
        stdio_bufs[si].waiters_count = 0;
    }
    devfs_entropy = 0;
    devfs_random_waiters_count = 0;
    devfs_ops.name = "devfs";
    devfs_ops.create = devfs_create;
    devfs_ops.open = devfs_open;
    devfs_ops.read = devfs_read;
    devfs_ops.write = devfs_write;
    devfs_ops.unlink = devfs_unlink;
    devfs_ops.release = devfs_release;
    devfs_driver.ops = &devfs_ops;
    /* set a unique non-NULL driver_data so VFS dispatch finds this driver for our files */
    devfs_driver_data = &devfs_driver; /* unique pointer */
    devfs_driver.driver_data = &devfs_driver_data;
    int r = fs_register_driver(&devfs_driver);
    if (r == 0) devfs_ready = 1;
    return r;
}

void devfs_tty_realloc_for_console(void) {
    size_t scr_sz = devfs_tty_screen_bytes();
    uint8_t *new_screens[DEVFS_TTY_COUNT];
    int i;
    for (i = 0; i < DEVFS_TTY_COUNT; i++)
        new_screens[i] = NULL;
    for (i = 0; i < DEVFS_TTY_COUNT; i++) {
        new_screens[i] = (uint8_t*)kmalloc(scr_sz);
        if (!new_screens[i]) {
            for (int j = 0; j < i; j++) {
                kfree(new_screens[j]);
                new_screens[j] = NULL;
            }
            return;
        }
    }
    for (i = 0; i < DEVFS_TTY_COUNT; i++) {
        kfree(dev_ttys[i].screen);
        dev_ttys[i].screen = new_screens[i];
        for (size_t j = 0; j + 1 < scr_sz; j += 2) {
            dev_ttys[i].screen[j] = ' ';
            dev_ttys[i].screen[j + 1] = GRAY_ON_BLACK;
        }
        dev_ttys[i].cursor_x = 0;
        dev_ttys[i].cursor_y = 0;
    }
}

int devfs_mount(const char *path) {
    if (!path) return -1;
    return fs_mount(path, &devfs_driver);
}

void devfs_switch_tty(int index) {
    if (index < 0 || index >= DEVFS_TTY_COUNT) return;
    if (index == devfs_active) return;
    size_t scr_sz = devfs_tty_screen_bytes();

    /* When cirrusfb is active, tty backing store matches its internal textbuf.
       Never memcpy fbcon-sized buffers into legacy VGA text memory; that corrupts memory. */
    if (cirrusfb_is_ready()) {
        struct devfs_tty *cur = &dev_ttys[devfs_active];
        if (cur && cur->screen) {
            cirrusfb_snapshot_screen(cur->screen, scr_sz);
            /* keep cursor position for this tty (in character cells) */
            cirrusfb_get_cursor(&cur->cursor_x, &cur->cursor_y);
        }

        devfs_active = index;

        struct devfs_tty *n = &dev_ttys[devfs_active];
        if (n && n->screen) {
            cirrusfb_restore_screen(n->screen, cirrusfb_cols(), cirrusfb_rows());
            cirrusfb_set_cursor(n->cursor_x, n->cursor_y);
        }
        return;
    }

    /* Fallback: legacy VGA text mode only.
       Clamp copy size so we never write beyond the actual VGA text buffer. */
    const size_t vga_scr_sz = (size_t)MAX_COLS * (size_t)MAX_ROWS * 2u;
    size_t copy_sz = scr_sz < vga_scr_sz ? scr_sz : vga_scr_sz;

    /* save current VGA into current tty buffer */
    struct devfs_tty *cur = &dev_ttys[devfs_active];
    if (cur && cur->screen) {
        uint8_t *vga = (uint8_t*)VIDEO_ADDRESS;
        memcpy(cur->screen, vga, copy_sz);
        uint16_t pos = get_cursor();
        uint32_t tty_cols = MAX_COLS;
        cur->cursor_x = (pos % (tty_cols * 2)) / 2;
        cur->cursor_y = pos / (tty_cols * 2);
    }

    devfs_active = index;

    /* restore new active screen */
    struct devfs_tty *n = &dev_ttys[devfs_active];
    if (n && n->screen) {
        uint8_t *vga = (uint8_t*)VIDEO_ADDRESS;
        memcpy(vga, n->screen, copy_sz);
        console_set_cursor(n->cursor_x, n->cursor_y);
    }
    /* set current user/process to first process attached to this tty, if any */
    /* NOTE:
       Do NOT call thread_set_current_user() here.
       current_user must track the *currently running* user thread (scheduler-owned),
       not "foreground tty process". Desync causes syscalls to be dispatched using the
       wrong thread struct and leads to user-mode GPF after vfork/exec. */
}

int devfs_tty_count(void) { return DEVFS_TTY_COUNT; }

int devfs_unregister(void) {
    for (int i = 0; i < DEVFS_TTY_COUNT; i++) {
        if (dev_ttys[i].screen) kfree(dev_ttys[i].screen);
    }
    devfs_ready = 0;
    return fs_unregister_driver(&devfs_driver);
}

int devfs_is_ready(void) { return devfs_ready; }

static int devfs_tty_try_erase(struct devfs_tty *t, int tty) {
    if (!t || t->in_count <= 0) return 0;
    /* Do not erase past a newline (start of current line). */
    int last_idx = t->in_tail - 1;
    if (last_idx < 0) last_idx += (int)sizeof(t->inbuf);
    if (t->inbuf[last_idx] == '\n') return 0;
    /* Remove last buffered character. */
    t->in_tail = last_idx;
    t->in_count--;
    /* Echo erase: use TTY's cursor (kept in sync on each echo) so visual matches buffer. */
    if ((t->term_lflag & 0x00000008u) /* ECHO */ && tty == devfs_get_active()) {
        if (t->cursor_x > 0) {
            uint32_t cx = (uint32_t)t->cursor_x;
            uint32_t cy = (uint32_t)t->cursor_y;
            uint8_t attr = console_get_cell_attr(cx - 1, cy);
            console_putch_xy(cx - 1, cy, ' ', attr);
            t->cursor_x = cx - 1;
            console_set_cursor(t->cursor_x, t->cursor_y);
        }
    }
    return 1;
}

/* push input char into tty's input queue and wake waiters */
void devfs_tty_push_input(int tty, char c) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    /* Backspace (DEL 0x7F / BS 0x08): never handle in kernel; always pass to application.
       Otherwise it is handled twice (kernel try_erase + app line editor) and display/buffer get out of sync. */
    if (t->in_count < (int)sizeof(t->inbuf)) {
        t->inbuf[t->in_tail] = c;
        t->in_tail = (t->in_tail + 1) % (int)sizeof(t->inbuf);
        t->in_count++;
    }
    /* wake waiters */
    for (int i = 0; i < t->waiters_count; i++) {
        int tid = t->waiters[i];
        if (tid >= 0) thread_unblock(tid);
    }
    t->waiters_count = 0;
    release_irqrestore(&t->in_lock, flags);
}

int devfs_get_active(void) { return devfs_active; }

/* Non-blocking push from ISR: try lock; on failure drop char and wake waiters */
void devfs_tty_push_input_noblock(int tty, char c) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return;
    struct devfs_tty *t = &dev_ttys[tty];
    if (!try_acquire(&t->in_lock)) {
        /* Ctrl+C: still send SIGINT so foreground process terminates even if lock busy */
        if ((unsigned char)c == 0x03) {
            int pgrp = devfs_get_tty_fg_pgrp(tty);
            if (pgrp >= 0) {
                thread_send_sigint_to_pgrp(pgrp);
                if (smp_cpu_count() <= 1)
                    thread_schedule();
            }
            return;
        }
        for (int i = 0; i < t->waiters_count; i++) {
            int tid = t->waiters[i];
            if (tid >= 0) thread_unblock(tid);
        }
        t->waiters_count = 0;
        return;
    }
    /* Backspace (DEL 0x7F / BS 0x08): never handle in kernel; always pass to application.
       Prevents double handling (kernel try_erase + sh line editor) and keeps display in sync. */
    /* Ctrl+C (0x03): send SIGINT to foreground process group only (Linux-like). */
    if ((unsigned char)c == 0x03) {
        if (t->fg_pgrp >= 0) thread_send_sigint_to_pgrp(t->fg_pgrp);
        /* Wake readers so they can observe updated process state. */
        for (int i = 0; i < t->waiters_count; i++) {
            int tid = t->waiters[i];
            if (tid >= 0) thread_unblock(tid);
        }
        t->waiters_count = 0;
        if (tty == devfs_get_active() && (t->term_lflag & 0x00000008u)) {
            /* Echo ^C on the visible console at its current cursor. */
            devfs_console_putc_at_tty_cursor(t, (uint8_t)'^');
            devfs_console_putc_at_tty_cursor(t, (uint8_t)'C');
            devfs_console_putc_at_tty_cursor(t, (uint8_t)'\n');
        }
        release(&t->in_lock);
        if (smp_cpu_count() <= 1)
            thread_schedule();
        return;
    }
    if (t->in_count < (int)sizeof(t->inbuf)) {
        t->inbuf[t->in_tail] = c;
        t->in_tail = (t->in_tail + 1) % (int)sizeof(t->inbuf);
        t->in_count++;
    }
    /* inbuf full: drop char */
    /* wake waiters (don't unblock in ISR) */
    for (int i = 0; i < t->waiters_count; i++) {
        int tid = t->waiters[i];
        if (tid >= 0) thread_unblock(tid);
    }
    t->waiters_count = 0;
    /* Do not echo from IRQ path: echo uses console output/locks and can deadlock
       when IRQ interrupts code already holding VGA/console locks. */
    release(&t->in_lock);
}

int devfs_tty_pop_nb(int tty) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return -1;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    if (t->unget_char >= 0) {
        int c = t->unget_char;
        t->unget_char = -1;
        release_irqrestore(&t->in_lock, flags);
        return c;
    }
    if (t->in_count == 0) { release_irqrestore(&t->in_lock, flags); return -1; }
    char c = t->inbuf[t->in_head];
    t->in_head = (t->in_head + 1) % (int)sizeof(t->inbuf);
    t->in_count--;
    release_irqrestore(&t->in_lock, flags);
    return (int)(unsigned char)c;
}

int devfs_tty_unget(int tty, int c) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return -1;
    if (c < 0 || c > 255) return -1;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    if (t->unget_char >= 0) { release_irqrestore(&t->in_lock, flags); return -1; }
    t->unget_char = (unsigned char)c;
    release_irqrestore(&t->in_lock, flags);
    return 0;
}

int devfs_tty_available(int tty) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return 0;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    int v = t->in_count;
    if (t->unget_char >= 0) v++;
    release_irqrestore(&t->in_lock, flags);
    return v;
}

int devfs_tty_add_waiter(int tty, int tid) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return -1;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    for (int i = 0; i < t->waiters_count; i++) if (t->waiters[i] == tid) { release_irqrestore(&t->in_lock, flags); return 0; }
    if (t->waiters_count >= (int)(sizeof(t->waiters)/sizeof(t->waiters[0]))) { release_irqrestore(&t->in_lock, flags); return -1; }
    t->waiters[t->waiters_count++] = tid;
    release_irqrestore(&t->in_lock, flags);
    return 0;
}

void devfs_tty_remove_waiter(int tty, int tid) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    for (int i = 0; i < t->waiters_count; i++) {
        if (t->waiters[i] == tid) {
            t->waiters[i] = t->waiters[t->waiters_count - 1];
            t->waiters_count--;
            break;
        }
    }
    release_irqrestore(&t->in_lock, flags);
}

void devfs_tty_remove_waiter_from_all_ttys(int tid) {
    if (tid < 0) return;
    for (int tty = 0; tty < DEVFS_TTY_COUNT; tty++) {
        for (;;) {
            struct devfs_tty *t = &dev_ttys[tty];
            unsigned long flags = 0;
            int found = 0;
            acquire_irqsave(&t->in_lock, &flags);
            for (int i = 0; i < t->waiters_count; i++) {
                if (t->waiters[i] == tid) {
                    t->waiters[i] = t->waiters[t->waiters_count - 1];
                    t->waiters_count--;
                    found = 1;
                    break;
                }
            }
            release_irqrestore(&t->in_lock, flags);
            if (!found) break;
        }
    }
}

/* Helpers exposed to other kernel components */
int devfs_tty_get_fg_pgrp(struct fs_file *file) {
    if (!file || !file->driver_private) return -1;
    uintptr_t p = (uintptr_t)file->driver_private;
    uintptr_t base = (uintptr_t)&dev_ttys[0];
    uintptr_t end = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
    if (!(p >= base && p < end)) return -1;
    struct devfs_tty *t = (struct devfs_tty*)p;
    return t->fg_pgrp;
}

int devfs_tty_set_fg_pgrp(struct fs_file *file, int pgrp) {
    if (!file || !file->driver_private) return -1;
    uintptr_t p = (uintptr_t)file->driver_private;
    uintptr_t base = (uintptr_t)&dev_ttys[0];
    uintptr_t end = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
    if (!(p >= base && p < end)) return -1;
    struct devfs_tty *t = (struct devfs_tty*)p;
    t->fg_pgrp = pgrp;
    return 0;
}

/* Get/set controlling session id via file handle helpers */
int devfs_get_tty_controlling_sid(struct fs_file *file) {
    if (!file || !file->driver_private) return -1;
    uintptr_t p = (uintptr_t)file->driver_private;
    uintptr_t base = (uintptr_t)&dev_ttys[0];
    uintptr_t end = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
    if (!(p >= base && p < end)) return -1;
    struct devfs_tty *t = (struct devfs_tty*)p;
    return t->controlling_sid;
}

int devfs_set_tty_controlling_sid(struct fs_file *file, int sid) {
    if (!file || !file->driver_private) return -1;
    uintptr_t p = (uintptr_t)file->driver_private;
    uintptr_t base = (uintptr_t)&dev_ttys[0];
    uintptr_t end = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
    if (!(p >= base && p < end)) return -1;
    struct devfs_tty *t = (struct devfs_tty*)p;
    t->controlling_sid = sid;
    return 0;
}

int devfs_tty_get_index_from_file(struct fs_file *file) {
    if (!file || !file->driver_private) return -1;
    uintptr_t p = (uintptr_t)file->driver_private;
    uintptr_t base = (uintptr_t)&dev_ttys[0];
    uintptr_t end = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
    if (!(p >= base && p < end)) return -1;
    struct devfs_tty *t = (struct devfs_tty*)p;
    return t->id;
}

int devfs_tty_attach_thread(struct fs_file *file, thread_t *th) {
    if (!file || !file->driver_private || !th) return -1;
    uintptr_t p = (uintptr_t)file->driver_private;
    uintptr_t base = (uintptr_t)&dev_ttys[0];
    uintptr_t end = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
    if (!(p >= base && p < end)) return -1;
    struct devfs_tty *t = (struct devfs_tty*)p;
    th->attached_tty = t->id;
    return 0;
}

int devfs_is_tty_file(struct fs_file *file) {
    if (!file) return 0;
    /* Fast path by path name: treat console/stdin/stdout/stderr/tty as tty-like. */
    if (file->path) {
        if (strcmp(file->path, "/dev/console") == 0) return 1;
        if (strcmp(file->path, "/dev/tty") == 0) return 1;
        if (strcmp(file->path, "/dev/stdin") == 0) return 1;
        if (strcmp(file->path, "/dev/stdout") == 0) return 1;
        if (strcmp(file->path, "/dev/stderr") == 0) return 1;
    }
    /* driver_private for devfs files points into dev_ttys array */
    for (int i = 0; i < DEVFS_TTY_COUNT; i++) {
        if (file->driver_private == &dev_ttys[i]) return 1;
    }
    return 0;
}

/* Map an open file handle to a tty index if possible, or -1 otherwise.
+   Encapsulates logic used to resolve /dev/stdin/out/err, /dev/tty and ttyN. */
int devfs_get_tty_index_from_file(struct fs_file *file) {
    if (!file) return -1;
    if (file->driver_private) {
        uintptr_t dp = (uintptr_t)file->driver_private;
        uintptr_t base_tty = (uintptr_t)&dev_ttys[0];
        uintptr_t end_tty = (uintptr_t)&dev_ttys[DEVFS_TTY_COUNT];
        if (dp >= base_tty && dp < end_tty) {
            struct devfs_tty *t = (struct devfs_tty*)dp;
            return t->id;
        }
        /* marker pointer for special devices */
        int marker = *(int*)file->driver_private;
        if ((marker & 0x80000000) == 0x80000000) {
            int si = marker & 0x7FFFFFFF;
            if (si == 3 || si == 6 || si == 4 || si == 5) {
                thread_t *cur = thread_current();
                return (cur && cur->attached_tty >= 0) ? cur->attached_tty : devfs_get_active();
            }
        }
    }
    if (file->path) {
        if (strcmp(file->path, "/dev/console") == 0) return 0;
        /* /dev/N and /dev/ttyN: same mapping as devfs_path_to_tty */
        if (strncmp(file->path, "/dev/", 5) == 0 && file->path[5] >= '0' && file->path[5] <= '9' && file->path[6] == '\0') {
            int n = file->path[5] - '0';
            if (n >= 1 && n <= DEVFS_TTY_COUNT) return n - 1;
            if (n == 0) return 0;
        }
        if (strlen(file->path) >= 9 && strncmp(file->path, "/dev/tty", 8) == 0 && file->path[8] >= '0' && file->path[8] <= '9') {
            int n = file->path[8] - '0';
            if (n >= 1 && n <= DEVFS_TTY_COUNT) return n - 1;
            if (n == 0) return 0;
        }
        if (strcmp(file->path, "/dev/stdin") == 0 || strcmp(file->path, "/dev/tty") == 0) {
            thread_t *cur = thread_current();
            return (cur && cur->attached_tty >= 0) ? cur->attached_tty : devfs_get_active();
        }
    }
    return -1;
}

/* Return pointer to internal tty struct by index, or NULL if invalid. */
struct devfs_tty *devfs_get_tty_by_index(int idx) {
    if (idx < 0 || idx >= DEVFS_TTY_COUNT) return NULL;
    return &dev_ttys[idx];
}

int devfs_get_tty_fg_pgrp(int tty) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return -1;
    return dev_ttys[tty].fg_pgrp;
}

void devfs_set_tty_fg_pgrp(int tty, int pgrp) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return;
    dev_ttys[tty].fg_pgrp = pgrp;
}

/* Clear controlling_sid for any ttys owned by given session id */
void devfs_clear_controlling_by_sid(int sid) {
    for (int i = 0; i < DEVFS_TTY_COUNT; i++) {
        if (dev_ttys[i].controlling_sid == sid) dev_ttys[i].controlling_sid = -1;
    }
}

int devfs_create_block_node_lba(const char *path, int device_id, uint32_t start_lba, uint32_t sectors) {
    if (!path) return -1;
    for (int i = 0; i < dev_block_count; i++) {
        if (strcmp(dev_blocks[i].path, path) == 0) {
            dev_blocks[i].device_id = device_id;
            dev_blocks[i].start_lba = start_lba;
            dev_blocks[i].sectors = sectors;
            return 0;
        }
    }
    if (dev_block_count >= (int)(sizeof(dev_blocks)/sizeof(dev_blocks[0]))) return -1;
    strncpy(dev_blocks[dev_block_count].path, path, sizeof(dev_blocks[dev_block_count].path)-1);
    dev_blocks[dev_block_count].path[sizeof(dev_blocks[dev_block_count].path)-1] = '\0';
    dev_blocks[dev_block_count].device_id = device_id;
    dev_blocks[dev_block_count].start_lba = start_lba;
    dev_blocks[dev_block_count].sectors = sectors;
    dev_block_count++;
    return 0;
}

/* Create a whole-disk block node and register mapping */
int devfs_create_block_node(const char *path, int device_id, uint32_t sectors) {
    return devfs_create_block_node_lba(path, device_id, 0, sectors);
}

/* Create a character device node and register mapping (e.g., /dev/fb0) */
int devfs_create_char_node(const char *path, void *driver_private) {
    if (!path) return -1;
    if (dev_char_count >= (int)(sizeof(dev_chars)/sizeof(dev_chars[0]))) return -1;
    /* avoid duplicate registrations for same path: update driver_private if provided */
    for (int i = 0; i < dev_char_count; i++) {
        if (strcmp(dev_chars[i].path, path) == 0) {
            if (driver_private) dev_chars[i].driver_private = driver_private;
            return 0;
        }
    }
    strncpy(dev_chars[dev_char_count].path, path, sizeof(dev_chars[dev_char_count].path)-1);
    dev_chars[dev_char_count].path[sizeof(dev_chars[dev_char_count].path)-1] = '\0';
    dev_chars[dev_char_count].driver_private = driver_private;
    dev_char_count++;
    return 0;
}

/* helper: find block index by path */
int devfs_find_block_by_path(const char *path) {
    if (!path) return -1;
    for (int i = 0; i < dev_block_count; i++) {
        if (strcmp(path, dev_blocks[i].path) == 0) return i;
    }
    return -1;
}

/* Return the underlying disk device_id for a block node path, or -1 if not found */
int devfs_get_device_id(const char *path) {
    int idx = devfs_find_block_by_path(path);
    if (idx < 0) return -1;
    return dev_blocks[idx].device_id;
}


