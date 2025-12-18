#include <devfs.h>
#include <heap.h>
#include <fs.h>
#include <vga.h>
#include <keyboard.h>
#include <thread.h>
#include <string.h>
#include <stddef.h>
#include <spinlock.h>
#include <ext2.h>
#include <keyboard.h>
#include <disk.h>

#define DEVFS_TTY_COUNT 6

struct devfs_tty {
    int id;
    uint8_t *screen; /* saved VGA buffer (raw bytes 2 per cell) */
    uint32_t cursor_x;
    uint32_t cursor_y;
    /* input buffer (chars) */
    char inbuf[256];
    int in_head;
    int in_tail;
    int in_count;
    spinlock_t in_lock;
    /* waiting threads (tids) */
    int waiters[8];
    int waiters_count;
};

static struct devfs_tty dev_ttys[DEVFS_TTY_COUNT];
static int devfs_active = 0;

static struct fs_driver devfs_driver;
static struct fs_driver_ops devfs_ops;
static void *devfs_driver_data = NULL;

/* simple block device node registry for /dev/hdN */
struct devfs_block {
    char path[32];
    int device_id;
    uint32_t sectors;
};
static struct devfs_block dev_blocks[16];
static int dev_block_count = 0;
static uint32_t devfs_rand_state = 0x12345678;
/* special device names exposed under /dev */
static const char * const devfs_special_names[] = { "null", "zero", "random", "stdin", "stdout", "stderr", "urandom" };
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
    if (strncmp(path, "/dev/tty", 8) == 0) {
        int n = path[8] - '0';
        if (n >= 0 && n < DEVFS_TTY_COUNT) return n;
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

static ssize_t devfs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    if (!file || !buf) return -1;
    /* block device file handling */
    for (int bi = 0; bi < dev_block_count; bi++) {
        if (file->driver_private == &dev_blocks[bi]) {
            struct devfs_block *b = (struct devfs_block*)file->driver_private;
            /* compute sector-aligned read */
            uint64_t dev_size_bytes = (uint64_t)b->sectors * 512ULL;
            if (offset >= dev_size_bytes) return 0;
            if ((uint64_t)offset + size > dev_size_bytes) size = (size_t)(dev_size_bytes - offset);
            uint32_t start_sector = (uint32_t)(offset / 512);
            uint32_t end_sector = (uint32_t)((offset + size + 511) / 512);
            uint32_t nsectors = end_sector - start_sector;
            uint32_t alloc_bytes = 512; /* read one sector at a time */
            void *tmp = kmalloc(alloc_bytes);
            if (!tmp) return -1;
            size_t copied = 0;
            size_t off_in_first = offset % 512;
            for (uint32_t s = 0; s < nsectors; s++) {
                /* allow user to abort via Ctrl-C */
                if (keyboard_ctrlc_pending()) {
                    keyboard_consume_ctrlc();
                    kfree(tmp);
                    return -1;
                }
                if (disk_read_sectors(b->device_id, start_sector + s, tmp, 1) != 0) {
                    kfree(tmp);
                    return -1;
                }
                /* determine where to copy from this sector */
                uint8_t *src = (uint8_t*)tmp;
                uint32_t tocopy = 512;
                if (s == 0) {
                    /* first sector - may start at offset within sector */
                    if (off_in_first >= 512) tocopy = 0;
                    else {
                        if (size + off_in_first < 512) tocopy = (uint32_t)size;
                        else tocopy = 512 - (uint32_t)off_in_first;
                        memcpy((uint8_t*)buf + copied, src + off_in_first, tocopy);
                    }
                } else {
                    /* subsequent sectors */
                    uint32_t remaining = (uint32_t)size - (uint32_t)copied;
                    if (remaining == 0) { break; }
                    if (remaining < 512) tocopy = remaining;
                    memcpy((uint8_t*)buf + copied, src, tocopy);
                }
                copied += tocopy;
                if (copied >= size) break;
            }
            kfree(tmp);
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
                case 6: { /* /dev/urandom - non-blocking random */
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
    /* include ttys + console + any registered block devices */
    int total_entries = (DEVFS_TTY_COUNT + 1) + dev_block_count;
    int total_with_special = (DEVFS_TTY_COUNT + 1) + devfs_special_count + dev_block_count;
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
                /* block device entries stored in dev_blocks[] */
                int bi = i - (DEVFS_TTY_COUNT + 1 + devfs_special_count);
                const char *path = dev_blocks[bi].path;
                const char *last = strrchr(path, '/');
                if (last) nm = last + 1;
                else nm = path;
            }
            size_t namelen = strlen(nm);
            size_t rec_len = 8 + namelen;
            if (pos + rec_len <= (size_t)offset) { pos += rec_len; continue; }
            if (written >= size) break;
            uint8_t tmp[512];
            if (rec_len > sizeof(tmp)) {
                /* name too long for our entry buffer -> skip safely */
                pos += rec_len;
                continue;
            }
            struct ext2_dir_entry de;
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
            char c = t->inbuf[t->in_head];
            t->in_head = (t->in_head + 1) % (int)sizeof(t->inbuf);
            t->in_count--;
            release_irqrestore(&t->in_lock, flags);
            out[got++] = c;
            if (c == '\n') break;
            continue;
        }
        /* no data: block current thread until pushed */
        thread_t* cur = thread_current();
        if (cur) {
            /* If current is main kernel thread (tid 0), fall back to direct blocking kgetc */
            if (cur->tid == 0) {
                release_irqrestore(&t->in_lock, flags);
                char c = kgetc();
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
            /* when unblocked, loop to try again */
            continue;
        } else {
            release_irqrestore(&t->in_lock, flags);
            return (ssize_t)got;
        }
    }
    return (ssize_t)got;
}

static ssize_t devfs_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
    (void)offset;
    if (!file || !buf) return -1;
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
    /* block device write? */
    for (int bi = 0; bi < dev_block_count; bi++) {
        if (file->driver_private == &dev_blocks[bi]) {
            struct devfs_block *b = (struct devfs_block*)file->driver_private;
            /* compute sector-aligned write: read-modify-write if unaligned */
            uint64_t dev_size_bytes = (uint64_t)b->sectors * 512ULL;
            if (offset >= dev_size_bytes) return -1;
            if ((uint64_t)offset + size > dev_size_bytes) size = (size_t)(dev_size_bytes - offset);
            uint32_t start_sector = (uint32_t)(offset / 512);
            uint32_t end_sector = (uint32_t)((offset + size + 511) / 512);
            uint32_t nsectors = end_sector - start_sector;
            uint32_t alloc_bytes = nsectors * 512;
            void *tmp = kmalloc(alloc_bytes);
            if (!tmp) return -1;
            /* read existing data for RMW */
            if (disk_read_sectors(b->device_id, start_sector, tmp, nsectors) != 0) { kfree(tmp); return -1; }
            size_t off_in_first = offset % 512;
            memcpy((uint8_t*)tmp + off_in_first, buf, size);
            if (disk_write_sectors(b->device_id, start_sector, tmp, nsectors) != 0) { kfree(tmp); return -1; }
            kfree(tmp);
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
            } else if (si == 3) {
                /* /dev/stdin used for writing — map to console tty */
                t = &dev_ttys[0];
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
    int idx = t->id;
    const char *s = (const char*)buf;
    for (size_t i = 0; i < size; i++) {
        char ch = s[i];
        if (idx == devfs_active) {
            /* write to VGA directly */
            kputchar((uint8_t)ch, GRAY_ON_BLACK);
        } else {
            /* write into saved screen buffer */
            /* compute offset and write char; simple approach: append at last line */
            /* For simplicity, ignore attributes and just drop if buffer not present */
            if (t->screen) {
                /* very naive: append at bottom-right with no wrapping */
                uint32_t x = t->cursor_x;
                uint32_t y = t->cursor_y;
                uint16_t off = (uint16_t)((y * MAX_COLS + x) * 2);
                if (off + 1 < (MAX_ROWS * MAX_COLS * 2)) {
                    t->screen[off] = (uint8_t)ch;
                    t->screen[off + 1] = GRAY_ON_BLACK;
                    t->cursor_x++;
                    if (t->cursor_x >= MAX_COLS) { t->cursor_x = 0; t->cursor_y++; if (t->cursor_y >= MAX_ROWS) t->cursor_y = MAX_ROWS - 1; }
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
                    char ch = ((const char*)buf)[ii];
                    size_t next = (rb->tail + 1) % rb->cap;
                    if (next != rb->head) {
                        rb->buf[rb->tail] = ch;
                        rb->tail = next;
                    } else {
                        /* buffer full: drop oldest */
                        rb->head = (rb->head + 1) % rb->cap;
                        rb->buf[rb->tail] = ch;
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
        if (!(dp >= base_tty && dp < end_tty) && !(dp >= base_blk && dp < end_blk)) {
            kfree(file->driver_private);
        }
    }
    if (file->path) kfree((void*)file->path);
    kfree(file);
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
        dev_ttys[i].screen = (uint8_t*)kmalloc(MAX_ROWS * MAX_COLS * 2);
        if (dev_ttys[i].screen) {
            for (uint32_t j=0;j<MAX_ROWS*MAX_COLS*2;j+=2) { dev_ttys[i].screen[j] = ' '; dev_ttys[i].screen[j+1] = GRAY_ON_BLACK; }
        }
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
    devfs_ops.release = devfs_release;
    devfs_driver.ops = &devfs_ops;
    /* set a unique non-NULL driver_data so VFS dispatch finds this driver for our files */
    devfs_driver_data = &devfs_driver; /* unique pointer */
    devfs_driver.driver_data = &devfs_driver_data;
    return fs_register_driver(&devfs_driver);
}

int devfs_mount(const char *path) {
    if (!path) return -1;
    return fs_mount(path, &devfs_driver);
}

void devfs_switch_tty(int index) {
    if (index < 0 || index >= DEVFS_TTY_COUNT) return;
    if (index == devfs_active) return;
    /* save current VGA into current tty buffer */
    struct devfs_tty *cur = &dev_ttys[devfs_active];
    if (cur && cur->screen) {
        /* copy VGA memory to buffer */
        uint8_t *vga = (uint8_t*)VIDEO_ADDRESS;
        memcpy(cur->screen, vga, MAX_ROWS * MAX_COLS * 2);
        uint16_t pos = get_cursor();
        cur->cursor_x = (pos % (MAX_COLS * 2)) / 2;
        cur->cursor_y = pos / (MAX_COLS * 2);
    }
    devfs_active = index;
    /* restore new active screen */
    struct devfs_tty *n = &dev_ttys[devfs_active];
    if (n && n->screen) {
        uint8_t *vga = (uint8_t*)VIDEO_ADDRESS;
        memcpy(vga, n->screen, MAX_ROWS * MAX_COLS * 2);
        set_cursor((n->cursor_y * MAX_COLS + n->cursor_x) * 2);
    }
    /* set current user/process to first process attached to this tty, if any */
    extern void thread_set_current_user(thread_t*);
    extern thread_t* thread_find_by_tty(int);
    thread_t* t = thread_find_by_tty(index);
    if (t) thread_set_current_user(t);
}

int devfs_tty_count(void) { return DEVFS_TTY_COUNT; }

int devfs_unregister(void) {
    for (int i = 0; i < DEVFS_TTY_COUNT; i++) {
        if (dev_ttys[i].screen) kfree(dev_ttys[i].screen);
    }
    return fs_unregister_driver(&devfs_driver);
}

/* push input char into tty's input queue and wake waiters */
void devfs_tty_push_input(int tty, char c) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
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

/* Non-blocking push suitable for ISR: try to acquire lock, drop on failure */
void devfs_tty_push_input_noblock(int tty, char c) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return;
    struct devfs_tty *t = &dev_ttys[tty];
    if (!try_acquire(&t->in_lock)) return;
    if (t->in_count < (int)sizeof(t->inbuf)) {
        t->inbuf[t->in_tail] = c;
        t->in_tail = (t->in_tail + 1) % (int)sizeof(t->inbuf);
        t->in_count++;
    }
    /* wake waiters (don't unblock in ISR) */
    for (int i = 0; i < t->waiters_count; i++) {
        int tid = t->waiters[i];
        if (tid >= 0) thread_unblock(tid);
    }
    t->waiters_count = 0;
    release(&t->in_lock);
}

int devfs_tty_pop_nb(int tty) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return -1;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    if (t->in_count == 0) { release_irqrestore(&t->in_lock, flags); return -1; }
    char c = t->inbuf[t->in_head];
    t->in_head = (t->in_head + 1) % (int)sizeof(t->inbuf);
    t->in_count--;
    release_irqrestore(&t->in_lock, flags);
    return (int)(unsigned char)c;
}

int devfs_tty_available(int tty) {
    if (tty < 0 || tty >= DEVFS_TTY_COUNT) return 0;
    struct devfs_tty *t = &dev_ttys[tty];
    unsigned long flags = 0;
    acquire_irqsave(&t->in_lock, &flags);
    int v = t->in_count;
    release_irqrestore(&t->in_lock, flags);
    return v;
}

int devfs_is_tty_file(struct fs_file *file) {
    if (!file) return 0;
    /* driver_private for devfs files points into dev_ttys array */
    for (int i = 0; i < DEVFS_TTY_COUNT; i++) {
        if (file->driver_private == &dev_ttys[i]) return 1;
    }
    return 0;
}

/* Create a block device node and register mapping */
int devfs_create_block_node(const char *path, int device_id, uint32_t sectors) {
    if (!path) return -1;
    if (dev_block_count >= (int)(sizeof(dev_blocks)/sizeof(dev_blocks[0]))) return -1;
    strncpy(dev_blocks[dev_block_count].path, path, sizeof(dev_blocks[dev_block_count].path)-1);
    dev_blocks[dev_block_count].path[sizeof(dev_blocks[dev_block_count].path)-1] = '\0';
    dev_blocks[dev_block_count].device_id = device_id;
    dev_blocks[dev_block_count].sectors = sectors;
    dev_block_count++;
    /*
     * Make device visible in ramfs as a simple loop/device node so that
     * tools that list /dev (or userspace reading ramfs) can see the node
     * even if devfs is not mounted or is layered. We create a ramfs file
     * via fs_create_file(), which will try mounted drivers first and then
     * fall back to registered drivers (ramfs) — the created ramfs node
     * persists in ramfs tree.
     */
    struct fs_file *f = fs_create_file(path);
    if (f) {
        /* we don't need to keep the open handle; free it */
        fs_file_free(f);
    }
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

