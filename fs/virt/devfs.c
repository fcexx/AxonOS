#include <devfs.h>
#include <heap.h>
#include <fs.h>
#include <ramfs.h>
#include <vga.h>
#include <vbe.h>
#include <keyboard.h>
#include <thread.h>
#include <string.h>
#include <stddef.h>
#include <spinlock.h>
#include <ext2.h>
#include <keyboard.h>
#include <disk.h>

#define DEVFS_TTY_COUNT 6


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
    if (strncmp(path, "/dev/tty", 8) == 0) {
        /* /dev/ttyN (virtual consoles) */
        int n = path[8] - '0';
        if (n >= 0 && n < DEVFS_TTY_COUNT) return n;
        /* /dev/ttyS0 -> map to tty0 (serial console alias) */
        if (path[8] == 'S' && path[9] >= '0' && path[9] <= '9' && path[10] == '\0') {
            int sn = path[9] - '0';
            if (sn >= 0 && sn < DEVFS_TTY_COUNT) return sn;
            return 0;
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
            f->size = 0;
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
                if (bi < dev_block_count) {
                    const char *path = dev_blocks[bi].path;
                    const char *last = strrchr(path, '/');
                    if (last) nm = last + 1;
                    else nm = path;
                } else {
                    int ci = bi - dev_block_count;
                    if (ci >= 0 && ci < dev_char_count) {
                        const char *path = dev_chars[ci].path;
                        const char *last = strrchr(path, '/');
                        if (last) nm = last + 1;
                        else nm = path;
                    } else {
                        nm = "";
                    }
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
    int idx = t->id;
    const char *s = (const char*)buf;
    for (size_t i = 0; i < size; i++) {
        char ch = s[i];
        int did_output = 0; /* 1 when we printed to VGA/buffer, 0 when consumed by ANSI */
        if (idx == devfs_active) {
            /* write to VGA directly, but respect ANSI escape sequences on the active tty */
            struct devfs_tty *tty = t;
            /* simple streaming ANSI CSI parser for a subset of sequences */
            if (tty->ansi_escape_state == 0) {
                if ((unsigned char)ch == 0x1B) {
                    tty->ansi_escape_state = 1; /* ESC seen */
                } else if (ch == '\r') {
                    /* carriage return: erase from cursor to EOL (no cursor advance), then move to start of line */
                    vga_clear_line_segment(tty->cursor_x, MAX_COLS - 1, tty->cursor_y, tty->current_attr);
                    tty->cursor_x = 0;
                    vga_set_cursor(0, tty->cursor_y);
                } else {
                    /* normal character output using current attribute */
                    kputchar((uint8_t)ch, tty->current_attr);
                    vga_get_cursor(&tty->cursor_x, &tty->cursor_y);
                    did_output = 1;
                }
            } else if (tty->ansi_escape_state == 1) {
                if ((unsigned char)ch == '[') {
                    tty->ansi_escape_state = 2; /* CSI start */
                    tty->ansi_param_count = 0;
                    tty->ansi_current_param = 0;
                } else if ((unsigned char)ch == 'O') {
                    tty->ansi_escape_state = 3; /* SS3 (ESC O A/B/C/D) */
                } else {
                    /* unknown sequence, reset and output the ESC as literal */
                    tty->ansi_escape_state = 0;
                    kputchar(0x1B, tty->current_attr);
                    kputchar((uint8_t)ch, tty->current_attr);
                    did_output = 1;
                }
            } else if (tty->ansi_escape_state == 3) {
                /* SS3: single final byte (e.g. A=up, B=down, C=right, D=left) */
                unsigned char fc = (unsigned char)ch;
                if (fc == 'A') {
                    if (tty->cursor_y > 0) tty->cursor_y--;
                    vga_set_cursor(tty->cursor_x, tty->cursor_y);
                } else if (fc == 'B') {
                    if (tty->cursor_y + 1 < MAX_ROWS) tty->cursor_y++;
                    vga_set_cursor(tty->cursor_x, tty->cursor_y);
                } else if (fc == 'C') {
                    if (tty->cursor_x + 1 < MAX_COLS) tty->cursor_x++;
                    vga_set_cursor(tty->cursor_x, tty->cursor_y);
                } else if (fc == 'D') {
                    if (tty->cursor_x > 0) tty->cursor_x--;
                    vga_set_cursor(tty->cursor_x, tty->cursor_y);
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
                        if (row > MAX_ROWS) row = MAX_ROWS;
                        if (col > MAX_COLS) col = MAX_COLS;
                        tty->cursor_y = row - 1;
                        tty->cursor_x = col - 1;
                        vga_set_cursor(tty->cursor_x, tty->cursor_y);
                    } else if (final_byte == 'J') {
                        int param = (tty->ansi_param_count > 0) ? tty->ansi_param[0] : 0;
                        if (param == 2 || param == 3) {
                            /* 2=clear entire screen; 3=clear entire screen + scrollback (we treat same) */
                            for (uint32_t ry = 0; ry < MAX_ROWS; ry++) {
                                for (uint32_t rx = 0; rx < MAX_COLS; rx++) {
                                    uint16_t off = (uint16_t)((ry * MAX_COLS + rx) * 2);
                                    if (tty->screen) {
                                        tty->screen[off] = ' ';
                                        tty->screen[off + 1] = tty->current_attr;
                                    }
                                }
                            }
                            tty->cursor_x = 0;
                            tty->cursor_y = 0;
                            vga_clear_screen_attr(tty->current_attr);
                            vga_set_cursor(0, 0);
                        } else if (param == 0) {
                            /* Clear from cursor to end of screen */
                            uint32_t cy = tty->cursor_y;
                            for (uint32_t ry = cy; ry < MAX_ROWS; ry++) {
                                uint32_t x0 = (ry == cy) ? tty->cursor_x : 0;
                                uint32_t x1 = MAX_COLS - 1;
                                for (uint32_t rx = x0; rx <= x1; rx++) {
                                    uint16_t off = (uint16_t)((ry * MAX_COLS + rx) * 2);
                                    if (tty->screen) {
                                        tty->screen[off] = ' ';
                                        tty->screen[off + 1] = tty->current_attr;
                                    }
                                }
                                vga_clear_line_segment((uint32_t)x0, x1, ry, tty->current_attr);
                            }
                            vga_set_cursor(tty->cursor_x, tty->cursor_y);
                        } else if (param == 1) {
                            /* Clear from start of screen to cursor */
                            uint32_t cy = tty->cursor_y;
                            for (uint32_t ry = 0; ry <= cy; ry++) {
                                uint32_t x0 = 0;
                                uint32_t x1 = (ry == cy) ? tty->cursor_x : MAX_COLS - 1;
                                for (uint32_t rx = x0; rx <= x1; rx++) {
                                    uint16_t off = (uint16_t)((ry * MAX_COLS + rx) * 2);
                                    if (tty->screen) {
                                        tty->screen[off] = ' ';
                                        tty->screen[off + 1] = tty->current_attr;
                                    }
                                }
                                vga_clear_line_segment(x0, x1, ry, tty->current_attr);
                            }
                            vga_set_cursor(tty->cursor_x, tty->cursor_y);
                        }
                    } else if (final_byte == 'K') {
                        /* Erase in line: 0=from cursor to EOL, 1=BOL to cursor, 2=whole line.
                         * For active tty: clear on VGA so sh (and other apps) can redraw the line. */
                        int param = (tty->ansi_param_count > 0) ? tty->ansi_param[0] : 0;
                        if (idx == devfs_active) {
                            uint32_t cy = tty->cursor_y;
                            uint32_t x0 = 0, x1 = MAX_COLS - 1;
                            if (param == 0) {
                                x0 = tty->cursor_x;
                            } else if (param == 1) {
                                x1 = tty->cursor_x;
                                tty->cursor_x = 0;
                            } else {
                                /* param == 2 or default: whole line */
                                tty->cursor_x = 0;
                            }
                            vga_clear_line_segment(x0, x1, cy, tty->current_attr);
                            vga_set_cursor(tty->cursor_x, tty->cursor_y);
                        } else if (param == 2) {
                            for (int rx = 0; rx < MAX_COLS; rx++) {
                                uint16_t off = (uint16_t)((tty->cursor_y * MAX_COLS + rx) * 2);
                                if (tty->screen) {
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
                            if (tty->cursor_y + n < MAX_ROWS) tty->cursor_y += n; else tty->cursor_y = MAX_ROWS - 1;
                        } else if (final_byte == 'C') {
                            if (tty->cursor_x + n < MAX_COLS) tty->cursor_x += n; else tty->cursor_x = MAX_COLS - 1;
                        } else {
                            if ((int)tty->cursor_x >= n) tty->cursor_x -= n; else tty->cursor_x = 0;
                        }
                        vga_set_cursor(tty->cursor_x, tty->cursor_y);
                    }
                    /* reset CSI parser state after handling final byte */
                    tty->ansi_escape_state = 0;
                    tty->ansi_param_count = 0;
                    tty->ansi_current_param = 0;
                }
            }
        } else {
            /* non-active tty: write directly to its saved screen with its current attributes */
            struct devfs_tty *tty = t;
            /* similar handling but on the non-active tty's buffer */
            if (tty->ansi_escape_state != 0) {
                /* For simplicity, ignore escape sequences on non-active ttys to avoid desync. */
                tty->ansi_escape_state = 0;
                tty->ansi_param_count = 0;
                tty->ansi_current_param = 0;
            }
            if (tty->screen) {
                uint32_t x = tty->cursor_x;
                uint32_t y = tty->cursor_y;
                uint16_t off = (uint16_t)((y * MAX_COLS + x) * 2);
                if (off + 1 < (MAX_ROWS * MAX_COLS * 2)) {
                    tty->screen[off] = (uint8_t)ch;
                    tty->screen[off + 1] = tty->current_attr;
                    tty->cursor_x++;
                    if (tty->cursor_x >= MAX_COLS) { tty->cursor_x = 0; tty->cursor_y++; if (tty->cursor_y >= MAX_ROWS) tty->cursor_y = MAX_ROWS - 1; }
                }
            }
            did_output = 1; /* non-active: we wrote to buffer */
        }
            /* write into saved screen buffer only when we actually output a char (not consumed by ANSI) */
            if (did_output && t->screen) {
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
        dev_ttys[i].screen = (uint8_t*)kmalloc(MAX_ROWS * MAX_COLS * 2);
        if (dev_ttys[i].screen) {
            for (uint32_t j=0;j<MAX_ROWS*MAX_COLS*2;j+=2) { dev_ttys[i].screen[j] = ' '; dev_ttys[i].screen[j+1] = GRAY_ON_BLACK; }
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
    devfs_ops.release = devfs_release;
    devfs_driver.ops = &devfs_ops;
    /* set a unique non-NULL driver_data so VFS dispatch finds this driver for our files */
    devfs_driver_data = &devfs_driver; /* unique pointer */
    devfs_driver.driver_data = &devfs_driver_data;
    return fs_register_driver(&devfs_driver);
}

int devfs_mount(const char *path) {
    if (!path) return -1;
    /* Ensure mount point exists in ramfs so ls / shows "dev" */
    (void)fs_mkdir(path);
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
        vga_set_cursor(n->cursor_x, n->cursor_y);
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
    return fs_unregister_driver(&devfs_driver);
}

static int devfs_tty_try_erase(struct devfs_tty *t, int tty) {
    if (!t || t->in_count <= 0) return 0;
    /* Do not erase past a newline (start of current line). */
    int last_idx = t->in_tail - 1;
    if (last_idx < 0) last_idx += (int)sizeof(t->inbuf);
    if (t->inbuf[last_idx] == '\n') return 0;
    /* Remove last buffered character. */
    t->in_tail = last_idx;
    t->in_count--;
    /* Echo erase: move cursor left and clear cell. VGA: do it directly so cursor always moves. */
    if ((t->term_lflag & 0x00000008u) /* ECHO */ && tty == devfs_get_active()) {
        if (!vbe_is_available()) {
            uint32_t cx = 0, cy = 0;
            vga_get_cursor(&cx, &cy);
            if (cx > 0) {
                uint8_t attr = vga_get_cell_attr(cx - 1, cy);
                vga_putch_xy(cx - 1, cy, ' ', attr);
                vga_set_cursor(cx - 2, cy);
                t->cursor_x = cx - 2;
                t->cursor_y = cy;
            }
        } else {
            kputchar('\b', t->current_attr);
            vga_get_cursor(&t->cursor_x, &t->cursor_y);
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
    /* Canonical mode: handle backspace in TTY (for busybox sh) */
    if ((t->term_lflag & 0x00000002u) /* ICANON */ && (c == '\b' || (unsigned char)c == 0x7F)) {
        (void)devfs_tty_try_erase(t, tty);
        for (int i = 0; i < t->waiters_count; i++) {
            int tid = t->waiters[i];
            if (tid >= 0) thread_unblock(tid);
        }
        t->waiters_count = 0;
        release_irqrestore(&t->in_lock, flags);
        return;
    }
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
        for (int i = 0; i < t->waiters_count; i++) {
            int tid = t->waiters[i];
            if (tid >= 0) thread_unblock(tid);
        }
        t->waiters_count = 0;
        return;
    }
    /* Canonical mode: handle backspace in TTY (for busybox sh etc. that read via read()) */
    if ((t->term_lflag & 0x00000002u) /* ICANON */ && (c == '\b' || (unsigned char)c == 0x7F)) {
        (void)devfs_tty_try_erase(t, tty);
        for (int i = 0; i < t->waiters_count; i++) {
            int tid = t->waiters[i];
            if (tid >= 0) thread_unblock(tid);
        }
        t->waiters_count = 0;
        release(&t->in_lock);
        return;
    }
    /* Ctrl+C (0x03): send SIGINT to foreground process group to terminate blocking program */
    if ((unsigned char)c == 0x03 && t->fg_pgrp >= 0) {
        thread_send_sigint_to_pgrp(t->fg_pgrp);
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
    /* echo to active tty display if enabled and this is active tty */
    if ((t->term_lflag & 0x00000008u) /* ECHO */ && tty == devfs_get_active()) {
        uint8_t u = (uint8_t)c;
        int skip_echo = 0;
        if (t->echo_escape_state == 1) {
            if (c == '[' || c == 'O') { t->echo_escape_state = 2; skip_echo = 1; }
            else { t->echo_escape_state = 0; /* fall through to normal echo */ }
        }
        if (t->echo_escape_state == 2) {
            /* Only suppress echo for cursor keys: ESC [ A/B/C/D or ESC O A/B/C/D. Any other byte
             * (digits, ;, ?, ~, other letters) → reset and echo, so standalone ESC never eats input. */
            if (u == 'A' || u == 'B' || u == 'C' || u == 'D') {
                t->echo_escape_state = 0;
                skip_echo = 1;
                if (tty == devfs_get_active()) {
                    uint32_t cx = 0, cy = 0;
                    vga_get_cursor(&cx, &cy);
                    if (u == 'A' && cy > 0) cy--;
                    else if (u == 'B' && cy + 1 < (uint32_t)MAX_ROWS) cy++;
                    else if (u == 'C' && cx + 1 < (uint32_t)MAX_COLS) cx++;
                    else if (u == 'D' && cx > 0) cx--;
                    t->cursor_x = cx;
                    t->cursor_y = cy;
                    vga_set_cursor(cx, cy);
                }
            } else {
                t->echo_escape_state = 0;
                /* fall through to echo this byte */
            }
        } else if (u == 0x1Bu) {
            t->echo_escape_state = 1;
            skip_echo = 1;
        }
        if (!skip_echo) {
            if (u >= 32 && u < 127) {
                kputchar(u, t->current_attr);
            } else if (c == '\n' || c == '\r') {
                kputchar(u, t->current_attr);
            }
            vga_get_cursor(&t->cursor_x, &t->cursor_y);
        }
    }
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
        if (strncmp(file->path, "/dev/tty", 8) == 0) {
            int n = file->path[8] - '0';
            if (n >= 0 && n < DEVFS_TTY_COUNT) return n;
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
    /* create visible node in ramfs so tools listing /dev see it */
    struct fs_file *f = fs_create_file(path);
    if (f) fs_file_free(f);
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


