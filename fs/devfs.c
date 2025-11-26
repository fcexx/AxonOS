#include "../inc/devfs.h"
#include "../inc/heap.h"
#include "../inc/fs.h"
#include "../inc/vga.h"
#include "../inc/keyboard.h"
#include "../inc/thread.h"
#include <string.h>
#include <stddef.h>
#include "../inc/spinlock.h"
#include "../inc/ext2.h"

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
    f->path = (const char*)kmalloc(strlen(path) + 1);
    strcpy((char*)f->path, path);
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
        f->path = (const char*)kmalloc(strlen(path) + 1);
        strcpy((char*)f->path, path);
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
    int tty = devfs_path_to_tty(path);
    if (tty < 0) return -1;
    struct fs_file *f = devfs_alloc_file(path, tty);
    if (!f) return -1;
    *out_file = f;
    return 0;
}

static ssize_t devfs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    (void)offset;
    if (!file || !buf) return -1;
    /* directory read */
    if (file->type == FS_TYPE_DIR && file->driver_private) {
        uint8_t *out = (uint8_t*)buf;
        size_t pos = 0;
        size_t written = 0;
        for (int i = 0; i < DEVFS_TTY_COUNT + 1; i++) {
            const char *nm;
            char tmpn[8];
            if (i == 0) nm = "console";
            else {
                tmpn[0] = 't'; tmpn[1] = 't'; tmpn[2] = 'y'; tmpn[3] = '0' + (char)(i-1); tmpn[4] = '\0';
                nm = tmpn;
            }
            size_t namelen = strlen(nm);
            size_t rec_len = 8 + namelen;
            if (pos + rec_len <= (size_t)offset) { pos += rec_len; continue; }
            if (written >= size) break;
            uint8_t tmp[256];
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(i + 1);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_REG_FILE;
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, nm, namelen);
            size_t entry_off = 0;
            if (offset > (ssize_t)pos) entry_off = (size_t)offset - pos;
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
    struct devfs_tty *t = (struct devfs_tty*)file->driver_private;
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
    }
    return (ssize_t)size;
}

static void devfs_release(struct fs_file *file) {
    if (!file) return;
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


