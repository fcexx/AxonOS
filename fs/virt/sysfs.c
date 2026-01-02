#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fs.h>
#include <sysfs.h>
#include <heap.h>
#include <ext2.h>
#include <stat.h>
#include <spinlock.h>
#include <rtc.h>
#include <thread.h>
#include <stdint.h>

struct sysfs_node {
    char *name;
    int is_dir;
    struct sysfs_node *parent;
    struct sysfs_node *children;
    struct sysfs_node *next;
    struct sysfs_attr *attr;
    /* POSIX-like metadata */
    unsigned long ino;
    mode_t mode;
    unsigned int uid;
    unsigned int gid;
    unsigned int nlink;
    size_t size;
    time_t atime;
    time_t mtime;
    time_t ctime;
};

struct sysfs_handle {
    struct sysfs_node *node;
    size_t pos;
};

static struct fs_driver sysfs_driver;
static struct fs_driver_ops sysfs_ops;
static struct sysfs_node *sysfs_root = NULL;
static unsigned long sysfs_next_ino = 1;
static spinlock_t sysfs_lock = { 0 };

/* Mode bits if not provided by platform headers */
#ifndef S_IFDIR
#define S_IFDIR 0040000
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif

static struct sysfs_node *sysfs_alloc_node(const char *name, size_t len, int is_dir) {
    struct sysfs_node *n = (struct sysfs_node*)kmalloc(sizeof(struct sysfs_node));
    if (!n) return NULL;
    memset(n, 0, sizeof(*n));
    n->name = (char*)kmalloc(len + 1);
    if (!n->name) { kfree(n); return NULL; }
    memcpy(n->name, name, len);
    n->name[len] = '\0';
    n->is_dir = is_dir;
    /* initialize POSIX-like metadata */
    n->ino = sysfs_next_ino++;
    n->mode = (is_dir ? (S_IFDIR | 0555) : (S_IFREG | 0444));
    n->uid = 0;
    n->gid = 0;
    n->nlink = is_dir ? 2u : 1u;
    n->size = 0;
    n->atime = n->mtime = n->ctime = 0;
    return n;
}

static void sysfs_free_node(struct sysfs_node *n) {
    if (!n) return;
    struct sysfs_node *c = n->children;
    while (c) {
        struct sysfs_node *next = c->next;
        sysfs_free_node(c);
        c = next;
    }
    if (n->attr) kfree(n->attr);
    if (n->name) kfree(n->name);
    kfree(n);
}

static void sysfs_update_node_size(struct sysfs_node *n) {
    if (!n || n->is_dir) return;
    if (!n->attr || !n->attr->show) { n->size = 0; return; }
    size_t cap = 4096;
    char *tmp = (char*)kmalloc(cap);
    if (!tmp) { n->size = 0; return; }
    ssize_t r = n->attr->show(tmp, cap, n->attr->priv);
    if (r < 0) n->size = 0;
    else {
        /* if value larger than cap, try to estimate by doubling up to a limit */
        if ((size_t)r < cap) n->size = (size_t)r;
        else {
            /* attempt larger buffer once */
            size_t cap2 = cap * 4;
            char *tmp2 = (char*)kmalloc(cap2);
            if (tmp2) {
                ssize_t r2 = n->attr->show(tmp2, cap2, n->attr->priv);
                if (r2 > 0) n->size = (size_t)r2;
                kfree(tmp2);
            } else {
                n->size = (size_t)r;
            }
        }
    }
    kfree(tmp);
}

static struct sysfs_node *sysfs_find_child_n(struct sysfs_node *parent, const char *name, size_t len) {
    if (!parent) return NULL;
    struct sysfs_node *c = parent->children;
    while (c) {
        if (strlen(c->name) == len && strncmp(c->name, name, len) == 0) return c;
        c = c->next;
    }
    return NULL;
}

static void sysfs_insert_child(struct sysfs_node *parent, struct sysfs_node *child) {
    if (!parent || !child) return;
    child->parent = parent;
    child->next = parent->children;
    parent->children = child;
    /* update link count for directories (parent gains a child directory entry) */
    if (child->is_dir) parent->nlink++;
}

static struct sysfs_node *sysfs_lookup(const char *path) {
    if (!sysfs_root || !path) return NULL;
    if (strcmp(path, "/sys") == 0) return sysfs_root;
    if (strncmp(path, "/sys/", 5) != 0) return NULL;
    const char *p = path + 5;
    struct sysfs_node *cur = sysfs_root;
    while (*p) {
        while (*p == '/') p++;
        if (*p == '\0') break;
        const char *end = p;
        while (*end && *end != '/') end++;
        size_t len = (size_t)(end - p);
        struct sysfs_node *child = sysfs_find_child_n(cur, p, len);
        if (!child) return NULL;
        cur = child;
        p = end;
    }
    return cur;
}

static struct sysfs_node *sysfs_ensure_dir(struct sysfs_node *start, const char *segments, int create_missing) {
    struct sysfs_node *cur = start;
    const char *p = segments;
    while (*p) {
        while (*p == '/') p++;
        if (*p == '\0') break;
        const char *end = p;
        while (*end && *end != '/') end++;
        size_t len = (size_t)(end - p);
        struct sysfs_node *child = sysfs_find_child_n(cur, p, len);
        if (!child) {
            if (!create_missing) return NULL;
            child = sysfs_alloc_node(p, len, 1);
            if (!child) return NULL;
            sysfs_insert_child(cur, child);
        }
        cur = child;
        p = end;
    }
    return cur;
}

int sysfs_mkdir(const char *path) {
    if (!sysfs_root || !path) return -1;
    if (strcmp(path, "/sys") == 0) return 0;
    if (strncmp(path, "/sys/", 5) != 0) return -1;
    acquire(&sysfs_lock);
    int r = sysfs_ensure_dir(sysfs_root, path + 5, 1) ? 0 : -1;
    release(&sysfs_lock);
    return r;
}

int sysfs_create_file(const char *path, const struct sysfs_attr *attr) {
    if (!sysfs_root || !path || !attr) return -1;
    if (strncmp(path, "/sys/", 5) != 0) return -1;
    const char *rel = path + 5;
    const char *last_slash = strrchr(rel, '/');
    struct sysfs_node *parent = sysfs_root;
    const char *name = rel;
    if (last_slash) {
        size_t parent_len = (size_t)(last_slash - rel);
        char *parent_path = (char*)kmalloc(parent_len + 1);
        if (!parent_path) return -1;
        memcpy(parent_path, rel, parent_len);
        parent_path[parent_len] = '\0';
        parent = sysfs_ensure_dir(sysfs_root, parent_path, 1);
        kfree(parent_path);
        if (!parent) return -1;
        name = last_slash + 1;
    }
    while (*name == '/') name++;
    size_t name_len = strlen(name);
    if (name_len == 0) return -1;
    acquire(&sysfs_lock);
    struct sysfs_node *node = sysfs_find_child_n(parent, name, name_len);
    if (!node) {
        node = sysfs_alloc_node(name, name_len, 0);
        if (!node) { release(&sysfs_lock); return -1; }
        sysfs_insert_child(parent, node);
    } else if (node->is_dir) {
        release(&sysfs_lock);
        return -1;
    }
    if (!node->attr) {
        node->attr = (struct sysfs_attr*)kmalloc(sizeof(struct sysfs_attr));
        if (!node->attr) { release(&sysfs_lock); return -1; }
    }
    memcpy(node->attr, attr, sizeof(struct sysfs_attr));
    /* compute size for sysfs file content if possible */
    sysfs_update_node_size(node);
    release(&sysfs_lock);
    return 0;
}

static int sysfs_create(const char *path, struct fs_file **out_file) {
    (void)path; (void)out_file;
    return -1;
}

static int sysfs_open(const char *path, struct fs_file **out_file) {
    if (!path || !out_file) return -1;
    if (!sysfs_root) return -1;
    if (!(strcmp(path, "/sys") == 0 || strncmp(path, "/sys/", 5) == 0)) return -1;
    int rc = -1;
    struct fs_file *f = NULL;
    char *pp = NULL;
    struct sysfs_handle *h = NULL;

    acquire(&sysfs_lock);
    struct sysfs_node *node = sysfs_lookup(path);
    if (!node) { release(&sysfs_lock); return -1; }

    /* Allocation failures must not leave sysfs_lock held, otherwise later VFS
       operations may spin forever under memory pressure. */
    f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
    if (!f) goto out_unlock;
    memset(f, 0, sizeof(*f));
    size_t plen = strlen(path) + 1;
    pp = (char*)kmalloc(plen);
    if (!pp) goto out_unlock;
    memcpy(pp, path, plen);
    f->path = pp;
    f->fs_private = sysfs_driver.driver_data;
    f->type = node->is_dir ? FS_TYPE_DIR : FS_TYPE_REG;
    f->size = node->size;
    h = (struct sysfs_handle*)kmalloc(sizeof(struct sysfs_handle));
    if (!h) goto out_unlock;
    h->node = node;
    f->driver_private = h;
    *out_file = f;
    f = NULL; pp = NULL; h = NULL;
    rc = 0;

out_unlock:
    release(&sysfs_lock);
    if (h) kfree(h);
    if (pp) kfree(pp);
    if (f) kfree(f);
    return rc;
}

static ssize_t sysfs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    if (!file || !file->driver_private || !buf) return -1;
    struct sysfs_handle *h = (struct sysfs_handle*)file->driver_private;
    struct sysfs_node *node = h->node;
    if (!node) return -1;
    /* directory reading: build dir entries under lock */
    if (node->is_dir) {
        /* respect offset: skip bytes until offset then write up to size */
        acquire(&sysfs_lock);

        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        struct sysfs_node *child = node->children;

        while (child) {
            size_t namelen = strlen(child->name);
            size_t rec_len = 8 + namelen;
            
            /* if entry lies entirely before offset, skip */
            if (pos + rec_len <= (size_t)offset) {
                pos += rec_len;
                child = child->next;
                continue;
            }
            /* if we've filled the output buffer, stop */
            if (written >= size) break;

            /* compute where to start copying from this entry */
            size_t entry_off = 0;
            if ((size_t)offset > pos) entry_off = (size_t)offset - pos;

            /* build full entry into a temporary buffer then copy partial */
            uint8_t tmp[512];
            if (rec_len > sizeof(tmp)) {
                /* name too long for our temp entry buffer -> skip entry safely */
                pos += rec_len;
                child = child->next;
                continue;
            }
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(child->ino & 0xFFFFFFFFu);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = child->is_dir ? EXT2_FT_DIR : EXT2_FT_REG_FILE;

            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, child->name, namelen);

            /* copy from tmp + entry_off up to remaining buffer */
            size_t avail = size - written;
            size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
            if (tocopy > avail) tocopy = avail;

            memcpy(out + written, tmp + entry_off, tocopy);

            written += tocopy;
            pos += rec_len;
            child = child->next;
        }
        /* update access time while holding lock */
        node->atime = (time_t)rtc_ticks;
        release(&sysfs_lock);
        return (ssize_t)written;
    }

    /* regular file: copy show pointer under lock and call it without holding lock */
    sysfs_show_t show_fn = NULL;
    void *show_priv = NULL;
    acquire(&sysfs_lock);
    if (node->attr && node->attr->show) {
        show_fn = node->attr->show;
        show_priv = node->attr->priv;
    }
    release(&sysfs_lock);
    if (!show_fn) return 0;
    /* sysfs must respect offset and provide EOF semantics, otherwise tools like `cat`
       will loop forever (because sysfs content is regenerated each read). */
    {
        /* Generate full value into a temporary buffer, then slice by offset. */
        size_t cap = 4096;
        if (cap < size + offset) cap = size + offset; /* best effort */
        if (cap > 65536) cap = 65536; /* hard cap */
        char *tmp = (char*)kmalloc(cap);
        if (!tmp) return -1;
        ssize_t full = show_fn(tmp, cap, show_priv);
        if (full < 0) { kfree(tmp); return -1; }
        size_t len = (size_t)full;
        if ((size_t)offset >= len) {
            kfree(tmp);
            /* update atime */
            acquire(&sysfs_lock);
            if (h->node == node && node->attr && node->attr->show == show_fn) node->atime = (time_t)rtc_ticks;
            release(&sysfs_lock);
            return 0;
        }
        size_t to_copy = len - (size_t)offset;
        if (to_copy > size) to_copy = size;
        memcpy(buf, tmp + offset, to_copy);
        kfree(tmp);
    /* update atime if node still valid and attr unchanged */
    acquire(&sysfs_lock);
    if (h->node == node && node->attr && node->attr->show == show_fn) {
        node->atime = (time_t)rtc_ticks;
    }
    release(&sysfs_lock);
        return (ssize_t)to_copy;
    }
}

static ssize_t sysfs_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
    if (!file || !file->driver_private || !buf) return -1;
    struct sysfs_handle *h = (struct sysfs_handle*)file->driver_private;
    struct sysfs_node *node = h->node;
    if (!node || node->is_dir) return -1;
    if (!node->attr || !node->attr->store) return -1;
    /* permission check: only root can write sysfs */
    thread_t* ct = thread_current();
    if (!ct || ct->euid != 0) return -1;
    /* copy store pointer under lock and call it without lock */
    sysfs_store_t store_fn = NULL;
    void *store_priv = NULL;
    acquire(&sysfs_lock);
    if (node->attr && node->attr->store) {
        store_fn = node->attr->store;
        store_priv = node->attr->priv;
    }
    release(&sysfs_lock);
    if (!store_fn) return -1;
    (void)offset;
    ssize_t r = store_fn((const char*)buf, size, store_priv);
    /* update cached size/times if node still valid and attr unchanged */
    acquire(&sysfs_lock);
    if (h->node == node && node->attr && node->attr->store == store_fn) {
        sysfs_update_node_size(node);
        node->mtime = (time_t)rtc_ticks;
        node->ctime = (time_t)rtc_ticks;
    }
    release(&sysfs_lock);
    return r;
}

static void sysfs_release(struct fs_file *file) {
    if (!file) return;
    if (file->driver_private) kfree(file->driver_private);
    if (file->path) kfree((void*)file->path);
    kfree(file);
}

int sysfs_register(void) {
    if (sysfs_root) return 0;
    sysfs_root = sysfs_alloc_node("sys", 3, 1);
    if (!sysfs_root) return -1;
    sysfs_ops.name = "sysfs";
    sysfs_ops.create = sysfs_create;
    sysfs_ops.open = sysfs_open;
    sysfs_ops.read = sysfs_read;
    sysfs_ops.write = sysfs_write;
    sysfs_ops.chmod = sysfs_chmod;
    sysfs_ops.release = sysfs_release;
    sysfs_driver.ops = &sysfs_ops;
    sysfs_driver.driver_data = (void*)sysfs_root;
    /* init lock */
    sysfs_lock.lock = 0;
    return fs_register_driver(&sysfs_driver);
}

int sysfs_unregister(void) {
    /* free allocated sysfs tree */
    if (sysfs_root) {
        sysfs_free_node(sysfs_root);
        sysfs_root = NULL;
    }
    return fs_unregister_driver(&sysfs_driver);
}

int sysfs_fill_stat(struct fs_file *file, struct stat *st) {
    if (!file || !st || !file->driver_private) return -1;
    struct sysfs_handle *h = (struct sysfs_handle*)file->driver_private;
    if (!h || !h->node) return -1;
    struct sysfs_node *n = h->node;
    st->st_ino = n->ino;
    st->st_mode = n->mode;
    st->st_nlink = n->nlink;
    st->st_uid = n->uid;
    st->st_gid = n->gid;
    st->st_size = (off_t)n->size;
    st->st_atime = n->atime;
    st->st_mtime = n->mtime;
    st->st_ctime = n->ctime;
    return 0;
}

int sysfs_mount(const char *path) {
    if (!sysfs_root) return -1;
    return fs_mount(path, &sysfs_driver);
}

int sysfs_remove(const char *path) {
    if (!sysfs_root || !path) return -1;
    if (strcmp(path, "/sys") == 0) return -1; /* cannot remove root */
    if (strncmp(path, "/sys/", 5) != 0) return -1;
    /* only root can remove sysfs nodes */
    thread_t* ct = thread_current();
    if (!ct || ct->euid != 0) return -1;
    const char *rel = path + 5;
    const char *last_slash = strrchr(rel, '/');
    struct sysfs_node *parent = sysfs_root;
    const char *name = rel;
    if (last_slash) {
        size_t parent_len = (size_t)(last_slash - rel);
        char *parent_path = (char*)kmalloc(parent_len + 1);
        if (!parent_path) return -1;
        memcpy(parent_path, rel, parent_len);
        parent_path[parent_len] = '\0';
        parent = sysfs_ensure_dir(sysfs_root, parent_path, 0);
        kfree(parent_path);
        if (!parent) return -1;
        name = last_slash + 1;
    }
    while (*name == '/') name++;
    size_t name_len = strlen(name);
    if (name_len == 0) return -1;

    acquire(&sysfs_lock);
    struct sysfs_node *node = sysfs_find_child_n(parent, name, name_len);
    if (!node) { release(&sysfs_lock); return -1; }
    /* if directory and not empty, reject */
    if (node->is_dir && node->children) { release(&sysfs_lock); return -1; }
    /* unlink from parent's child list */
    struct sysfs_node **pp = &parent->children;
    while (*pp) {
        if (*pp == node) {
            *pp = node->next;
            break;
        }
        pp = &(*pp)->next;
    }
    if (node->is_dir && parent) parent->nlink--;
    release(&sysfs_lock);

    /* free node and its attr/name */
    sysfs_free_node(node);
    return 0;
}

int sysfs_chmod(const char *path, mode_t mode) {
    if (!sysfs_root || !path) return -1;
    if (!(strcmp(path, "/sys") == 0 || strncmp(path, "/sys/", 5) == 0)) return -1;
    acquire(&sysfs_lock);
    struct sysfs_node *node = sysfs_lookup(path);
    if (!node) { release(&sysfs_lock); return -1; }
    /* only root or owner */
    thread_t* ct = thread_current();
    unsigned int uid = ct ? ct->euid : 0;
    if (uid != 0 && uid != node->uid) { release(&sysfs_lock); return -1; }
    node->mode = mode;
    release(&sysfs_lock);
    return 0;
}


