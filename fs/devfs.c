#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../inc/fs.h"
#include "../inc/devfs.h"
#include "../inc/heap.h"
#include "../inc/ext2.h"
#include "../inc/keyboard.h"
#include "../inc/vga.h"

struct devfs_node {
    char *name;
    int is_dir;
    int dev_type; /* DEVFS_TYPE_* for device nodes, 0 for dirs */
    const struct devfs_ops *ops;
    void *priv;
    struct devfs_node *parent;
    struct devfs_node *children;
    struct devfs_node *next;
};

struct devfs_handle {
    struct devfs_node *node;
};

static struct fs_driver devfs_driver;
static struct fs_driver_ops devfs_ops_fs;
static struct devfs_node *devfs_root = NULL;
static int devfs_ready = 0;

/* forward declaration for console helper */
static ssize_t dev_tty0_write(void *priv, const void *buf, size_t size, size_t offset);

/* ----- helpers ----- */

static struct devfs_node *devfs_alloc_node(const char *name, size_t len, int is_dir) {
    struct devfs_node *n = (struct devfs_node*)kmalloc(sizeof(struct devfs_node));
    if (!n) return NULL;
    memset(n, 0, sizeof(*n));
    n->name = (char*)kmalloc(len + 1);
    if (!n->name) { kfree(n); return NULL; }
    memcpy(n->name, name, len);
    n->name[len] = '\0';
    n->is_dir = is_dir;
    return n;
}

static void devfs_insert_child(struct devfs_node *parent, struct devfs_node *child) {
    if (!parent || !child) return;
    child->parent = parent;
    child->next = parent->children;
    parent->children = child;
}

static struct devfs_node *devfs_find_child_n(struct devfs_node *parent, const char *name, size_t len) {
    if (!parent) return NULL;
    struct devfs_node *c = parent->children;
    while (c) {
        if (strlen(c->name) == len && strncmp(c->name, name, len) == 0) return c;
        c = c->next;
    }
    return NULL;
}

static struct devfs_node *devfs_lookup(const char *path) {
    if (!devfs_root || !path) return NULL;
    if (strcmp(path, "/dev") == 0) return devfs_root;
    if (strncmp(path, "/dev/", 5) != 0) return NULL;
    const char *p = path + 5;
    struct devfs_node *cur = devfs_root;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != '/') end++;
        size_t len = (size_t)(end - p);
        struct devfs_node *child = devfs_find_child_n(cur, p, len);
        if (!child) return NULL;
        cur = child;
        p = end;
    }
    return cur;
}

static struct devfs_node *devfs_ensure_dir(struct devfs_node *start, const char *segments, int create_missing) {
    struct devfs_node *cur = start;
    const char *p = segments;
    while (*p) {
        while (*p == '/') p++;
        if (*p == '\0') break;
        const char *end = p;
        while (*end && *end != '/') end++;
        size_t len = (size_t)(end - p);
        struct devfs_node *child = devfs_find_child_n(cur, p, len);
        if (!child) {
            if (!create_missing) return NULL;
            child = devfs_alloc_node(p, len, 1);
            if (!child) return NULL;
            devfs_insert_child(cur, child);
        }
        cur = child;
        p = end;
    }
    return cur;
}

/* ----- public registration API ----- */

int devfs_register_dev(const char *path, int dev_type,
                       const struct devfs_ops *ops, void *priv) {
    if (!devfs_root || !path || !ops) return -1;
    if (strncmp(path, "/dev/", 5) != 0) return -1;
    const char *rel = path + 5;
    const char *last_slash = strrchr(rel, '/');
    struct devfs_node *parent = devfs_root;
    const char *name = rel;
    if (last_slash) {
        size_t parent_len = (size_t)(last_slash - rel);
        if (parent_len > 0) {
            char *parent_path = (char*)kmalloc(parent_len + 1);
            if (!parent_path) return -1;
            memcpy(parent_path, rel, parent_len);
            parent_path[parent_len] = '\0';
            parent = devfs_ensure_dir(devfs_root, parent_path, 1);
            kfree(parent_path);
            if (!parent) return -1;
        }
        name = last_slash + 1;
    }
    while (*name == '/') name++;
    size_t name_len = strlen(name);
    if (name_len == 0) return -1;
    struct devfs_node *node = devfs_find_child_n(parent, name, name_len);
    if (!node) {
        node = devfs_alloc_node(name, name_len, 0);
        if (!node) return -1;
        devfs_insert_child(parent, node);
    } else if (node->is_dir) {
        return -1;
    }
    node->dev_type = dev_type;
    node->ops = ops;
    node->priv = priv;
    return 0;
}

int devfs_register_alias(const char *alias_path, const char *target_path) {
    if (!devfs_root || !alias_path || !target_path) return -1;
    /* target must already exist */
    struct devfs_node *target = devfs_lookup(target_path);
    if (!target || target->is_dir) return -1;
    if (strncmp(alias_path, "/dev/", 5) != 0) return -1;
    const char *rel = alias_path + 5;
    const char *last_slash = strrchr(rel, '/');
    struct devfs_node *parent = devfs_root;
    const char *name = rel;
    if (last_slash) {
        size_t parent_len = (size_t)(last_slash - rel);
        if (parent_len > 0) {
            char *parent_path = (char*)kmalloc(parent_len + 1);
            if (!parent_path) return -1;
            memcpy(parent_path, rel, parent_len);
            parent_path[parent_len] = '\0';
            parent = devfs_ensure_dir(devfs_root, parent_path, 1);
            kfree(parent_path);
            if (!parent) return -1;
        }
        name = last_slash + 1;
    }
    while (*name == '/') name++;
    size_t name_len = strlen(name);
    if (name_len == 0) return -1;
    struct devfs_node *node = devfs_find_child_n(parent, name, name_len);
    if (!node) {
        node = devfs_alloc_node(name, name_len, 0);
        if (!node) return -1;
        devfs_insert_child(parent, node);
    } else if (node->is_dir) {
        return -1;
    }
    /* Point alias to same device implementation */
    node->dev_type = target->dev_type;
    node->ops = target->ops;
    node->priv = target->priv;
    return 0;
}

ssize_t devfs_console_write(const char *buf, size_t size) {
    if (!devfs_ready || !buf || size == 0) return 0;
    /* Write directly to primary TTY implementation. We bypass fs_open to
       avoid recursion and allocations. */
    return dev_tty0_write(NULL, buf, size, 0);
}

/* ----- fs_driver implementation ----- */

static int devfs_create(const char *path, struct fs_file **out_file) {
    (void)path; (void)out_file;
    /* Device nodes are only created via devfs_register_dev. */
    return -1;
}

static int devfs_open(const char *path, struct fs_file **out_file) {
    if (!path || !out_file) return -1;
    if (!devfs_root) return -1;
    if (!(strcmp(path, "/dev") == 0 || strncmp(path, "/dev/", 5) == 0)) return -1;
    struct devfs_node *node = devfs_lookup(path);
    if (!node) return -1;
    struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
    if (!f) return -1;
    memset(f, 0, sizeof(*f));
    size_t plen = strlen(path) + 1;
    char *pp = (char*)kmalloc(plen);
    if (!pp) { kfree(f); return -1; }
    memcpy(pp, path, plen);
    f->path = pp;
    f->fs_private = devfs_driver.driver_data;
    f->type = node->is_dir ? FS_TYPE_DIR : FS_TYPE_REG;
    struct devfs_handle *h = (struct devfs_handle*)kmalloc(sizeof(struct devfs_handle));
    if (!h) { kfree((void*)f->path); kfree(f); return -1; }
    h->node = node;
    f->driver_private = h;
    *out_file = f;
    return 0;
}

static ssize_t devfs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    if (!file || !file->driver_private || !buf) return -1;
    struct devfs_handle *h = (struct devfs_handle*)file->driver_private;
    struct devfs_node *node = h->node;
    if (!node) return -1;
    if (node->is_dir) {
        /* Produce ext2-like directory entries for children */
        size_t pos = 0;
        uint32_t inode = 1;
        uint8_t *out = (uint8_t*)buf;
        struct devfs_node *child = node->children;
        while (child) {
            size_t namelen = strlen(child->name);
            size_t rec_len = 8 + namelen;
            if (pos + rec_len > size) break;
            struct ext2_dir_entry de;
            de.inode = inode++;
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = child->is_dir ? EXT2_FT_DIR : EXT2_FT_REG_FILE;
            memcpy(out + pos, &de, 8);
            memcpy(out + pos + 8, child->name, namelen);
            pos += rec_len;
            child = child->next;
        }
        (void)offset;
        return (ssize_t)pos;
    } else {
        if (!node->ops || !node->ops->read) return 0;
        return node->ops->read(node->priv, buf, size, offset);
    }
}

static ssize_t devfs_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
    if (!file || !file->driver_private) return -1;
    struct devfs_handle *h = (struct devfs_handle*)file->driver_private;
    struct devfs_node *node = h->node;
    if (!node || node->is_dir) return -1;
    if (!node->ops || !node->ops->write) return -1;
    return node->ops->write(node->priv, buf, size, offset);
}

static void devfs_release(struct fs_file *file) {
    if (!file) return;
    if (file->driver_private) kfree(file->driver_private);
    if (file->path) kfree((void*)file->path);
    kfree(file);
}

/* ----- built-in pseudo devices ----- */

static ssize_t dev_null_read(void *priv, void *buf, size_t size, size_t offset) {
    (void)priv; (void)buf; (void)size; (void)offset;
    return 0; /* EOF */
}

static ssize_t dev_null_write(void *priv, const void *buf, size_t size, size_t offset) {
    (void)priv; (void)buf; (void)offset;
    return (ssize_t)size; /* discard */
}

static const struct devfs_ops dev_null_ops = {
    dev_null_read,
    dev_null_write,
    NULL
};

static ssize_t dev_zero_read(void *priv, void *buf, size_t size, size_t offset) {
    (void)priv; (void)offset;
    if (size && buf) memset(buf, 0, size);
    return (ssize_t)size;
}

static ssize_t dev_zero_write(void *priv, const void *buf, size_t size, size_t offset) {
    (void)priv; (void)buf; (void)offset;
    return (ssize_t)size;
}

static const struct devfs_ops dev_zero_ops = {
    dev_zero_read,
    dev_zero_write,
    NULL
};

/* Simple stub for fd0 until real block device driver appears. */
static ssize_t dev_fd0_read(void *priv, void *buf, size_t size, size_t offset) {
    (void)priv; (void)buf; (void)size; (void)offset;
    /* No real floppy yet: report EOF */
    return 0;
}

static ssize_t dev_fd0_write(void *priv, const void *buf, size_t size, size_t offset) {
    (void)priv; (void)buf; (void)offset;
    return -1; /* read-only stub */
}

static const struct devfs_ops dev_fd0_ops = {
    dev_fd0_read,
    dev_fd0_write,
    NULL
};

/* /dev/tty0: primary console (VGA + keyboard), POSIX-like TTY.
 * Читаем в каноническом режиме: построчно, с эхо, Backspace и Ctrl‑C/Ctrl‑D.
 */
static ssize_t dev_tty0_read(void *priv, void *buf, size_t size, size_t offset) {
    (void)priv; (void)offset;
    if (!buf || size == 0) return 0;
    char *out = (char*)buf;
    size_t done = 0;
    /* Канонический режим: как минимум один байт, максимум одна строка. */
    while (1) {
        char c = kgetc();
        if (c == 0) continue;

        /* Ctrl+C (INT): прерывание команды.
           Если пока ничего не прочитали — возвращаем 0 байт (EOF/interrupt). */
        if ((unsigned char)c == 3) {
            keyboard_consume_ctrlc();
            if (done == 0) return 0;
            break;
        }

        /* Ctrl+D (EOT): EOF. Если буфер пуст — немедленный EOF, иначе
           завершаем чтение и возвращаем уже набранные байты. */
        if ((unsigned char)c == 4) {
            if (done == 0) return 0;
            break;
        }

        /* Normalize CR -> LF */
        if (c == '\r') c = '\n';

        /* Backspace / DEL: локальное редактирование строки. */
        if (c == '\b' || (unsigned char)c == 127) {
            if (done > 0) {
                /* стёрли последний символ и визуально откатили курсор */
                static const char bs_seq[3] = {'\b',' ','\b'};
                (void)dev_tty0_write(NULL, bs_seq, sizeof(bs_seq), 0);
                done--;
            }
            continue;
        }

        /* Эхо символа на экран */
        (void)dev_tty0_write(NULL, &c, 1, 0);

        /* Записываем в пользовательский буфер */
        out[done++] = c;

        /* Завершаем по концу строки или при заполнении буфера. */
        if (c == '\n' || done >= size) break;
    }
    return (ssize_t)done;
}

static ssize_t dev_tty0_write(void *priv, const void *buf, size_t size, size_t offset) {
    (void)priv; (void)offset;
    if (!buf || size == 0) return 0;
    /* Используем color-aware путь: kprint_colorized понимает ANSI и Axon-теги. */
    char *tmp = (char*)kmalloc(size + 1);
    if (!tmp) return -1;
    memcpy(tmp, buf, size);
    tmp[size] = '\0';
    kprint_colorized(tmp);
    kfree(tmp);
    return (ssize_t)size;
}

static const struct devfs_ops dev_tty0_ops = {
    dev_tty0_read,
    dev_tty0_write,
    NULL
};

static void devfs_create_builtin_nodes(void) {
    (void)devfs_register_chr("/dev/null", &dev_null_ops, NULL);
    (void)devfs_register_chr("/dev/zero", &dev_zero_ops, NULL);
    (void)devfs_register_blk("/dev/fd0", &dev_fd0_ops, NULL);
    (void)devfs_register_chr("/dev/tty0", &dev_tty0_ops, NULL);
    (void)devfs_register_alias("/dev/console", "/dev/tty0");
    (void)devfs_register_alias("/dev/tty", "/dev/tty0");
}

/* ----- public registration ----- */

int devfs_register(void) {
    if (devfs_root) return 0;
    devfs_root = devfs_alloc_node("dev", 3, 1);
    if (!devfs_root) return -1;
    devfs_ops_fs.name = "devfs";
    devfs_ops_fs.create = devfs_create;
    devfs_ops_fs.open = devfs_open;
    devfs_ops_fs.read = devfs_read;
    devfs_ops_fs.write = devfs_write;
    devfs_ops_fs.release = devfs_release;
    devfs_driver.ops = &devfs_ops_fs;
    devfs_driver.driver_data = (void*)devfs_root;
    devfs_create_builtin_nodes();
    int rc = fs_register_driver(&devfs_driver);
    if (rc == 0) devfs_ready = 1;
    return rc;
}

int devfs_unregister(void) {
    return fs_unregister_driver(&devfs_driver);
}

int devfs_mount(const char *path) {
    if (!devfs_root || !path) return -1;
    return fs_mount(path, &devfs_driver);
}


