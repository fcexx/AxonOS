#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../inc/fs.h"
#include "../inc/sysfs.h"
#include "../inc/heap.h"
#include "../inc/ext2.h"

struct sysfs_node {
    char *name;
    int is_dir;
    struct sysfs_node *parent;
    struct sysfs_node *children;
    struct sysfs_node *next;
    struct sysfs_attr *attr;
};

struct sysfs_handle {
    struct sysfs_node *node;
};

static struct fs_driver sysfs_driver;
static struct fs_driver_ops sysfs_ops;
static struct sysfs_node *sysfs_root = NULL;

static struct sysfs_node *sysfs_alloc_node(const char *name, size_t len, int is_dir) {
    struct sysfs_node *n = (struct sysfs_node*)kmalloc(sizeof(struct sysfs_node));
    if (!n) return NULL;
    memset(n, 0, sizeof(*n));
    n->name = (char*)kmalloc(len + 1);
    if (!n->name) { kfree(n); return NULL; }
    memcpy(n->name, name, len);
    n->name[len] = '\0';
    n->is_dir = is_dir;
    return n;
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
    return sysfs_ensure_dir(sysfs_root, path + 5, 1) ? 0 : -1;
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
    struct sysfs_node *node = sysfs_find_child_n(parent, name, name_len);
    if (!node) {
        node = sysfs_alloc_node(name, name_len, 0);
        if (!node) return -1;
        sysfs_insert_child(parent, node);
    } else if (node->is_dir) {
        return -1;
    }
    if (!node->attr) {
        node->attr = (struct sysfs_attr*)kmalloc(sizeof(struct sysfs_attr));
        if (!node->attr) return -1;
    }
    memcpy(node->attr, attr, sizeof(struct sysfs_attr));
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
    struct sysfs_node *node = sysfs_lookup(path);
    if (!node) return -1;
    struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
    if (!f) return -1;
    memset(f, 0, sizeof(*f));
    size_t plen = strlen(path) + 1;
    char *pp = (char*)kmalloc(plen);
    if (!pp) { kfree(f); return -1; }
    memcpy(pp, path, plen);
    f->path = pp;
    f->fs_private = sysfs_driver.driver_data;
    f->type = node->is_dir ? FS_TYPE_DIR : FS_TYPE_REG;
    struct sysfs_handle *h = (struct sysfs_handle*)kmalloc(sizeof(struct sysfs_handle));
    if (!h) { kfree((void*)f->path); kfree(f); return -1; }
    h->node = node;
    f->driver_private = h;
    *out_file = f;
    return 0;
}

static ssize_t sysfs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    if (!file || !file->driver_private || !buf) return -1;
    struct sysfs_handle *h = (struct sysfs_handle*)file->driver_private;
    struct sysfs_node *node = h->node;
    if (!node) return -1;
    if (node->is_dir) {
        size_t pos = 0;
        uint32_t inode = 1;
        uint8_t *out = (uint8_t*)buf;
        struct sysfs_node *child = node->children;
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
        return (ssize_t)pos;
    } else {
        if (!node->attr || !node->attr->show) return 0;
        (void)offset; /* sysfs values are regenerated each read */
        return node->attr->show((char*)buf, size, node->attr->priv);
    }
}

static ssize_t sysfs_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
    if (!file || !file->driver_private || !buf) return -1;
    struct sysfs_handle *h = (struct sysfs_handle*)file->driver_private;
    struct sysfs_node *node = h->node;
    if (!node || node->is_dir) return -1;
    if (!node->attr || !node->attr->store) return -1;
    (void)offset;
    return node->attr->store((const char*)buf, size, node->attr->priv);
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
    sysfs_ops.release = sysfs_release;
    sysfs_driver.ops = &sysfs_ops;
    sysfs_driver.driver_data = (void*)sysfs_root;
    return fs_register_driver(&sysfs_driver);
}

int sysfs_unregister(void) {
    return fs_unregister_driver(&sysfs_driver);
}

int sysfs_mount(const char *path) {
    if (!sysfs_root) return -1;
    return fs_mount(path, &sysfs_driver);
}


