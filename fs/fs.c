#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../inc/fs.h"
#include "../inc/stat.h"
/* driver-specific stat helpers */
#include "../inc/sysfs.h"
#include "../inc/ramfs.h"
/* debug print */
extern void kprintf(const char *fmt, ...);

#define MAX_FS_DRIVERS 8
#define MAX_FS_MOUNTS 8

static struct fs_driver *g_drivers[MAX_FS_DRIVERS];
static int g_drivers_count = 0;
struct mount_entry {
    char path[64];
    size_t path_len;
    struct fs_driver *driver;
};

static struct mount_entry g_mounts[MAX_FS_MOUNTS];
static int g_mount_count = 0;

static struct fs_driver *fs_match_mount(const char *path) {
    struct fs_driver *best = NULL;
    size_t best_len = 0;
    for (int i = 0; i < g_mount_count; i++) {
        struct mount_entry *m = &g_mounts[i];
        if (!m->driver) continue;
        if (strncmp(path, m->path, m->path_len) == 0) {
            if (path[m->path_len] == '\0' || path[m->path_len] == '/') {
                if (m->path_len > best_len) {
                    best = m->driver;
                    best_len = m->path_len;
                }
            }
        }
    }
    return best;
}

int fs_register_driver(struct fs_driver *drv) {
    if (!drv || !drv->ops) return -1;
    if (g_drivers_count >= MAX_FS_DRIVERS) return -1;
    g_drivers[g_drivers_count++] = drv;
    return 0;
}

int fs_unregister_driver(struct fs_driver *drv) {
    for (int i = 0; i < g_drivers_count; i++) {
        if (g_drivers[i] == drv) {
            for (int j = i; j + 1 < g_drivers_count; j++) g_drivers[j] = g_drivers[j+1];
            g_drivers[--g_drivers_count] = NULL;
            return 0;
        }
    }
    return -1;
}

int fs_mount(const char *path, struct fs_driver *drv) {
    if (!path || !drv) return -1;
    if (g_mount_count >= MAX_FS_MOUNTS) return -1;
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(g_mounts[0].path)) return -1;
    strcpy(g_mounts[g_mount_count].path, path);
    g_mounts[g_mount_count].path_len = len;
    g_mounts[g_mount_count].driver = drv;
    g_mount_count++;
    return 0;
}

/* Try drivers in registration order. Drivers should return -1 if they do not handle the path. */
struct fs_file *fs_create_file(const char *path) {
    if (!path) return NULL;
    struct fs_driver *mount_drv = fs_match_mount(path);
    if (mount_drv && mount_drv->ops && mount_drv->ops->create) {
        struct fs_file *file = NULL;
        if (mount_drv->ops->create(path, &file) == 0) return file;
    }
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv || !drv->ops || !drv->ops->create) continue;
        struct fs_file *file = NULL;
        int r = drv->ops->create(path, &file);
        if (r == 0 && file) {
            /* driver should set file->fs_private to drv->driver_data if needed */
            file->refcount = 1;
            return file;
        }
        if (r < 0 && r != -1) {
            /* real error, stop */
            return NULL;
        }
        /* r == -1 -> not handled, try next */
    }
    return NULL;
}

struct fs_file *fs_open(const char *path) {
    if (!path) return NULL;
    struct fs_driver *mount_drv = fs_match_mount(path);
    if (mount_drv && mount_drv->ops && mount_drv->ops->open) {
        struct fs_file *file = NULL;
        int rr = mount_drv->ops->open(path, &file);
        if (rr == 0 && file) return file;
    }
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv || !drv->ops || !drv->ops->open) continue;
        struct fs_file *file = NULL;
        int r = drv->ops->open(path, &file);
        if (r == 0 && file) return file;
        if (r < 0 && r != -1) return NULL; /* real error */
    }
    return NULL;
}

ssize_t fs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    if (!file || !file->path) return -1;
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv || !drv->ops || drv->driver_data != file->fs_private) continue;
        if (!drv->ops->read) return -1;
        return drv->ops->read(file, buf, size, offset);
    }
    return -1;
}

ssize_t fs_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
    if (!file || !file->path) return -1;
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv || !drv->ops || drv->driver_data != file->fs_private) continue;
        if (!drv->ops->write) return -1;
        return drv->ops->write(file, buf, size, offset);
    }
    return -1;
}

void fs_file_free(struct fs_file *file) {
    if (!file) return;
    /* reference-counted: decrement and only free when zero */
    if (file->refcount > 1) { file->refcount--; return; }
    /* file->refcount <= 1 -> release resources */
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv || !drv->ops) continue;
        if (file->fs_private == drv->driver_data) {
            if (drv->ops->release) drv->ops->release(file);
            return;
        }
    }
    /* If no driver handled it, free memory */
    kfree((void*)file->path);
    kfree(file);
}

int fs_chmod(const char *path, mode_t mode) {
    if (!path) return -1;
    struct fs_driver *mount_drv = fs_match_mount(path);
    if (mount_drv && mount_drv->ops && mount_drv->ops->chmod) {
        int r = mount_drv->ops->chmod(path, mode);
        if (r == 0) return 0;
    }
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv || !drv->ops || !drv->ops->chmod) continue;
        int r = drv->ops->chmod(path, mode);
        if (r == 0) return 0;
        if (r < 0 && r != -1) return -1;
    }
    return -1;
}

ssize_t fs_readdir_next(struct fs_file *file, void *buf, size_t size) {
    if (!file) return -1;
    ssize_t r = fs_read(file, buf, size, file->pos);
    if (r > 0) file->pos += r;
    return r;
}

int vfs_fstat(struct fs_file *file, struct stat *st) {
    if (!file || !st) return -1;
    memset(st, 0, sizeof(*st));
    /* try driver-specific if possible */
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv) continue;
        if (file->fs_private != drv->driver_data) continue;
        const char *name = drv->ops ? drv->ops->name : NULL;
        if (name && strcmp(name, "sysfs") == 0) {
            if (sysfs_fill_stat(file, st) == 0) return 0;
        } else if (name && strcmp(name, "ramfs") == 0) {
            if (ramfs_fill_stat(file, st) == 0) return 0;
        }
        break;
    }
    /* fallback: fill from fs_file fields */
    st->st_mode = (file->type == FS_TYPE_DIR) ? (S_IFDIR | 0755) : (S_IFREG | 0644);
    st->st_size = (off_t)file->size;
    st->st_nlink = 1;
    return 0;
}

int vfs_stat(const char *path, struct stat *st) {
    if (!path || !st) return -1;
    struct fs_file *f = fs_open(path);
    if (!f) return -1;
    int r = vfs_fstat(f, st);
    fs_file_free(f);
    return r;
}
