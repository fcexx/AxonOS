#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fs.h>
#include <stat.h>
#include <heap.h>
#include <vga.h>
/* driver-specific stat helpers */
#include <sysfs.h>
#include <ramfs.h>
#include <procfs.h>

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

/* Public wrapper to get mounted driver for a given path */
struct fs_driver *fs_get_mount_driver(const char *path) {
    return fs_match_mount(path);
}

/* helper: returns true if file is associated with driver 'drv'.
   file->fs_private may point to drv->driver_data or to drv itself. */
static int fs_file_matches_driver(const struct fs_driver *drv, const struct fs_file *file) {
    if (!drv || !file) return 0;
    if (file->fs_private == drv->driver_data) return 1;
    if (file->fs_private == (void*)drv) return 1;
    return 0;
}

int fs_get_mount_path(const struct fs_driver *drv, char *out, size_t outlen) {
    if (!drv || !out || outlen == 0) return -1;
    for (int i = 0; i < g_mount_count; i++) {
        if (g_mounts[i].driver == drv) {
            size_t len = g_mounts[i].path_len;
            if (len >= outlen) return -1;
            memcpy(out, g_mounts[i].path, len);
            out[len] = '\0';
            return 0;
        }
    }
    return -1;
}

/* Return the mount prefix that best matches the provided path (longest match).
   Writes prefix into out (null-terminated). Returns 0 on success, -1 if none. */
int fs_get_matching_mount_prefix(const char *path, char *out, size_t outlen) {
    if (!path || !out || outlen == 0) return -1;
    size_t best_len = 0;
    const char *best = NULL;
    for (int i = 0; i < g_mount_count; i++) {
        struct mount_entry *m = &g_mounts[i];
        if (!m->driver) continue;
        if (strncmp(path, m->path, m->path_len) == 0) {
            if (path[m->path_len] == '\0' || path[m->path_len] == '/') {
                if (m->path_len > best_len) {
                    best_len = m->path_len;
                    best = m->path;
                }
            }
        }
    }
    if (!best) return -1;
    if (best_len >= outlen) return -1;
    memcpy(out, best, best_len);
    out[best_len] = '\0';
    return 0;
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

int fs_mkdir(const char *path) {
    if (!path) return -1;
    struct fs_driver *mount_drv = fs_match_mount(path);
    if (mount_drv && mount_drv->ops && mount_drv->ops->mkdir) {
        int r = mount_drv->ops->mkdir(path);
        if (r == 0) return 0;
        if (r < 0) return -1;
    }
    /* fallback: try drivers' create if they accept directories */
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv || !drv->ops || !drv->ops->mkdir) continue;
        int r = drv->ops->mkdir(path);
        if (r == 0) return 0;
        if (r < 0) return -1;
    }
    return -1;
}

int fs_unmount(const char *path) {
    if (!path) return -1;
    for (int i = 0; i < g_mount_count; i++) {
        if (strcmp(g_mounts[i].path, path) == 0) {
            /* remove this mount by shifting remaining entries */
            for (int j = i; j + 1 < g_mount_count; j++) g_mounts[j] = g_mounts[j+1];
            /* clear last */
            g_mounts[--g_mount_count].driver = NULL;
            g_mounts[g_mount_count].path[0] = '\0';
            g_mounts[g_mount_count].path_len = 0;
            return 0;
        }
    }
    return -1;
}

/* Внутренняя функция открытия файла без разрешения симлинков.
   Используется для чтения содержимого симлинков. */
static struct fs_file *fs_open_no_resolve(const char *path) {
    if (!path) return NULL;
    struct fs_driver *mount_drv = fs_match_mount(path);
    if (mount_drv && mount_drv->ops && mount_drv->ops->open) {
        struct fs_file *file = NULL;
        int rr = mount_drv->ops->open(path, &file);
        if (rr == 0 && file) {
            if (!file->fs_private) file->fs_private = (void*)mount_drv;
            return file;
        }
    }
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv || !drv->ops || !drv->ops->open) continue;
        struct fs_file *file = NULL;
        int r = drv->ops->open(path, &file);
        if (r == 0 && file) {
            if (!file->fs_private) file->fs_private = (void*)drv;
            return file;
        }
        if (r < 0 && r != -1) return NULL; /* real error */
    }
    return NULL;
}

/* Разрешает симлинки в пути, возвращает новый путь или NULL при ошибке.
   Вызывающий должен освободить возвращенный путь через kfree. */
static char *fs_resolve_symlinks(const char *path) {
    if (!path) return NULL;
    char *curpath = (char*)kmalloc(strlen(path) + 1);
    if (!curpath) return NULL;
    strcpy(curpath, path);
    
    for (int depth = 0; depth < 16; depth++) {
        struct stat st;
        /* используем fs_open_no_resolve для проверки, чтобы избежать рекурсии */
        struct fs_file *check_file = fs_open_no_resolve(curpath);
        if (!check_file) {
            /* файл не существует, возвращаем текущий путь */
            return curpath;
        }
        int stat_result = vfs_fstat(check_file, &st);
        fs_file_free(check_file);
        if (stat_result != 0) {
            /* не удалось получить stat, возвращаем текущий путь */
            return curpath;
        }
        
        /* если это не симлинк, возвращаем текущий путь */
        if ((st.st_mode & S_IFLNK) != S_IFLNK) {
            return curpath;
        }
        
        /* читаем содержимое симлинка (без разрешения симлинков) */
        struct fs_file *lf = fs_open_no_resolve(curpath);
        if (!lf) {
            /* не удалось открыть симлинк, возвращаем текущий путь */
            return curpath;
        }
        
        size_t tsize = (size_t)lf->size;
        if (tsize == 0) {
            fs_file_free(lf);
            return curpath;
        }
        
        size_t cap = tsize + 1;
        char *tbuf = (char*)kmalloc(cap);
        if (!tbuf) {
            fs_file_free(lf);
            kfree(curpath);
            return NULL;
        }
        
        ssize_t rr = fs_read(lf, tbuf, tsize, 0);
        fs_file_free(lf);
        if (rr <= 0) {
            kfree(tbuf);
            return curpath;
        }
        tbuf[rr] = '\0';
        
        /* строим новый абсолютный путь */
        char *newpath = NULL;
        if (tbuf[0] == '/') {
            /* абсолютный путь */
            newpath = (char*)kmalloc(strlen(tbuf) + 1);
            if (newpath) {
                strcpy(newpath, tbuf);
            }
        } else {
            /* относительный путь: родительская директория curpath + '/' + tbuf */
            const char *slash = strrchr(curpath, '/');
            size_t plen = slash ? (size_t)(slash - curpath) : 0;
            if (plen == 0) plen = 1; /* корень */
            
            size_t nlen = plen + 1 + strlen(tbuf) + 1;
            newpath = (char*)kmalloc(nlen);
            if (newpath) {
                if (plen == 1) {
                    /* родитель - корень */
                    newpath[0] = '/';
                    newpath[1] = '\0';
                } else {
                    strncpy(newpath, curpath, plen);
                    newpath[plen] = '\0';
                }
                /* добавляем '/' если нужно */
                size_t curl = strlen(newpath);
                if (newpath[curl-1] != '/') {
                    strncat(newpath, "/", nlen - curl - 1);
                }
                strncat(newpath, tbuf, nlen - strlen(newpath) - 1);
            }
        }
        
        kfree(tbuf);
        kfree(curpath);
        
        if (!newpath) {
            return NULL;
        }
        
        curpath = newpath;
        /* продолжаем цикл для разрешения следующего уровня */
    }
    
    /* достигнут лимит глубины, возвращаем последний путь */
    return curpath;
}

/* Try drivers in registration order. Drivers should return -1 if they do not handle the path. */
struct fs_file *fs_create_file(const char *path) {
    if (!path) return NULL;
    struct fs_driver *mount_drv = fs_match_mount(path);
    if (mount_drv && mount_drv->ops && mount_drv->ops->create) {
        struct fs_file *file = NULL;
        if (mount_drv->ops->create(path, &file) == 0) {
            if (file) file->refcount = 1;
            return file;
        }
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
    
    /* разрешаем симлинки перед открытием */
    char *resolved_path = fs_resolve_symlinks(path);
    if (!resolved_path) return NULL;
    
    struct fs_file *result = NULL;
    struct fs_driver *mount_drv = fs_match_mount(resolved_path);
    if (mount_drv && mount_drv->ops && mount_drv->ops->open) {
        struct fs_file *file = NULL;
        int rr = mount_drv->ops->open(resolved_path, &file);
        if (rr == 0 && file) {
            if (!file->fs_private) file->fs_private = (void*)mount_drv;
            result = file;
        }
    }
    
    if (!result) {
        for (int i = 0; i < g_drivers_count; i++) {
            struct fs_driver *drv = g_drivers[i];
            if (!drv || !drv->ops || !drv->ops->open) continue;
            struct fs_file *file = NULL;
            int r = drv->ops->open(resolved_path, &file);
            if (r == 0 && file) {
                if (!file->fs_private) file->fs_private = (void*)drv;
                result = file;
                break;
            }
            if (r < 0 && r != -1) {
                /* real error, stop */
                break;
            }
        }
    }
    
    /* освобождаем разрешенный путь (всегда выделяется новый буфер) */
    kfree(resolved_path);
    
    return result;
}

ssize_t fs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    if (!file || !file->path) return -1;
    /* debug logging removed */
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv || !drv->ops) continue;
        /* debug logging removed */
        if (!fs_file_matches_driver(drv, file)) continue;
        /* debug logging removed */
        if (!drv->ops->read) return -1;
        return drv->ops->read(file, buf, size, offset);
    }
    return -1;
}

ssize_t fs_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
    if (!file || !file->path) return -1;
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv || !drv->ops || !fs_file_matches_driver(drv, file)) continue;
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
        if (fs_file_matches_driver(drv, file)) {
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
    qemu_debug_printf("fs_readdir_next: path=%s pos=%llu returned=%d\n",
                      file->path ? file->path : "(null)", (unsigned long long)file->pos, (int)r);
    return r;
}

int vfs_fstat(struct fs_file *file, struct stat *st) {
    if (!file || !st) return -1;
    memset(st, 0, sizeof(*st));
    /* try driver-specific if possible */
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv) continue;
        if (!fs_file_matches_driver(drv, file)) continue;
        const char *name = drv->ops ? drv->ops->name : NULL;
        if (name && strcmp(name, "sysfs") == 0) {
            if (sysfs_fill_stat(file, st) == 0) return 0;
        } else if (name && strcmp(name, "ramfs") == 0) {
            if (ramfs_fill_stat(file, st) == 0) return 0;
        } else if (name && strcmp(name, "procfs") == 0) {
            if (procfs_fill_stat(file, st) == 0) return 0;
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
