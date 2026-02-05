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
    if (!path) return NULL;
    size_t path_len = strlen(path);
    struct fs_driver *best = NULL;
    size_t best_len = 0;
    for (int i = 0; i < g_mount_count; i++) {
        struct mount_entry *m = &g_mounts[i];
        if (!m->driver) continue;
        /* path must be at least as long as mount path so path[m->path_len] is valid */
        if (path_len < m->path_len) continue;
        if (strncmp(path, m->path, m->path_len) != 0) continue;
        if (path[m->path_len] != '\0' && path[m->path_len] != '/') continue;
        if (m->path_len > best_len) {
            best = m->driver;
            best_len = m->path_len;
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
    size_t path_len = strlen(path);
    size_t best_len = 0;
    const char *best = NULL;
    for (int i = 0; i < g_mount_count; i++) {
        struct mount_entry *m = &g_mounts[i];
        if (!m->driver) continue;
        if (path_len < m->path_len) continue;
        if (strncmp(path, m->path, m->path_len) != 0) continue;
        if (path[m->path_len] != '\0' && path[m->path_len] != '/') continue;
        if (m->path_len > best_len) {
            best_len = m->path_len;
            best = m->path;
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
        /* Path is under a mount; do not fall through to ramfs/etc. so /dev returns devfs, not empty ramfs dir */
        return NULL;
    }
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv || !drv->ops || !drv->ops->open) continue;
        struct fs_file *file = NULL;
        int r = drv->ops->open(path, &file);
        if (r == 0 && file) {
            /* Path might be a mount point (e.g. /dev): use mounted fs so ls /dev sees devfs list, not ramfs */
            struct fs_driver *m = fs_match_mount(path);
            if (m && m->ops && m->ops->open) {
                struct fs_file *mount_file = NULL;
                if (m->ops->open(path, &mount_file) == 0 && mount_file) {
                    if (!mount_file->fs_private) mount_file->fs_private = (void*)m;
                    fs_file_free(file);
                    return mount_file;
                }
            }
            if (!file->fs_private) file->fs_private = (void*)drv;
            return file;
        }
        if (r < 0 && r != -1) return NULL; /* real error */
    }
    return NULL;
}

/* Разрешает симлинки в пути, возвращает новый путь или NULL при ошибке.
   Вызывающий должен освободить возвращенный путь через kfree. */
static int fs_readlink_no_resolve(const char *path, char *out, size_t out_cap, size_t *out_len) {
    if (!path || !out || out_cap == 0) return -1;
    struct fs_file *lf = fs_open_no_resolve(path);
    if (!lf) return -1;
    struct stat st;
    int sr = vfs_fstat(lf, &st);
    if (sr != 0 || ((st.st_mode & S_IFLNK) != S_IFLNK)) {
        fs_file_free(lf);
        return -1;
    }
    size_t sz = (size_t)lf->size;
    if (sz == 0) { fs_file_free(lf); return -1; }
    if (sz >= out_cap) sz = out_cap - 1;
    ssize_t rr = fs_read(lf, out, sz, 0);
    fs_file_free(lf);
    if (rr <= 0) return -1;
    out[(size_t)rr] = '\0';
    if (out_len) *out_len = (size_t)rr;
    return 0;
}

/* Normalize an absolute path:
   - collapse repeated '/'
   - remove '.' components
   - resolve '..' components (without going above '/')
   Returns newly allocated string (caller must kfree), or NULL on OOM. */
static char *fs_normalize_abs_path(const char *in) {
    if (!in) return NULL;
    if (in[0] != '/') {
        /* only absolute supported here */
        char *cp = (char*)kmalloc(strlen(in) + 1);
        if (cp) strcpy(cp, in);
        return cp;
    }
    const char *parts[96];
    size_t plen[96];
    int pc = 0;
    const char *p = in;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *seg = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - seg);
        if (len == 0) continue;
        if (len == 1 && seg[0] == '.') {
            /* skip */
        } else if (len == 2 && seg[0] == '.' && seg[1] == '.') {
            if (pc > 0) pc--;
        } else {
            if (pc < (int)(sizeof(parts)/sizeof(parts[0]))) {
                parts[pc] = seg;
                plen[pc] = len;
                pc++;
            }
        }
    }
    /* compute size */
    size_t out_len = 1; /* leading '/' */
    for (int i = 0; i < pc; i++) out_len += plen[i] + 1;
    if (out_len < 2) out_len = 2;
    char *out = (char*)kmalloc(out_len);
    if (!out) return NULL;
    size_t w = 0;
    out[w++] = '/';
    for (int i = 0; i < pc; i++) {
        if (w > 1 && out[w - 1] != '/') out[w++] = '/';
        memcpy(out + w, parts[i], plen[i]);
        w += plen[i];
        out[w] = '\0';
        if (i + 1 < pc) out[w++] = '/';
    }
    if (w == 0) { out[0] = '/'; w = 1; }
    out[w] = '\0';
    return out;
}

/* Resolve symlinks anywhere in the path (like a simplified realpath).
   - follows up to 16 symlinks
   - follows symlinks in intermediate components always
   - follows final symlink too (for open/exec)
   Returns newly allocated absolute path on success; caller must kfree(). */
static char *fs_resolve_symlinks(const char *path) {
    if (!path) return NULL;
    char *cur = (char*)kmalloc(strlen(path) + 1);
    if (!cur) return NULL;
    strcpy(cur, path);

    for (int depth = 0; depth < 16; depth++) {
        /* Walk prefixes: /a, /a/b, /a/b/c ... and detect first symlink. */
        if (cur[0] != '/') return cur;
        size_t len = strlen(cur);
        size_t i = 1;
        int restarted = 0;
        while (i < len) {
            while (i < len && cur[i] == '/') i++;
            if (i >= len) break;
            size_t comp_end = i;
            while (comp_end < len && cur[comp_end] != '/') comp_end++;

            /* prefix = cur[0:comp_end] */
            size_t prefix_len = comp_end;
            char *prefix = (char*)kmalloc(prefix_len + 1);
            if (!prefix) { kfree(cur); return NULL; }
            memcpy(prefix, cur, prefix_len);
            prefix[prefix_len] = '\0';

            struct fs_file *pf = fs_open_no_resolve(prefix);
            if (!pf) {
                /* prefix does not exist -> stop resolving and return current path */
                kfree(prefix);
                return cur;
            }
            struct stat st;
            int sr = vfs_fstat(pf, &st);
            fs_file_free(pf);
            if (sr != 0) { kfree(prefix); return cur; }

            if ((st.st_mode & S_IFLNK) == S_IFLNK) {
                /* read link target */
                char target[512];
                size_t tlen = 0;
                if (fs_readlink_no_resolve(prefix, target, sizeof(target), &tlen) != 0) {
                    kfree(prefix);
                    return cur;
                }

                /* remaining path after this component (including leading slash if any) */
                const char *rest = (comp_end < len) ? (cur + comp_end) : "";

                /* build base path from target (absolute or relative-to-parent) */
                char base[768];
                if (target[0] == '/') {
                    strncpy(base, target, sizeof(base) - 1);
                    base[sizeof(base) - 1] = '\0';
                } else {
                    /* parent directory of prefix */
                    const char *slash = strrchr(prefix, '/');
                    size_t plen = slash ? (size_t)(slash - prefix) : 0;
                    if (plen == 0) plen = 1;
                    if (plen >= sizeof(base) - 2) plen = sizeof(base) - 2;
                    memcpy(base, prefix, plen);
                    base[plen] = '\0';
                    if (plen == 1) { base[0] = '/'; base[1] = '\0'; }
                    size_t bl = strlen(base);
                    if (bl > 1 && base[bl - 1] == '/') base[bl - 1] = '\0';
                    bl = strlen(base);
                    if (bl + 1 < sizeof(base)) { base[bl] = '/'; base[bl + 1] = '\0'; }
                    strncat(base, target, sizeof(base) - strlen(base) - 1);
                }

                /* join base + rest */
                size_t newcap = strlen(base) + strlen(rest) + 2;
                char *newp = (char*)kmalloc(newcap);
                if (!newp) { kfree(prefix); kfree(cur); return NULL; }
                strcpy(newp, base);
                if (rest[0]) {
                    size_t bl = strlen(newp);
                    if (bl > 0 && newp[bl - 1] == '/' && rest[0] == '/') {
                        strncat(newp, rest + 1, newcap - strlen(newp) - 1);
                    } else {
                        strncat(newp, rest, newcap - strlen(newp) - 1);
                    }
                }

                kfree(prefix);
                kfree(cur);
                /* normalize (handle ../ in symlink target) */
                {
                    char *norm = fs_normalize_abs_path(newp);
                    kfree(newp);
                    if (!norm) return NULL;
                    cur = norm;
                }
                restarted = 1;
                break; /* restart outer depth loop */
            }

            kfree(prefix);
            i = comp_end;
        }
        if (!restarted) return cur;
    }
    return cur;
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

    /* Fast path: most paths have no symlinks. Try direct open first. */
    struct fs_file *f = fs_open_no_resolve(path);
    if (f) {
        struct stat st;
        if (vfs_fstat(f, &st) == 0 && (st.st_mode & S_IFLNK) != S_IFLNK) {
            return f;  /* regular file or dir, no resolution needed */
        }
        fs_file_free(f);  /* symlink or error, need full resolve */
    }

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
        } else {
            /* Path is under a mount; do not fall through so /dev returns devfs, not empty ramfs */
            kfree(resolved_path);
            return NULL;
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
            if (r < 0 && r != -1) break;
        }
    }

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
    if (file->type == FS_TYPE_PIPE) {
        pipe_release_end(file);
    }
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

int fs_link(const char *oldpath, const char *newpath) {
    if (!oldpath || !newpath) return -1;
    struct fs_driver *mount_drv = fs_match_mount(oldpath);
    if (mount_drv && mount_drv->ops && mount_drv->ops->link) {
        int r = mount_drv->ops->link(oldpath, newpath);
        if (r == 0) return 0;
        if (r < 0) return r;
    }
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv || !drv->ops || !drv->ops->link) continue;
        int r = drv->ops->link(oldpath, newpath);
        if (r == 0) return 0;
        if (r < 0 && r != -1) return r;
    }
    return -1;
}

int fs_rename(const char *oldpath, const char *newpath) {
    if (!oldpath || !newpath) return -1;
    if (strcmp(oldpath, newpath) == 0) return 0;
    struct fs_driver *mount_drv = fs_match_mount(oldpath);
    if (mount_drv && mount_drv->ops && mount_drv->ops->rename) {
        int r = mount_drv->ops->rename(oldpath, newpath);
        if (r == 0) return 0;
        if (r < 0) return r;
    }
    for (int i = 0; i < g_drivers_count; i++) {
        struct fs_driver *drv = g_drivers[i];
        if (!drv || !drv->ops || !drv->ops->rename) continue;
        int r = drv->ops->rename(oldpath, newpath);
        if (r == 0) return 0;
        if (r < 0 && r != -1) return r;
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
        if (!fs_file_matches_driver(drv, file)) continue;
        const char *name = drv->ops ? drv->ops->name : NULL;
        if (name && strcmp(name, "sysfs") == 0) {
            if (sysfs_fill_stat(file, st) == 0) goto fix_mode;
        } else if (name && strcmp(name, "ramfs") == 0) {
            if (ramfs_fill_stat(file, st) == 0) goto fix_mode;
        } else if (name && strcmp(name, "procfs") == 0) {
            if (procfs_fill_stat(file, st) == 0) goto fix_mode;
        }
        break;
    }
    /* fallback: fill from fs_file fields */
    st->st_mode = (file->type == FS_TYPE_DIR) ? (S_IFDIR | 0755) : (S_IFREG | 0644);
    goto done;
fix_mode:
    /* Add type bits only when driver left them zero. Do not overwrite existing type
       so boot init path is not changed (avoids rc=-1 when exec fails for script/interp). */
    {
        unsigned int have_type = (st->st_mode & 0170000u);
        if (have_type == 0) {
            unsigned int want_type = (file->type == FS_TYPE_DIR) ? S_IFDIR : S_IFREG;
            st->st_mode = (st->st_mode & 07777u) | want_type;
        }
    }
    return 0;
done:
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

/* Like lstat(): do not follow the final symlink. */
int vfs_lstat(const char *path, struct stat *st) {
    if (!path || !st) return -1;
    struct fs_file *f = fs_open_no_resolve(path);
    if (!f) return -1;
    int r = vfs_fstat(f, st);
    fs_file_free(f);
    return r;
}

/* Read symlink target into buf. Returns bytes copied (no NUL) or -1 on error. */
ssize_t vfs_readlink(const char *path, char *buf, size_t bufsiz) {
    if (!path || !buf || bufsiz == 0) return -1;
    struct fs_file *f = fs_open_no_resolve(path);
    if (!f) return -1;
    struct stat st;
    if (vfs_fstat(f, &st) != 0 || ((st.st_mode & S_IFLNK) != S_IFLNK)) {
        fs_file_free(f);
        return -1;
    }
    size_t sz = (size_t)f->size;
    if (sz > bufsiz) sz = bufsiz;
    ssize_t rr = fs_read(f, buf, sz, 0);
    fs_file_free(f);
    return rr;
}
