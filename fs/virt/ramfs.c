#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fs.h>
#include <ext2.h>
#include <ramfs.h>
#include <heap.h>
#include <stat.h>
#include <thread.h>

struct ramfs_node {
    char *name;
    int is_dir;
    char *data;
    size_t size;
    unsigned long ino;
    unsigned int mode;
    unsigned int uid;
    unsigned int gid;
    unsigned int nlink;
    time_t atime;
    time_t mtime;
    time_t ctime;
    struct ramfs_node *parent;
    struct ramfs_node *children; /* linked list of children */
    struct ramfs_node *next; /* sibling */
    struct ramfs_node *link_target; /* if set, this is a hard link to that node */
};

/* forward declarations for functions used before definitions */
static void ramfs_free_node_shallow(struct ramfs_node *n);
static struct ramfs_node *ramfs_find_child(struct ramfs_node *parent, const char *name);
static struct ramfs_node *ramfs_lookup(const char *path);

struct ramfs_file_handle {
    struct ramfs_node *node;
};

static struct fs_driver ramfs_driver;
static struct fs_driver_ops ramfs_ops;
static struct ramfs_node *ramfs_root = NULL;
static uint32_t ramfs_next_inode = 10;

static struct ramfs_node *ramfs_alloc_node(const char *name, int is_dir) {
    if (!name) name = "";
    struct ramfs_node *n = (struct ramfs_node*)kmalloc(sizeof(*n));
    if (!n) return NULL;
    memset(n, 0, sizeof(*n));
    size_t l = strlen(name) + 1;
    n->name = (char*)kmalloc(l);
    if (!n->name) { kfree(n); return NULL; }
    memcpy(n->name, name, l);
    n->is_dir = is_dir;
    n->ino = ramfs_next_inode++;
    n->mode = is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644);
    n->uid = 0;
    n->gid = 0;
    n->nlink = is_dir ? 2u : 1u;
    n->size = 0;
    n->atime = n->mtime = n->ctime = 0;
    return n;
}

/* create a symlink at path -> target */
int ramfs_symlink(const char *path, const char *target) {
    if (!path || path[0] != '/' || !target) return -1;
    /* find parent */
    size_t path_len = strlen(path);
    char *tmp = (char*)kmalloc(path_len + 1);
    if (!tmp) return -2;
    memcpy(tmp, path, path_len + 1);
    char *slash = strrchr(tmp, '/');
    char *name = NULL;
    const char *parent_path = NULL;
    if (slash == tmp) {
        parent_path = "/";
        name = slash + 1;
    } else {
        *slash = '\0';
        parent_path = tmp;
        name = slash + 1;
    }
    if (!name || !name[0]) { kfree(tmp); return -3; }
    struct ramfs_node *parent = ramfs_lookup(parent_path);
    if (!parent) { kfree(tmp); return -2; }
    if (!parent->is_dir) { kfree(tmp); return -3; }
    if (ramfs_find_child(parent, name)) { kfree(tmp); return -4; }
    struct ramfs_node *n = ramfs_alloc_node(name, 0);
    if (!n) { kfree(tmp); return -5; }
    n->parent = parent;
    n->next = parent->children;
    parent->children = n;
    /* set symlink mode and store target in data */
    n->mode = S_IFLNK | 0777;
    size_t tlen = strlen(target);
    n->data = (char*)kmalloc(tlen + 1);
    if (!n->data) {
        /* rollback */
        if (parent->children == n) parent->children = n->next;
        else {
            struct ramfs_node *p = parent->children;
            while (p && p->next != n) p = p->next;
            if (p && p->next == n) p->next = n->next;
        }
        ramfs_free_node_shallow(n);
        kfree(tmp);
        return -6;
    }
    memcpy(n->data, target, tlen+1);
    n->size = tlen;
    /* owner */
    thread_t* ct = thread_current();
    if (ct) { n->uid = ct->euid; n->gid = ct->egid; }
    kfree(tmp);
    return 0;
}

/* Create hard link: newpath will point to same inode as oldpath. */
int ramfs_link(const char *oldpath, const char *newpath) {
    if (!oldpath || oldpath[0] != '/' || !newpath || newpath[0] != '/') return -1;
    /* resolve oldpath (follow symlinks) to get target node */
    struct ramfs_node *target = ramfs_lookup(oldpath);
    if (!target) return -2;
    if (target->is_dir) return -1; /* EPERM: cannot link directory */
    if (target->link_target) target = target->link_target; /* resolve if oldpath is itself a link */

    /* get parent and basename of newpath */
    size_t new_len = strlen(newpath);
    char *tmp = (char*)kmalloc(new_len + 1);
    if (!tmp) return -5;
    memcpy(tmp, newpath, new_len + 1);
    char *slash = strrchr(tmp, '/');
    const char *parent_path = NULL;
    char *name = NULL;
    if (slash == tmp) {
        parent_path = "/";
        name = slash + 1;
    } else if (slash) {
        *slash = '\0';
        parent_path = tmp;
        name = slash + 1;
    } else {
        kfree(tmp);
        return -3;
    }
    if (!name || !name[0]) { kfree(tmp); return -3; }

    struct ramfs_node *parent = ramfs_lookup(parent_path);
    if (!parent) { kfree(tmp); return -2; }
    if (!parent->is_dir) { kfree(tmp); return -3; }
    if (ramfs_find_child(parent, name)) { kfree(tmp); return -17; } /* EEXIST=17 */

    /* allocate link node (minimal: name, parent, next, link_target) */
    struct ramfs_node *link = (struct ramfs_node*)kmalloc(sizeof(*link));
    if (!link) { kfree(tmp); return -5; }
    memset(link, 0, sizeof(*link));
    size_t nlen = strlen(name) + 1;
    link->name = (char*)kmalloc(nlen);
    if (!link->name) { kfree(link); kfree(tmp); return -5; }
    memcpy(link->name, name, nlen);
    link->link_target = target;
    link->parent = parent;
    link->next = parent->children;
    parent->children = link;
    target->nlink++;
    kfree(tmp);
    return 0;
}

static struct ramfs_node *ramfs_resolve_link(struct ramfs_node *n) {
    return (n && n->link_target) ? n->link_target : n;
}

static void ramfs_free_node_shallow(struct ramfs_node *n) {
    if (!n) return;
    if (n->name) kfree(n->name);
    if (n->data) kfree(n->data);
    kfree(n);
}

static struct ramfs_node *ramfs_find_child(struct ramfs_node *parent, const char *name) {
    if (!parent || !parent->children) return NULL;
    struct ramfs_node *c = parent->children;
    while (c) {
        if (strcmp(c->name, name) == 0) return c;
        c = c->next;
    }
    return NULL;
}

/* Build absolute path to a node into buf. Returns 0 on success.
   If node is root, returns "/". */
static int ramfs_build_path(struct ramfs_node *node, char *buf, size_t bufsz) {
    if (!buf || bufsz == 0) return -1;
    if (!node) { buf[0] = '\0'; return -1; }
    if (node == ramfs_root) {
        if (bufsz < 2) { buf[0] = '\0'; return -1; }
        buf[0] = '/'; buf[1] = '\0';
        return 0;
    }

    /* collect components from node up to (but excluding) root */
    const char *parts[64];
    int count = 0;
    struct ramfs_node *cur = node;
    while (cur && cur != ramfs_root && count < (int)(sizeof(parts)/sizeof(parts[0]))) {
        parts[count++] = cur->name ? cur->name : "";
        cur = cur->parent;
    }
    if (!cur) { buf[0] = '\0'; return -1; }

    /* write in reverse */
    size_t pos = 0;
    if (pos + 1 >= bufsz) { buf[0] = '\0'; return -1; }
    buf[pos++] = '/';
    for (int i = count - 1; i >= 0; i--) {
        const char *p = parts[i];
        size_t l = p ? strlen(p) : 0;
        if (l == 0) continue;
        if (pos + l + 1 >= bufsz) { buf[0] = '\0'; return -1; }
        memcpy(buf + pos, p, l);
        pos += l;
        if (i != 0) buf[pos++] = '/';
    }
    buf[pos] = '\0';
    /* ensure it is absolute */
    if (buf[0] != '/') return -1;
    return 0;
}

/* Lookup node by absolute path WITHOUT following symlinks.
   If a symlink appears in the middle of the path, we treat it as non-directory and fail. */
static struct ramfs_node *ramfs_lookup_nofollow(const char *path) {
    if (!path) return NULL;
    if (strcmp(path, "/") == 0) return ramfs_root;
    if (path[0] != '/') return NULL;

    size_t plen = strlen(path);
    char *tmp = (char*)kmalloc(plen + 1);
    if (!tmp) return NULL;
    memcpy(tmp, path + 1, plen); /* skip leading '/' */
    tmp[plen] = '\0';

    struct ramfs_node *cur = ramfs_root;
    char *tok = strtok(tmp, "/");
    while (tok && cur) {
        struct ramfs_node *child = ramfs_find_child(cur, tok);
        if (!child) { kfree(tmp); return NULL; }
        /* If this is a symlink and there are more components, fail (nofollow). */
        if ((child->mode & S_IFLNK) == S_IFLNK) {
            char *peek = strtok(NULL, "/");
            if (peek) { kfree(tmp); return NULL; }
            /* it was the last component */
            kfree(tmp);
            return child;
        }
        cur = child;
        tok = strtok(NULL, "/");
    }
    kfree(tmp);
    return cur;
}

static struct ramfs_node *ramfs_lookup(const char *path) {
    if (!path) return NULL;
    if (strcmp(path, "/") == 0) return ramfs_root;
    if (path[0] != '/') return NULL;
    /* We'll implement basic symlink resolution with limited depth. */
    int depth = 0;
    char *curpath = (char*)kmalloc(strlen(path) + 1);
    if (!curpath) return NULL;
    strcpy(curpath, path);
    while (depth < 16) {
        depth++;
        size_t plen = strlen(curpath);
        char *tmp = (char*)kmalloc(plen + 1);
        if (!tmp) { kfree(curpath); return NULL; }
        /* copy without leading slash */
        memcpy(tmp, curpath + 1, plen);
        tmp[plen] = '\0';
        struct ramfs_node *cur = ramfs_root;
        char *tok = strtok(tmp, "/");
        char *restptr = NULL;
        while (tok && cur) {
            struct ramfs_node *child = ramfs_find_child(cur, tok);
            if (!child) {
                kfree(tmp);
                kfree(curpath);
                return NULL;
            }
            /* if child is symlink, resolve */
            if ((child->mode & S_IFLNK) == S_IFLNK) {
                /* compute remaining path after this token */
                char *rest = NULL;
                if ((restptr = strtok(NULL, "")) && restptr[0] != '\0') rest = restptr;
                size_t newlen = strlen(child->data) + 1 + (rest ? strlen(rest) : 0) + 2;
                char *newpath = (char*)kmalloc(newlen);
                if (!newpath) { kfree(tmp); kfree(curpath); return NULL; }
                if (child->data[0] == '/') {
                    /* absolute target */
                    strcpy(newpath, child->data);
                } else {
                    /* relative to parent directory of symlink */
                    /* build parent path */
                    char parentbuf[512];
                    parentbuf[0] = '\0';
                    /* compute absolute directory path of the symlink's parent */
                    if (ramfs_build_path(child->parent ? child->parent : ramfs_root, parentbuf, sizeof(parentbuf)) != 0) {
                        strcpy(parentbuf, "/");
                    }
                    /* join parent path + relative target */
                    size_t plen = strlen(parentbuf);
                    if (plen > 1 && parentbuf[plen - 1] == '/') parentbuf[plen - 1] = '\0';
                    snprintf(newpath, newlen, "%s/%s", parentbuf, child->data);
                }
                if (rest) {
                    size_t curlen = strlen(newpath);
                    newpath[curlen] = '/';
                    newpath[curlen+1] = '\0';
                    strncat(newpath, rest, newlen - curlen - 2);
                }
                kfree(tmp);
                kfree(curpath);
                curpath = newpath;
                /* restart outer loop to resolve new path */
                break;
            }
            /* not a symlink: continue traversal */
            cur = child;
            tok = strtok(NULL, "/");
        }
        if (tok == NULL) {
            /* finished without hitting symlink; resolve hard link if any */
            kfree(tmp);
            kfree(curpath);
            return ramfs_resolve_link(cur);
        }
        /* else we restarted due to symlink; continue loop */
        /* loop continues, curpath updated */
    }
    kfree(curpath);
    return NULL;
}

static int ramfs_create(const char *path, struct fs_file **out_file) {
    if (!path || path[0] != '/') return -1;
    /* find parent */
    size_t path_len = strlen(path);
    char *tmp = (char*)kmalloc(path_len + 1);
    if (!tmp) return -2;
    memcpy(tmp, path, path_len + 1);
    char *slash = strrchr(tmp, '/');
    char *name = NULL;
    const char *parent_path = NULL;
    if (slash == tmp) {
        /* parent is root */
        parent_path = "/";
        name = slash + 1;
    } else {
        *slash = '\0';
        parent_path = tmp;
        name = slash + 1;
    }
    if (!name || !name[0]) { kfree(tmp); return -3; }
    struct ramfs_node *parent = ramfs_lookup(parent_path);
    if (!parent) { kfree(tmp); return -2; }
    if (!parent->is_dir) { kfree(tmp); return -3; }
    if (ramfs_find_child(parent, name)) { kfree(tmp); return -4; }
    struct ramfs_node *n = ramfs_alloc_node(name, 0);
    if (!n) { kfree(tmp); return -5; }
    /* set owner to current thread euid/egid */
    thread_t* ct = thread_current();
    if (ct) { n->uid = ct->euid; n->gid = ct->egid; }
    n->parent = parent;
    /* insert at head */
    n->next = parent->children;
    parent->children = n;
    /* create fs_file */
    struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
    if (!f) {
        /* rollback node insert */
        if (parent->children == n) parent->children = n->next;
        else {
            struct ramfs_node *p = parent->children;
            while (p && p->next != n) p = p->next;
            if (p && p->next == n) p->next = n->next;
        }
        ramfs_free_node_shallow(n);
        kfree(tmp);
        return -6;
    }
    memset(f,0,sizeof(*f));
    size_t plen = strlen(path)+1;
    char *pp = (char*)kmalloc(plen);
    if (!pp) {
        kfree(f);
        /* rollback node insert */
        if (parent->children == n) parent->children = n->next;
        else {
            struct ramfs_node *p = parent->children;
            while (p && p->next != n) p = p->next;
            if (p && p->next == n) p->next = n->next;
        }
        ramfs_free_node_shallow(n);
        kfree(tmp);
        return -6;
    }
    memcpy(pp, path, plen);
    f->path = pp;
    f->size = 0;
    f->fs_private = ramfs_driver.driver_data;
    f->type = n->is_dir ? FS_TYPE_DIR : FS_TYPE_REG;
    struct ramfs_file_handle *fh = (struct ramfs_file_handle*)kmalloc(sizeof(*fh));
    if (!fh) {
        kfree(pp);
        kfree(f);
        /* rollback node insert */
        if (parent->children == n) parent->children = n->next;
        else {
            struct ramfs_node *p = parent->children;
            while (p && p->next != n) p = p->next;
            if (p && p->next == n) p->next = n->next;
        }
        ramfs_free_node_shallow(n);
        kfree(tmp);
        return -6;
    }
    fh->node = n;
    f->driver_private = fh;
    if (out_file) *out_file = f;
    kfree(tmp);
    return 0;
}

static int ramfs_open(const char *path, struct fs_file **out_file) {
    /* IMPORTANT: do NOT follow symlinks here.
       VFS (`fs_open`) is responsible for resolving symlinks in paths.
       Returning the symlink node allows lstat/readlink to work. */
    struct ramfs_node *n = ramfs_lookup_nofollow(path);
    if (!n) return -1;
    n = ramfs_resolve_link(n); /* hard links: use target for data */
    struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
    if (!f) return -2;
    memset(f,0,sizeof(*f));
    size_t plen = strlen(path)+1;
    char *pp = (char*)kmalloc(plen);
    if (!pp) { kfree(f); return -2; }
    memcpy(pp, path, plen);
    f->path = pp;
    f->size = n->size;
    f->fs_private = ramfs_driver.driver_data;
    f->type = n->is_dir ? FS_TYPE_DIR : FS_TYPE_REG;
    struct ramfs_file_handle *fh = (struct ramfs_file_handle*)kmalloc(sizeof(*fh));
    if (!fh) { kfree(pp); kfree(f); return -2; }
    fh->node = n;
    f->driver_private = fh;
    if (out_file) *out_file = f;
    return 0;
}

static ssize_t ramfs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    if (!file || !file->driver_private) return -1;
    struct ramfs_file_handle *fh = (struct ramfs_file_handle*)file->driver_private;
    struct ramfs_node *n = fh->node;
    if (n->is_dir) {
        /* produce ext2-like dir entries, respect offset */
        size_t pos = 0;
        size_t written = 0;
        struct ext2_dir_entry de;
        uint8_t *out = (uint8_t*)buf;
        for (struct ramfs_node *c = n->children; c; c = c->next) {
            struct ramfs_node *r = ramfs_resolve_link(c);
            size_t namelen = strlen(c->name);
            /* record length: header (8) + name, padded to 4 bytes for compatibility */
            size_t rec_len = (size_t)(8 + namelen);
            rec_len = (rec_len + 3) & ~3u;
            if (rec_len < sizeof(struct ext2_dir_entry)) rec_len = sizeof(struct ext2_dir_entry);
            if (pos + rec_len <= (size_t)offset) { pos += rec_len; continue; }
            if (written >= size) break;
            uint8_t tmp[512];
            /* initialize buffer to zero to avoid leaking memory beyond name */
            for (size_t zi = 0; zi < sizeof(tmp); zi++) tmp[zi] = 0;
            de.inode = (uint32_t)(r->ino & 0xFFFFFFFFu);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = ((c->mode & S_IFLNK) == S_IFLNK) ? EXT2_FT_SYMLINK : (r->is_dir ? EXT2_FT_DIR : EXT2_FT_REG_FILE);
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, c->name, namelen);
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
    } else {
        if (offset >= n->size) return 0;
        if (offset + size > n->size) size = n->size - offset;
        memcpy(buf, n->data + offset, size);
        return (ssize_t)size;
    }
}

int ramfs_chmod(const char *path, mode_t mode) {
    if (!path) return -1;
    struct ramfs_node *n = ramfs_lookup(path);
    if (!n) return -1;
    /* permission: only owner or root */
    thread_t* ct = thread_current();
    uid_t uid = ct ? ct->euid : 0;
    if (uid != 0 && uid != n->uid) return -1;
    n->mode = mode;
    return 0;
}

int ramfs_fill_stat(struct fs_file *file, struct stat *st) {
    if (!file || !st || !file->driver_private) return -1;
    struct ramfs_file_handle *fh = (struct ramfs_file_handle*)file->driver_private;
    if (!fh || !fh->node) return -1;
    struct ramfs_node *n = fh->node;
    st->st_ino = (ino_t)n->ino;
    /* Use stored node mode (supports S_IFLNK, S_IFREG, S_IFDIR) */
    st->st_mode = (mode_t)n->mode;
    st->st_nlink = (nlink_t)n->nlink;
    st->st_uid = n->uid;
    st->st_gid = n->gid;
    st->st_size = (off_t)n->size;
    st->st_atime = n->atime;
    st->st_mtime = n->mtime;
    st->st_ctime = n->ctime;
    return 0;
}

static ssize_t ramfs_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
    if (!file || !file->driver_private) return -1;
    struct ramfs_file_handle *fh = (struct ramfs_file_handle*)file->driver_private;
    struct ramfs_node *n = fh->node;
    if (n->is_dir) return -1;
    /* allow kernel context writes (ct == NULL), otherwise require root */
    thread_t* ct = thread_current();
    if (ct) {
        if (ct->euid != 0) return -1;
    } else {
        /* kernel context: allow writes */
    }
    /* Grow and copy in chunks to avoid one-shot large reallocs where possible.
       This may allow progress when large contiguous allocations fail. */
    const size_t CHUNK = 64 * 1024; /* 64 KiB */
    size_t write_pos = offset;
    size_t src_pos = 0;
    size_t remaining = size;
    while (remaining > 0) {
        size_t chunk = remaining > CHUNK ? CHUNK : remaining;
        size_t needed_end = write_pos + chunk;
        if (needed_end > n->size) {
            char *d = (char*)krealloc(n->data, needed_end);
            if (!d) {
                /* log diagnostic info to help root cause allocation failure */
                klogprintf("ramfs: write: krealloc failed path=%s offset=%u write_size=%u needed_end=%u heap_used=%llu heap_total=%llu\n",
                           file && file->path ? file->path : "(null)",
                           (unsigned)offset, (unsigned)size, (unsigned)needed_end,
                           (unsigned long long)heap_used_bytes(), (unsigned long long)heap_total_bytes());
                return -1;
            }
            n->data = d;
            n->size = needed_end;
        }
        memcpy(n->data + write_pos, (const char*)buf + src_pos, chunk);
        write_pos += chunk;
        src_pos += chunk;
        remaining -= chunk;
    }
    return (ssize_t)size;
}

static void ramfs_release(struct fs_file *file) {
    if (!file) return;
    if (file->driver_private) kfree(file->driver_private);
    if (file->path) kfree((void*)file->path);
    kfree(file);
}

int ramfs_mkdir(const char *path) {
    if (!path) return -1;
    /* create directory node */
    if (path[0] != '/') return -1;
    size_t path_len = strlen(path);
    char *tmp = (char*)kmalloc(path_len + 2);
    if (!tmp) return -2;
    memcpy(tmp, path, path_len + 1);
    /* ensure no trailing slash */
    size_t l = strlen(tmp);
    if (l > 1 && tmp[l-1] == '/') tmp[l-1] = '\0';
    /* find parent */
    char *slash = strrchr(tmp, '/');
    const char *parent_path = NULL;
    char *name;
    if (slash == tmp) { parent_path = "/"; name = slash + 1; }
    else { *slash = '\0'; parent_path = tmp; name = slash + 1; }
    if (!name || !name[0]) { kfree(tmp); return -3; }
    struct ramfs_node *parent = ramfs_lookup(parent_path);
    if (!parent) { kfree(tmp); return -2; }
    if (!parent->is_dir) { kfree(tmp); return -3; }
    if (ramfs_find_child(parent, name)) { kfree(tmp); return -4; }
    struct ramfs_node *n = ramfs_alloc_node(name, 1);
    if (!n) { kfree(tmp); return -5; }
    n->parent = parent;
    n->next = parent->children;
    parent->children = n;
    kfree(tmp);
    return 0;
}

int ramfs_remove(const char *path) {
    if (!path) return -1;
    if (strcmp(path, "/") == 0) return -2;
    /* only root can remove files from ramfs by default */
    thread_t* ct = thread_current();
    if (!ct || ct->euid != 0) return -1;
    struct ramfs_node *n = ramfs_lookup(path);
    if (!n) return -3;
    struct ramfs_node *p = n->parent;
    if (!p) return -4;
    /* unlink from parent's children */
    struct ramfs_node **pp = &p->children;
    while (*pp) {
        if (*pp == n) { *pp = n->next; break; }
        pp = &(*pp)->next;
    }
    /* free recursively */
    /* simple recursive free */
    struct ramfs_node *stack[64]; int sp = 0;
    stack[sp++] = n;
    while (sp) {
        struct ramfs_node *cur = stack[--sp];
        for (struct ramfs_node *c = cur->children; c; c = c->next) {
            if (sp < 64) stack[sp++] = c;
        }
        if (cur->name) kfree(cur->name);
        if (cur->data) kfree(cur->data);
        kfree(cur);
    }
    return 0;
}

int ramfs_register(void) {
    /* init root */
    ramfs_root = ramfs_alloc_node("", 1);
    if (!ramfs_root) return -1;
    ramfs_root->parent = NULL;
    /* Create /dev immediately so it is always in root; critical for ls / visibility */
    (void)ramfs_mkdir("/dev");
    ramfs_driver.ops = &ramfs_ops;
    ramfs_driver.driver_data = (void*)ramfs_root;
    ramfs_ops.name = "ramfs";
    ramfs_ops.create = ramfs_create;
    ramfs_ops.open = ramfs_open;
    ramfs_ops.read = ramfs_read;
    ramfs_ops.write = ramfs_write;
    ramfs_ops.mkdir = ramfs_mkdir;
    ramfs_ops.chmod = ramfs_chmod;
    ramfs_ops.link = ramfs_link;
    ramfs_ops.release = ramfs_release;

    return fs_register_driver(&ramfs_driver);
}

int ramfs_unregister(void) {
    return fs_unregister_driver(&ramfs_driver);
}
