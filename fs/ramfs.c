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
                    /* compute parent path of current node */
                    struct ramfs_node *p = child->parent;
                    size_t plenp = 0;
                    parentbuf[0] = '\0';
                    if (p && p != ramfs_root) {
                        /* reconstruct path by walking up - simple approach: ignore, treat as '/' */
                        strcpy(parentbuf, "/");
                    } else {
                        strcpy(parentbuf, "/");
                    }
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
            /* finished without hitting symlink */
            kfree(tmp);
            kfree(curpath);
            return cur;
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
    struct ramfs_node *n = ramfs_lookup(path);
    if (!n) return -1;
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
            de.inode = (uint32_t)(c->ino & 0xFFFFFFFFu);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = c->is_dir ? EXT2_FT_DIR : EXT2_FT_REG_FILE;
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
    size_t new_size = offset + size;
    if (new_size > n->size) {
        char *d = (char*)krealloc(n->data, new_size);
        if (!d) return -1;
        n->data = d;
        n->size = new_size;
    }
    memcpy(n->data + offset, buf, size);
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
    ramfs_driver.ops = &ramfs_ops;
    ramfs_driver.driver_data = (void*)ramfs_root;
    ramfs_ops.name = "ramfs";
    ramfs_ops.create = ramfs_create;
    ramfs_ops.open = ramfs_open;
    ramfs_ops.read = ramfs_read;
    ramfs_ops.write = ramfs_write;
    ramfs_ops.mkdir = ramfs_mkdir;
    ramfs_ops.chmod = ramfs_chmod;
    ramfs_ops.release = ramfs_release;

    return fs_register_driver(&ramfs_driver);
}

int ramfs_unregister(void) {
    return fs_unregister_driver(&ramfs_driver);
}
