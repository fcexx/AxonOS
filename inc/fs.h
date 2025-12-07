#ifndef INC_FS_H
#define INC_FS_H

#include <stdint.h>
#include <stddef.h>
#include "stat.h"

/* ssize_t may not be available in this kernel environment */
typedef long ssize_t;

/* Generic filesystem file handle returned to callers */
struct fs_file {
    const char *path;          /* logical path */
    void *fs_private;         /* pointer managed by filesystem implementation */
    void *driver_private;     /* optional per-file driver data */
    size_t size;
    off_t pos;
    int type;                 /* FS_TYPE_* (set by driver) */
    int refcount;             /* VFS reference count for this handle */
};

/* Filesystem driver operations (minimal set) */
struct fs_driver_ops {
    const char *name; /* short name of FS (e.g., "ext2") */

    /* Try to create a file at path. Return 0 on success, negative on error.
       If success, allocate and return fs_file via out_file (caller frees with fs_file_free).
       Drivers may choose to accept or reject paths (return -1 to indicate not-handled). */
    int (*create)(const char *path, struct fs_file **out_file);
    /* Make directory (create directory entry). Return 0 on success. Optional. */
    int (*mkdir)(const char *path);

    /* Open existing file. Return 0 on success and set out_file. Return -1 if driver does not handle path.
       Return negative errno-like on other errors. */
    int (*open)(const char *path, struct fs_file **out_file);

    /* Read from file; return number of bytes read or negative error */
    ssize_t (*read)(struct fs_file *file, void *buf, size_t size, size_t offset);

    /* Write to file; return bytes written or negative error */
    ssize_t (*write)(struct fs_file *file, const void *buf, size_t size, size_t offset);

    /* Optional cleanup for fs_file allocated by driver */
    void (*release)(struct fs_file *file);
    /* Optional chmod operation: set mode for path */
    int (*chmod)(const char *path, mode_t mode);
};

/* Registered driver object */
struct fs_driver {
    struct fs_driver_ops *ops;
    void *driver_data; /* for future use */
};

/* extendable driver operations (chmod optional) */
/* Note: keep single definition above; chmod added here for drivers that support it */

/* Public VFS API */
int fs_register_driver(struct fs_driver *drv);
int fs_unregister_driver(struct fs_driver *drv);
int fs_mount(const char *path, struct fs_driver *drv);
/* Unmount previously mounted path. Returns 0 on success, -1 on error */
int fs_unmount(const char *path);
/* Return driver mounted for path (NULL if none) */
struct fs_driver *fs_get_mount_driver(const char *path);
/* Get mount path for a registered driver. Returns 0 on success and fills out, -1 if not found. */
int fs_get_mount_path(const struct fs_driver *drv, char *out, size_t outlen);
/* Get the matching mount prefix for a given path (longest prefix). Returns 0 on success. */
int fs_get_matching_mount_prefix(const char *path, char *out, size_t outlen);

/* High-level helpers which dispatch to registered drivers in registration order */
struct fs_file *fs_create_file(const char *path);
struct fs_file *fs_open(const char *path);
ssize_t fs_read(struct fs_file *file, void *buf, size_t size, size_t offset);
ssize_t fs_write(struct fs_file *file, const void *buf, size_t size, size_t offset);
void fs_file_free(struct fs_file *file);
/* Read next chunk from directory/file using and advancing file->pos */
ssize_t fs_readdir_next(struct fs_file *file, void *buf, size_t size);

/* POSIX-like stat helpers */
int vfs_fstat(struct fs_file *file, struct stat *st);
int vfs_stat(const char *path, struct stat *st);
int fs_chmod(const char *path, mode_t mode);

/* file types */
#define FS_TYPE_UNKNOWN 0
#define FS_TYPE_REG     1
#define FS_TYPE_DIR     2

#endif /* INC_FS_H */
