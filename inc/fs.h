#ifndef INC_FS_H
#define INC_FS_H

#include <stdint.h>
#include <stddef.h>

/* ssize_t may not be available in this kernel environment */
typedef long ssize_t;

/* Generic filesystem file handle returned to callers */
struct fs_file {
    const char *path;          /* logical path */
    void *fs_private;         /* pointer managed by filesystem implementation */
    void *driver_private;     /* optional per-file driver data */
    size_t size;
    int type;                 /* FS_TYPE_* (set by driver) */
};

/* Filesystem driver operations (minimal set) */
struct fs_driver_ops {
    const char *name; /* short name of FS (e.g., "ext2") */

    /* Try to create a file at path. Return 0 on success, negative on error.
       If success, allocate and return fs_file via out_file (caller frees with fs_file_free).
       Drivers may choose to accept or reject paths (return -1 to indicate not-handled). */
    int (*create)(const char *path, struct fs_file **out_file);

    /* Open existing file. Return 0 on success and set out_file. Return -1 if driver does not handle path.
       Return negative errno-like on other errors. */
    int (*open)(const char *path, struct fs_file **out_file);

    /* Read from file; return number of bytes read or negative error */
    ssize_t (*read)(struct fs_file *file, void *buf, size_t size, size_t offset);

    /* Write to file; return bytes written or negative error */
    ssize_t (*write)(struct fs_file *file, const void *buf, size_t size, size_t offset);

    /* Optional cleanup for fs_file allocated by driver */
    void (*release)(struct fs_file *file);
};

/* Registered driver object */
struct fs_driver {
    struct fs_driver_ops *ops;
    void *driver_data; /* for future use */
};

/* Public VFS API */
int fs_register_driver(struct fs_driver *drv);
int fs_unregister_driver(struct fs_driver *drv);
int fs_mount(const char *path, struct fs_driver *drv);

/* High-level helpers which dispatch to registered drivers in registration order */
struct fs_file *fs_create_file(const char *path);
struct fs_file *fs_open(const char *path);
ssize_t fs_read(struct fs_file *file, void *buf, size_t size, size_t offset);
ssize_t fs_write(struct fs_file *file, const void *buf, size_t size, size_t offset);
void fs_file_free(struct fs_file *file);

/* file types */
#define FS_TYPE_UNKNOWN 0
#define FS_TYPE_REG     1
#define FS_TYPE_DIR     2

#endif /* INC_FS_H */
