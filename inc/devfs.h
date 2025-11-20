#ifndef INC_DEVFS_H
#define INC_DEVFS_H

#include <stdint.h>
#include <stddef.h>
#include "fs.h"

/* Simple POSIX-like device filesystem for AxonOS.
 * Only /dev hierarchy is handled by this driver.
 */

#define DEVFS_TYPE_CHAR  1
#define DEVFS_TYPE_BLOCK 2

struct devfs_ops {
    /* Read from device; return bytes read or negative error */
    ssize_t (*read)(void *priv, void *buf, size_t size, size_t offset);
    /* Write to device; return bytes written or negative error */
    ssize_t (*write)(void *priv, const void *buf, size_t size, size_t offset);
    /* Optional ioctl-style hook; return 0 on success or negative error */
    int (*ioctl)(void *priv, unsigned long cmd, unsigned long arg);
};

int devfs_register(void);
int devfs_unregister(void);
int devfs_mount(const char *path);

/* Register a device node under /dev.
 * path must be like "/dev/null" or "/dev/input/kbd0".
 */
int devfs_register_dev(const char *path, int dev_type,
                       const struct devfs_ops *ops, void *priv);

/* Create an alias path that refers to an already registered device node.
 * Example: alias "/dev/console" -> "/dev/tty0".
 */
int devfs_register_alias(const char *alias_path, const char *target_path);

/* Low-level helper: write directly to primary console TTY (tty0) from kernel.
 * If devfs/tty0 is not ready yet, this is a no-op.
 */
ssize_t devfs_console_write(const char *buf, size_t size);

static inline int devfs_register_chr(const char *path,
                                     const struct devfs_ops *ops, void *priv) {
    return devfs_register_dev(path, DEVFS_TYPE_CHAR, ops, priv);
}

static inline int devfs_register_blk(const char *path,
                                     const struct devfs_ops *ops, void *priv) {
    return devfs_register_dev(path, DEVFS_TYPE_BLOCK, ops, priv);
}

#endif /* INC_DEVFS_H */


