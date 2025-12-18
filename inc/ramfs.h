#ifndef INC_RAMFS_H
#define INC_RAMFS_H

#include <stddef.h>
#include <fs.h>
#include <stat.h>

int ramfs_register(void);
int ramfs_unregister(void);
int ramfs_mkdir(const char *path);
int ramfs_remove(const char *path);

#ifdef __cplusplus
extern "C" {
#endif
/* Fill stat for an open ramfs file (driver-specific) */
int ramfs_fill_stat(struct fs_file *file, struct stat *st);
int ramfs_chmod(const char *path, mode_t mode);
#ifdef __cplusplus
}
#endif

#endif /* INC_RAMFS_H */
