#pragma once

#include <stddef.h>
#include <stdint.h>
#include <fs.h>
#include <stat.h>

typedef ssize_t (*sysfs_show_t)(char *buf, size_t size, void *priv);
typedef ssize_t (*sysfs_store_t)(const char *buf, size_t size, void *priv);

/* Show callbacks for sysfs attributes (implemented in kernel.c) */
ssize_t sysfs_show_const(char *buf, size_t size, void *priv);
ssize_t sysfs_show_cpu_name_attr(char *buf, size_t size, void *priv);
ssize_t sysfs_show_ram_mb_attr(char *buf, size_t size, void *priv);

struct sysfs_attr {
    sysfs_show_t show;
    sysfs_store_t store;
    void *priv;
};

int sysfs_register(void);
int sysfs_unregister(void);
int sysfs_mount(const char *path);

int sysfs_mkdir(const char *path);
int sysfs_create_file(const char *path, const struct sysfs_attr *attr);
int sysfs_remove(const char *path);

/* Fill stat for an open sysfs file (driver-specific) */
int sysfs_fill_stat(struct fs_file *file, struct stat *st);
int sysfs_chmod(const char *path, mode_t mode);


