#pragma once

#include <stddef.h>
#include <stdint.h>
#include "fs.h"

typedef ssize_t (*sysfs_show_t)(char *buf, size_t size, void *priv);
typedef ssize_t (*sysfs_store_t)(const char *buf, size_t size, void *priv);

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


