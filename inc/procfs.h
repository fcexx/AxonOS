#pragma once

#include <stddef.h>
#include <stdint.h>
#include <fs.h>
#include <stat.h>

int procfs_register(void);
int procfs_unregister(void);
int procfs_mount(const char *path);


