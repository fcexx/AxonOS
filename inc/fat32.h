#pragma once

#include <stdint.h>
#include <stddef.h>

int fat32_register(void);
int fat32_unregister(void);
int fat32_mount_from_device(int device_id);
int fat32_probe_and_mount(int device_id);
/* Return pointer to registered fat32 driver (or NULL) */
struct fs_driver *fat32_get_driver(void);


