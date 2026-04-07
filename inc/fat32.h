#pragma once

#include <stdint.h>
#include <stddef.h>
#include <fs.h>
#include <stat.h>

int fat32_register(void);
int fat32_unregister(void);
int fat32_mount_from_device(int device_id);
int fat32_probe_and_mount(int device_id);
void fat32_unmount_cleanup(void);
/* Return pointer to registered fat32 driver (or NULL) */
struct fs_driver *fat32_get_driver(void);

/* Truncate open FAT file. Only length==0 is fully supported; grow returns -EOPNOTSUPP. */
int fat32_ftruncate(struct fs_file *file, off_t length);

