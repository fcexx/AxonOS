#pragma once

#include <stdint.h>
#include <stddef.h>

#define DISK_MAX_DEVICES 16
#define DISK_SECTOR_SIZE 512

typedef struct disk_ops {
	const char *name;
	/* optional init, return 0 on success */
	int (*init)(void);
	/* read/write sectors: device_id is the id returned by disk_register,
	   lba is sector number, sectors is number of 512-byte sectors */
	int (*read)(int device_id, uint32_t lba, void *buf, uint32_t sectors);
	int (*write)(int device_id, uint32_t lba, const void *buf, uint32_t sectors);
} disk_ops_t;

/* Register a disk driver; returns device id (>=0) or -1 on error */
int disk_register(disk_ops_t *ops);

/* Number of registered block devices */
int disk_count(void);

/* Read/write helpers used by upper layers (return 0 on success) */
int disk_read_sectors(int device_id, uint32_t lba, void *buf, uint32_t sectors);
int disk_write_sectors(int device_id, uint32_t lba, const void *buf, uint32_t sectors);


