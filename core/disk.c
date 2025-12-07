#include <disk.h>
#include <axonos.h>
#include <string.h>

static disk_ops_t *g_disks[DISK_MAX_DEVICES];
static int g_disk_count = 0;

int disk_register(disk_ops_t *ops) {
	if (!ops || g_disk_count >= DISK_MAX_DEVICES) return -1;
	g_disks[g_disk_count] = ops;
	int id = g_disk_count++;
	if (ops->init) {
		int r = ops->init();
		if (r != 0) {
			kprintf("disk: driver %s init failed\n", ops->name ? ops->name : "unknown");
			/* unregister */
			g_disks[id] = NULL;
			g_disk_count--;
			return -1;
		}
	}
	kprintf("disk: registered device %d -> %s\n", id, ops->name ? ops->name : "unnamed");
	return id;
}

int disk_count(void) {
	return g_disk_count;
}

int disk_read_sectors(int device_id, uint32_t lba, void *buf, uint32_t sectors) {
	if (device_id < 0 || device_id >= g_disk_count) return -1;
	disk_ops_t *d = g_disks[device_id];
	if (!d || !d->read) return -1;
	return d->read(device_id, lba, buf, sectors);
}

int disk_write_sectors(int device_id, uint32_t lba, const void *buf, uint32_t sectors) {
	if (device_id < 0 || device_id >= g_disk_count) return -1;
	disk_ops_t *d = g_disks[device_id];
	if (!d || !d->write) return -1;
	return d->write(device_id, lba, buf, sectors);
}


