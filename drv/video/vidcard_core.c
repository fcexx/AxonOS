/* Minimal video driver registry and probe implementation */
#include <video.h>
#include <mmio.h>
#include <klog.h>
#include <string.h>
#include <stddef.h>

#define MAX_VIDEO_DRIVERS 8
#define MAX_VIDEO_DEVICES 8

typedef struct {
	const char *name;
	const video_ops_t *ops;
	void *priv;
} video_driver_entry_t;

static video_driver_entry_t g_drivers[MAX_VIDEO_DRIVERS];
static video_device_t g_devices[MAX_VIDEO_DEVICES];
static size_t g_driver_count = 0;
static size_t g_device_count = 0;

int video_register_driver(const char *name, const video_ops_t *ops, void *priv) {
	if (!name || !ops) return -1;
	if (g_driver_count >= MAX_VIDEO_DRIVERS) {
		klogprintf("video: driver table full, cannot register %s\n", name);
		return -1;
	}
	/* simple duplicate check */
	for (size_t i = 0; i < g_driver_count; i++) {
		if (g_drivers[i].name && strcmp(g_drivers[i].name, name) == 0) {
			klogprintf("video: driver %s already registered\n", name);
			return -1;
		}
	}
	g_drivers[g_driver_count].name = name;
	g_drivers[g_driver_count].ops = ops;
	g_drivers[g_driver_count].priv = priv;
	g_driver_count++;
	klogprintf("video: registered driver %s\n", name);
	return 0;
}

int video_probe_all(void) {
	size_t inited = 0;
	for (size_t d = 0; d < g_driver_count; d++) {
		const char *name = g_drivers[d].name;
		const video_ops_t *ops = g_drivers[d].ops;
		if (!ops || !ops->init) continue;
		if (g_device_count >= MAX_VIDEO_DEVICES) {
			klogprintf("video: device table full, skipping driver %s\n", name);
			continue;
		}
		video_device_t *dev = &g_devices[g_device_count];
		memset(dev, 0, sizeof(*dev));
		dev->name = name;
		dev->ops = ops;
		dev->priv = g_drivers[d].priv;
		/* driver init is responsible for mapping MMIO and setting geometry */
		int r = ops->init(dev);
		if (r == 0) {
			klogprintf("video: driver %s initialized device (w=%u h=%u bpp=%u)\n",
				(const char*)name, dev->width, dev->height, dev->bpp);
			g_device_count++;
			inited++;
		} else {
			klogprintf("video: driver %s init failed (%d)\n", (const char*)name, r);
		}
	}
	return (int)inited;
}

video_device_t *video_find_by_name(const char *name) {
	if (!name) return NULL;
	for (size_t i = 0; i < g_device_count; i++) {
		if (g_devices[i].name && strcmp(g_devices[i].name, name) == 0) return &g_devices[i];
	}
	return NULL;
}


