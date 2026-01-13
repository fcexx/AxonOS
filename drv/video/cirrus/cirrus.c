/* Minimal Cirrus driver skeleton */
#include <cirrus.h>
#include <mmio.h>
#include <klog.h>
#include <string.h>

static int cirrus_init(video_device_t *dev) {
	klogprintf("cirrus: init for device %s\n", dev && dev->name ? dev->name : "cirrus");
	/* Typical legacy Cirrus cards may use MMIO or IO ports; here we only show MMIO mapping example */
	if (dev->mmio_pa && dev->mmio_base == NULL) {
		void *va = mmio_map_phys(dev->mmio_pa, 1 * 1024 * 1024); /* 1MiB example */
		if (!va) {
			klogprintf("cirrus: mmio_map_phys failed for pa=0x%llx\n", (unsigned long long)dev->mmio_pa);
			return -1;
		}
		dev->mmio_base = va;
	}
	dev->width = 640;
	dev->height = 480;
	dev->bpp = 32;
	dev->pitch = dev->width * (dev->bpp / 8);
	return 0;
}

static void cirrus_shutdown(video_device_t *dev) {
	(void)dev;
}

static void cirrus_flush_region(video_device_t *dev, uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
	(void)dev; (void)x; (void)y; (void)w; (void)h;
}

static int cirrus_set_mode(video_device_t *dev, uint32_t width, uint32_t height, uint32_t bpp) {
	dev->width = width; dev->height = height; dev->bpp = bpp;
	dev->pitch = width * (bpp / 8);
	return 0;
}

const video_ops_t cirrus_video_ops = {
	.init = cirrus_init,
	.shutdown = cirrus_shutdown,
	.flush_region = cirrus_flush_region,
	.set_mode = cirrus_set_mode,
};

int cirrus_driver_register(void) {
	return video_register_driver("cirrus", &cirrus_video_ops, NULL);
}



