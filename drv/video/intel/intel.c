/* Minimal Intel driver skeleton */
#include <intel.h>
#include <mmio.h>
#include <klog.h>
#include <string.h>
#include <stddef.h>

static int intel_init(video_device_t *dev) {
	klogprintf("intel: init for device %s\n", dev && dev->name ? dev->name : "intel");
	/* If physical MMIO was supplied by higher-level code, map a reasonable window. */
	if (dev->mmio_pa && dev->mmio_base == NULL) {
		/* example: map 4 MiB of device MMIO (drivers should pick correct size) */
		void *va = mmio_map_phys(dev->mmio_pa, 4 * 1024 * 1024);
		if (!va) {
			klogprintf("intel: mmio_map_phys failed for pa=0x%llx\n", (unsigned long long)dev->mmio_pa);
			return -1;
		}
		dev->mmio_base = va;
	}

	/* For skeleton set a conservative default mode */
	dev->width = 800;
	dev->height = 600;
	dev->bpp = 32;
	dev->pitch = dev->width * (dev->bpp / 8);
	return 0;
}

static void intel_shutdown(video_device_t *dev) {
	/* TODO: unmap mmio, free resources when implemented */
	(void)dev;
}

static void intel_flush_region(video_device_t *dev, uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
	/* Placeholder: real driver should flush GPU or copy buffers as appropriate */
	(void)dev; (void)x; (void)y; (void)w; (void)h;
}

static int intel_set_mode(video_device_t *dev, uint32_t width, uint32_t height, uint32_t bpp) {
	dev->width = width; dev->height = height; dev->bpp = bpp;
	dev->pitch = width * (bpp / 8);
	return 0;
}

const video_ops_t intel_video_ops = {
	.init = intel_init,
	.shutdown = intel_shutdown,
	.flush_region = intel_flush_region,
	.set_mode = intel_set_mode,
};

int intel_driver_register(void) {
	return video_register_driver("intel", &intel_video_ops, NULL);
}


