/* Common video driver interface for AxonOS */
#ifndef VIDEO_H
#define VIDEO_H

#include <stdint.h>
#include <stddef.h>

typedef struct video_device video_device_t;

typedef struct video_ops {
	int (*init)(video_device_t *dev); /* initialize device; return 0 on success */
	void (*shutdown)(video_device_t *dev);
	void (*flush_region)(video_device_t *dev, uint32_t x, uint32_t y, uint32_t w, uint32_t h);
	int (*set_mode)(video_device_t *dev, uint32_t width, uint32_t height, uint32_t bpp);
} video_ops_t;

struct video_device {
	const char *name;
	void *mmio_base;      /* mapped virtual base (or NULL) */
	uint64_t mmio_pa;     /* physical address of MMIO (if known) */
	uint32_t width;
	uint32_t height;
	uint32_t pitch;
	uint32_t bpp;
	const video_ops_t *ops;
	void *priv;           /* driver-private storage */
};

/* Register a video driver implementation by name. The registry keeps a small
   fixed-size table; drivers should call this at startup (or via explicit init). */
int video_register_driver(const char *name, const video_ops_t *ops, void *priv);

/* Probe all registered drivers and call their init. Returns number of
   successfully initialized devices. */
int video_probe_all(void);

/* Find a device by name (returns first match) */
video_device_t *video_find_by_name(const char *name);

#endif /* VIDEO_H */


