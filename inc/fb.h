#pragma once

#include <stdint.h>
#include <stddef.h>
#include <fs.h>

/* Simple framebuffer interface for Axonos */

/* Pixel formats */
#define FB_FMT_RGB565  1
#define FB_FMT_RGB888  2
#define FB_FMT_XRGB8888 3

typedef struct fb_info {
    /* resolution */
    uint32_t width;
    uint32_t height;
    uint32_t pitch; /* bytes per scanline */
    uint32_t bpp;   /* bits per pixel */
    uint32_t format; /* FB_FMT_* */

    /* framebuffer memory */
    void *fb_mem;
    size_t fb_mem_size;

    /* driver-private pointer */
    void *driver_data;

    /* logical device number (e.g., 0 => /dev/fb0) */
    int devnum;
} fb_info_t;

/* Framebuffer operations implemented by drivers */
struct fb_ops {
    const char *name;
    /* initialize hardware and allocate fb_mem; return 0 on success */
    int (*init)(fb_info_t *info);
    /* shutdown and free resources */
    void (*shutdown)(fb_info_t *info);
    /* optional: set mode (width/height/bpp) - return 0 on success */
    int (*set_mode)(fb_info_t *info, uint32_t width, uint32_t height, uint32_t bpp);
    /* flush region to display (if required) */
    void (*flush)(fb_info_t *info, uint32_t x, uint32_t y, uint32_t w, uint32_t h);
};

/* Register a framebuffer device; returns devnum (>=0) or -1 on error */
int fb_register_device(struct fb_ops *ops, fb_info_t *info);
int fb_unregister_device(int devnum);

/* Helpers to get fb_info by device number */
fb_info_t *fb_get_by_devnum(int devnum);

/* Filesystem binding for /dev/fbN */
int fb_fs_register(void);
void fb_fs_unregister(void);


