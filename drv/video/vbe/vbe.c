#include <vbe.h>
#include <stdint.h>
#include <mmio.h>
#include <heap.h>
#include <string.h>
#include <fb.h>
#include <klog.h>
#include <debug.h>

static void *g_frontbuf = NULL;
static void *g_backbuf = NULL;
static uint32_t g_width = 0;
static uint32_t g_height = 0;
static uint32_t g_pitch = 0;
static uint32_t g_bpp = 0;
static int g_enabled = 0;
/* RGB field info (positions and sizes) from multiboot framebuffer tag (defaults XRGB8888) */
static uint8_t g_rpos = 16, g_rsize = 8;
static uint8_t g_gpos = 8, g_gsize = 8;
static uint8_t g_bpos = 0, g_bsize = 8;

int vbe_is_available(void) { return g_enabled; }

static void vbe_flush_region_internal(uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
	if (!g_enabled || !g_frontbuf || !g_backbuf) return;
	if (x >= g_width || y >= g_height) return;
	if (x + w > g_width) w = g_width - x;
	if (y + h > g_height) h = g_height - y;

	uint32_t bytes_per_pixel = g_bpp / 8;
	for (uint32_t row = 0; row < h; row++) {
		uint8_t *src = (uint8_t*)g_backbuf + (size_t)( (y + row) * g_pitch + x * bytes_per_pixel );
		uint8_t *dst = (uint8_t*)g_frontbuf + (size_t)( (y + row) * g_pitch + x * bytes_per_pixel );
		memcpy(dst, src, (size_t)w * bytes_per_pixel);
	}
}

/* Public: flush entire backbuffer to front */
void vbe_flush_full(void) {
	if (!g_enabled) return;
	vbe_flush_region_internal(0, 0, g_width, g_height);
}

void vbe_flush_region(uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
	vbe_flush_region_internal(x,y,w,h);
}

void *vbe_get_backbuffer(void) { return g_backbuf; }
void *vbe_get_frontbuffer(void) { return g_frontbuf; }
uint32_t vbe_get_pitch(void) { return g_pitch; }
uint32_t vbe_get_bpp(void) { return g_bpp; }
uint32_t vbe_get_width(void) { return g_width; }
uint32_t vbe_get_height(void) { return g_height; }

/* Pack 8-bit channels into framebuffer pixel according to detected masks */
uint32_t vbe_pack_pixel(uint8_t r, uint8_t g, uint8_t b) {
	/* reduce to field sizes */
	uint32_t rv = (g_rsize >= 8) ? r : (r >> (8 - g_rsize));
	uint32_t gv = (g_gsize >= 8) ? g : (g >> (8 - g_gsize));
	uint32_t bv = (g_bsize >= 8) ? b : (b >> (8 - g_bsize));
	uint32_t pixel = ( (rv & ((1u<<g_rsize)-1)) << g_rpos )
	               | ( (gv & ((1u<<g_gsize)-1)) << g_gpos )
	               | ( (bv & ((1u<<g_bsize)-1)) << g_bpos );
	return pixel;
}

/* Scroll framebuffer up by given pixel rows (fast memmove). */
void vbe_scroll_up_pixels(uint32_t pixels) {
	if (!g_enabled || !g_frontbuf || pixels == 0 || pixels >= g_height) return;
	uint32_t bytes_per_pixel = (g_bpp + 7) / 8;
	size_t row_bytes = (size_t)g_pitch;
	size_t move_bytes = row_bytes * (size_t)(g_height - pixels);
	uint8_t *fb = (uint8_t*)g_frontbuf;
	/* memmove handles overlap */
	memmove(fb, fb + (size_t)pixels * row_bytes, move_bytes);
	/* clear bottom area */
	uint32_t clear_y = g_height - pixels;
	uint32_t packed_clear = vbe_pack_pixel(0,0,0);
	for (uint32_t ry = 0; ry < pixels; ry++) {
		uint8_t *line = fb + (size_t)( (clear_y + ry) * row_bytes );
		/* fill each pixel */
		for (uint32_t x = 0; x < g_width; x++) {
			uint8_t *dst = line + (size_t)x * bytes_per_pixel;
			if (bytes_per_pixel == 4) *(uint32_t*)dst = packed_clear;
			else if (bytes_per_pixel == 3) {
				dst[0] = (uint8_t)(packed_clear & 0xFF);
				dst[1] = (uint8_t)((packed_clear >> 8) & 0xFF);
				dst[2] = (uint8_t)((packed_clear >> 16) & 0xFF);
			} else if (bytes_per_pixel == 2) {
				dst[0] = (uint8_t)(packed_clear & 0xFF);
				dst[1] = (uint8_t)((packed_clear >> 8) & 0xFF);
			}
		}
	}
}

/* Clear pixel region in front buffer using packed pixel value. */
void vbe_clear_region(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t packed_pixel) {
	if (!g_enabled || !g_frontbuf) return;
	uint32_t bpp = g_bpp;
	uint32_t bytespp = (bpp + 7) / 8;
	uint8_t *fb = (uint8_t*)g_frontbuf;
	if (x >= g_width || y >= g_height) return;
	if (x + w > g_width) w = g_width - x;
	if (y + h > g_height) h = g_height - y;
	for (uint32_t ry = 0; ry < h; ry++) {
		uint8_t *line = fb + (size_t)( (y + ry) * g_pitch + x * bytespp );
		for (uint32_t rx = 0; rx < w; rx++) {
			uint8_t *dst = line + (size_t)rx * bytespp;
			if (bytespp == 4) *(uint32_t*)dst = packed_pixel;
			else if (bytespp == 3) {
				dst[0] = (uint8_t)(packed_pixel & 0xFF);
				dst[1] = (uint8_t)((packed_pixel >> 8) & 0xFF);
				dst[2] = (uint8_t)((packed_pixel >> 16) & 0xFF);
			} else if (bytespp == 2) {
				dst[0] = (uint8_t)(packed_pixel & 0xFF);
				dst[1] = (uint8_t)((packed_pixel >> 8) & 0xFF);
			}
		}
	}
}

int vbe_init_from_multiboot(uint32_t multiboot_magic, uint64_t multiboot_info) {
	// Only multiboot2 handled here; otherwise no framebuffer info
	if (multiboot_magic != 0x36d76289u || multiboot_info == 0) return 0;
	uint8_t *p = (uint8_t*)(uintptr_t)multiboot_info;
	uint32_t total_size = *(uint32_t*)p;
	klogprintf("vbe: multiboot total_size=%u\n", (unsigned)total_size);
	if (total_size < 16 || total_size > (64u * 1024u * 1024u)) return 0;

	uint32_t off = 8;
	while (off + 8 <= total_size) {
		uint32_t tag_type = *(uint32_t*)(p + off);
		uint32_t tag_size = *(uint32_t*)(p + off + 4);
		// debug each tag
		//klogprintf("vbe: tag type=%u size=%u off=%u\n", (unsigned)tag_type, (unsigned)tag_size, (unsigned)off);
		if (tag_size < 8) break;
		if ((uint64_t)off + (uint64_t)tag_size > (uint64_t)total_size) break;
		if (tag_type == 0) break;

		if (tag_type == 8 && tag_size >= 32) { /* FRAMEBUFFER tag */
			// layout: u64 addr; u32 pitch; u32 width; u32 height; u8 bpp; u8 type; u8 reserved[2]; ...
			uint64_t fb_addr = *(uint64_t*)(p + off + 8);
			uint32_t pitch = *(uint32_t*)(p + off + 16);
			uint32_t width = *(uint32_t*)(p + off + 20);
			uint32_t height = *(uint32_t*)(p + off + 24);
			uint8_t bpp = *(uint8_t*)(p + off + 28);
			uint8_t ftype = *(uint8_t*)(p + off + 29);

			klogprintf("vbe: framebuffer tag found addr=0x%016llx pitch=%u width=%u height=%u bpp=%u\n",
				(unsigned long long)fb_addr, (unsigned)pitch, (unsigned)width, (unsigned)height, (unsigned)bpp);

			if (fb_addr == 0 || width == 0 || height == 0 || bpp == 0) {
				klogprintf("vbe: invalid fb fields, skipping\n");
				off += (tag_size + 7) & ~7u;
				continue;
			}

			size_t fb_size = (size_t)pitch * (size_t)height;
			void *fb_va = mmio_map_phys(fb_addr, fb_size);
			if (!fb_va) {
				klogprintf("vbe: mmio_map_phys failed for addr=0x%016llx size=%u\n", (unsigned long long)fb_addr, (unsigned)fb_size);
				off += (tag_size + 7) & ~7u;
				continue;
			}

			/* parse RGB mask info if provided (framebuffer type 1 == RGB) */
			if (ftype == 1 && tag_size >= 40) {
				uint8_t rpos = *(uint8_t*)(p + off + 32);
				uint8_t rsize = *(uint8_t*)(p + off + 33);
				uint8_t gpos = *(uint8_t*)(p + off + 34);
				uint8_t gsize = *(uint8_t*)(p + off + 35);
				uint8_t bpos = *(uint8_t*)(p + off + 36);
				uint8_t bsize = *(uint8_t*)(p + off + 37);
				/* apply (with some sanity checks) */
				if (rsize > 0 && rsize <= 8) { g_rpos = rpos; g_rsize = rsize; }
				if (gsize > 0 && gsize <= 8) { g_gpos = gpos; g_gsize = gsize; }
				if (bsize > 0 && bsize <= 8) { g_bpos = bpos; g_bsize = bsize; }
				klogprintf("vbe: rgb mask rpos=%u rsize=%u gpos=%u gsize=%u bpos=%u bsize=%u\n",
					(unsigned)g_rpos, (unsigned)g_rsize, (unsigned)g_gpos, (unsigned)g_gsize, (unsigned)g_bpos, (unsigned)g_bsize);
			}

			if (width < 320 || height < 200 || bpp < 15) {
				// klogprintf("vbe: framebuffer looks like text mode (%ux%u bpp=%u) - skipping\n",
				// 	(unsigned)width, (unsigned)height, (unsigned)bpp);
				off += (tag_size + 7) & ~7u;
				continue;
			}

			/* avoid large backbuffer allocation to reduce heap pressure;
			   render directly into front buffer when possible */
			g_frontbuf = fb_va;
			g_backbuf = NULL;
			g_width = width;
			g_height = height;
			g_pitch = pitch;
			g_bpp = bpp;
			g_enabled = 1;
			klogprintf("vbe: framebuffer at %p %ux%u bpp=%u pitch=%u (backbuf %p)\n",
				(void*)(uintptr_t)fb_addr, width, height, (unsigned)g_bpp, (unsigned)g_pitch, g_backbuf);
			qemu_debug_printf("vbe: mapped fb_phys=%p -> fb_va=%p backbuf=%p width=%u height=%u bpp=%u pitch=%u\n",
				(void*)(uintptr_t)fb_addr, fb_va, g_backbuf, (unsigned)width, (unsigned)height, (unsigned)bpp, (unsigned)pitch);
			/* Quick visual sanity test: fill first few scanlines with color bars if 32bpp */
			if (g_bpp == 32 && g_frontbuf) {
				uint32_t *fbp = (uint32_t*)g_frontbuf;
				uint32_t scan = g_pitch / 4;
				for (uint32_t y2 = 0; y2 < (g_height < 64 ? g_height : 64); y2++) {
					uint32_t color;
					if ((y2 / 16) % 3 == 0) color = 0x00FF0000; /* red */
					else if ((y2 / 16) % 3 == 1) color = 0x0000FF00; /* green */
					else color = 0x000000FF; /* blue */
					for (uint32_t x2 = 0; x2 < g_width; x2++) {
						fbp[y2 * scan + x2] = color;
					}
				}
			}
			return 1;
		}

		off += (tag_size + 7) & ~7u;
	}
	klogprintf("vbe: no framebuffer tag found in multiboot info\n");
	return 0;
}


