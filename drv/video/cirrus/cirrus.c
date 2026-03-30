#include <cirrus.h>
#include <cirrusfb.h>
#include <fbdev.h>
#include <klog.h>
#include <mmio.h>
#include <pci.h>
#include <serial.h>
#include <string.h>

#define CIRRUS_VENDOR_ID 0x1013
#define CIRRUS_BAR0_OFF  0x10

#define BGA_INDEX_PORT 0x01CE
#define BGA_DATA_PORT  0x01CF
#define BGA_IDX_ID         0x0
#define BGA_IDX_XRES       0x1
#define BGA_IDX_YRES       0x2
#define BGA_IDX_BPP        0x3
#define BGA_IDX_ENABLE     0x4
#define BGA_IDX_BANK       0x5
#define BGA_IDX_VIRT_WIDTH 0x6
#define BGA_IDX_X_OFFSET   0x8
#define BGA_IDX_Y_OFFSET   0x9
#define BGA_EN_ENABLED 0x01
#define BGA_EN_LFB     0x40
#define BGA_EN_NOCLEAR 0x80

#define VGA_MISC_W 0x3C2
#define VGA_MISC_R 0x3CC
#define VGA_SEQ_I  0x3C4
#define VGA_SEQ_D  0x3C5
#define VGA_GFX_I  0x3CE
#define VGA_GFX_D  0x3CF
#define VGA_CRT_I  0x3D4
#define VGA_CRT_D  0x3D5
#define VGA_INSTAT1 0x3DA
#define VGA_ATTR_IW 0x3C0
#define VGA_PEL_MASK 0x3C6

#define CL_SEQR6   0x06
#define CL_SEQR7   0x07
#define CL_SEQRF   0x0F
#define CL_SEQR17  0x17
#define CL_CRT1A   0x1A
#define CL_CRT1B   0x1B
#define CL_CRT1D   0x1D

typedef struct {
	uint8_t bus;
	uint8_t device;
	uint8_t function;
	uint64_t fb_pa;
	uint32_t fb_len;
	uint32_t width;
	uint32_t height;
	uint32_t pitch;
	uint32_t bpp;
	int present;
	int registered;
} cirrus_ctx_t;

static cirrus_ctx_t g_cirrus_ctx;

typedef struct {
	uint16_t width;
	uint16_t height;
	uint16_t bpp;
	uint16_t right_margin;
	uint16_t hsync_len;
	uint16_t left_margin;
	uint16_t lower_margin;
	uint16_t vsync_len;
	uint16_t upper_margin;
	uint8_t pos_hsync;
	uint8_t pos_vsync;
} cirrus_mode_t;

static uint8_t vga_rseq(uint8_t idx) {
	outb(VGA_SEQ_I, idx);
	return inb(VGA_SEQ_D);
}

static void vga_wseq(uint8_t idx, uint8_t val) {
	outb(VGA_SEQ_I, idx);
	outb(VGA_SEQ_D, val);
}

static void vga_wcrt(uint8_t idx, uint8_t val) {
	outb(VGA_CRT_I, idx);
	outb(VGA_CRT_D, val);
}

static void vga_wgfx(uint8_t idx, uint8_t val) {
	outb(VGA_GFX_I, idx);
	outb(VGA_GFX_D, val);
}

static void cirrus_hidden_dac_write(uint8_t val) {
	(void)inb(VGA_PEL_MASK);
	(void)inb(VGA_PEL_MASK);
	(void)inb(VGA_PEL_MASK);
	(void)inb(VGA_PEL_MASK);
	outb(VGA_PEL_MASK, val);
}

static void cirrus_attr_on(void) {
	(void)inb(VGA_INSTAT1);
	outb(VGA_ATTR_IW, 0x20);
}

static void cirrus_unlock_registers(void) {
	/* Unlock Cirrus extension and VGA CRTC protected registers. */
	vga_wseq(CL_SEQR6, 0x12);
	vga_wcrt(0x11, 0x20);
}

static uint16_t bga_read(uint16_t index) {
	outports(BGA_INDEX_PORT, index);
	return inports(BGA_DATA_PORT);
}

static void bga_write(uint16_t index, uint16_t value) {
	outports(BGA_INDEX_PORT, index);
	outports(BGA_DATA_PORT, value);
}

static uint32_t cirrus_read_bar_size(const pci_device_t *dev, int bar_idx) {
	if (!dev || bar_idx < 0 || bar_idx > 5) return 0;
	uint8_t bar_off = (uint8_t)(CIRRUS_BAR0_OFF + bar_idx * 4);
	uint32_t original = pci_config_read_dword(dev->bus, dev->device, dev->function, bar_off);
	if ((original & 0x1u) != 0 || (original & ~0xFu) == 0) return 0;
	pci_config_write_dword(dev->bus, dev->device, dev->function, bar_off, 0xFFFFFFFFu);
	uint32_t mask = pci_config_read_dword(dev->bus, dev->device, dev->function, bar_off);
	pci_config_write_dword(dev->bus, dev->device, dev->function, bar_off, original);
	mask &= ~0xFu;
	if (mask == 0) return 0;
	return (uint32_t)(~mask + 1u);
}

static int cirrus_program_mode(const cirrus_mode_t *m) {
	if (!m || m->bpp != 16) return -1;

	uint32_t xres = m->width;
	uint32_t yres = m->height;
	uint32_t hsyncstart = xres + m->right_margin;
	uint32_t hsyncend = hsyncstart + m->hsync_len;
	uint32_t htotal = hsyncend + m->left_margin;
	uint32_t vdispend = yres;
	uint32_t vsyncstart = vdispend + m->lower_margin;
	uint32_t vsyncend = vsyncstart + m->vsync_len;
	uint32_t vtotal = vsyncend + m->upper_margin;

	/* Linux cirrusfb-compatible VGA timing transform (8-pixel granularity). */
	htotal /= 8;
	uint32_t hdisp = xres / 8;
	hsyncstart /= 8;
	hsyncend /= 8;

	htotal -= 5;
	hdisp -= 1;
	hsyncstart += 1;
	hsyncend += 1;

	vdispend -= 1;
	vsyncstart -= 1;
	vsyncend -= 1;
	vtotal -= 2;

	cirrus_unlock_registers();

	vga_wcrt(0x00, (uint8_t)htotal);
	vga_wcrt(0x01, (uint8_t)hdisp);
	vga_wcrt(0x02, (uint8_t)(xres / 8));
	vga_wcrt(0x03, (uint8_t)(0x80u + ((htotal + 5u) & 0x1Fu)));
	vga_wcrt(0x04, (uint8_t)hsyncstart);
	{
		uint8_t c5 = (uint8_t)(hsyncend & 0x1Fu);
		if ((htotal + 5u) & 0x20u) c5 |= 0x80u;
		vga_wcrt(0x05, c5);
	}
	vga_wcrt(0x06, (uint8_t)(vtotal & 0xFFu));
	{
		uint8_t c7 = 0x10u;
		if (vtotal & 0x100u) c7 |= 0x01u;
		if (vdispend & 0x100u) c7 |= 0x02u;
		if (vsyncstart & 0x100u) c7 |= 0x04u;
		if ((vdispend + 1u) & 0x100u) c7 |= 0x08u;
		if (vtotal & 0x200u) c7 |= 0x20u;
		if (vdispend & 0x200u) c7 |= 0x40u;
		if (vsyncstart & 0x200u) c7 |= 0x80u;
		vga_wcrt(0x07, c7);
	}
	vga_wcrt(0x09, (uint8_t)(0x40u | (((vdispend + 1u) & 0x200u) ? 0x20u : 0)));
	vga_wcrt(0x10, (uint8_t)(vsyncstart & 0xFFu));
	vga_wcrt(0x11, (uint8_t)(0x60u | (vsyncend & 0x0Fu)));
	vga_wcrt(0x12, (uint8_t)(vdispend & 0xFFu));
	vga_wcrt(0x15, (uint8_t)((vdispend + 1u) & 0xFFu));
	vga_wcrt(0x16, (uint8_t)(vtotal & 0xFFu));
	vga_wcrt(0x18, 0xFF);

	{
		uint8_t c1a = 0;
		if ((htotal + 5u) & 0x40u) c1a |= 0x10u;
		if ((htotal + 5u) & 0x80u) c1a |= 0x20u;
		if (vtotal & 0x100u) c1a |= 0x40u;
		if (vtotal & 0x200u) c1a |= 0x80u;
		vga_wcrt(CL_CRT1A, c1a);
	}

	/* 16bpp packed pixel mode for CLGD54xx family. */
	vga_wseq(CL_SEQR7, 0xA7);
	vga_wgfx(0x05, 0x40);
	cirrus_hidden_dac_write(0xC1);

	/* Enable MMIO path on PCI and use PCI BAR mapping. */
	{
		uint8_t sr17 = vga_rseq(CL_SEQR17);
		sr17 &= 0x80u;
		sr17 |= 0x64u; /* PCI bus + MMIO enable + use PCI base for MMIO */
		vga_wseq(CL_SEQR17, sr17);
	}

	{
		uint32_t pitch_bytes = (uint32_t)m->width * 2u;
		uint16_t pitch_qwords = (uint16_t)(pitch_bytes >> 3);
		vga_wcrt(0x13, (uint8_t)(pitch_qwords & 0xFFu));
		{
			uint8_t c1b = 0x22u;
			if (pitch_qwords & 0x100u) c1b |= 0x10u;
			vga_wcrt(CL_CRT1B, c1b);
		}
		vga_wcrt(CL_CRT1D, (uint8_t)((pitch_qwords >> 9) & 0x01u));
	}

	{
		uint8_t misc = 0x0Fu; /* color + enable mem + clock select */
		if (m->pos_hsync) misc |= 0x40u;
		if (m->pos_vsync) misc |= 0x80u;
		outb(VGA_MISC_W, misc);
	}

	cirrus_attr_on();
	return 0;
}

static int cirrus_set_best_mode(uint32_t vram_bytes, uint32_t *w, uint32_t *h, uint32_t *bpp, uint32_t *pitch) {
	static const struct {
		uint16_t width;
		uint16_t height;
		uint16_t bits;
	} candidates[] = {
		{1920, 1080, 32}, {1600, 1200, 32}, {1440, 900, 32}, {1366, 768, 32},
		{1280, 1024, 32}, {1280, 800, 32}, {1024, 768, 32}, {800, 600, 32},
		{1920, 1080, 24}, {1600, 1200, 24}, {1440, 900, 24}, {1366, 768, 24},
		{1280, 1024, 24}, {1280, 800, 24}, {1024, 768, 24}, {800, 600, 24},
		{1280, 1024, 16}, {1280, 800, 16}, {1024, 768, 16}, {800, 600, 16},
		{640, 480, 32}, {640, 480, 24}, {640, 480, 16}
	};

	for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
		uint32_t bytespp = (uint32_t)candidates[i].bits / 8u;
		uint32_t needed = (uint32_t)candidates[i].width * (uint32_t)candidates[i].height * bytespp;
		if (vram_bytes && needed > vram_bytes) continue;

		bga_write(BGA_IDX_ENABLE, 0);
		bga_write(BGA_IDX_XRES, candidates[i].width);
		bga_write(BGA_IDX_YRES, candidates[i].height);
		bga_write(BGA_IDX_BPP, candidates[i].bits);
		bga_write(BGA_IDX_VIRT_WIDTH, candidates[i].width);
		bga_write(BGA_IDX_X_OFFSET, 0);
		bga_write(BGA_IDX_Y_OFFSET, 0);
		bga_write(BGA_IDX_BANK, 0);
		bga_write(BGA_IDX_ENABLE, BGA_EN_ENABLED | BGA_EN_LFB | BGA_EN_NOCLEAR);

		uint16_t rw = bga_read(BGA_IDX_XRES);
		uint16_t rh = bga_read(BGA_IDX_YRES);
		uint16_t rbpp = bga_read(BGA_IDX_BPP);
		if (rw == candidates[i].width && rh == candidates[i].height && rbpp == candidates[i].bits) {
			*w = (uint32_t)rw;
			*h = (uint32_t)rh;
			*bpp = (uint32_t)rbpp;
			*pitch = (uint32_t)rw * bytespp;
			return 0;
		}
	}
	return -1;
}

static int cirrus_set_best_native_mode(uint32_t vram_bytes, uint32_t *w, uint32_t *h, uint32_t *bpp, uint32_t *pitch) {
	static const cirrus_mode_t modes[] = {
		/* Try high to low; use 16bpp for broad CLGD54xx compatibility. */
		{1280, 1024, 16, 48, 112, 248, 1, 3, 38, 1, 1},
		{1024,  768, 16, 24, 136, 160, 3, 6, 29, 0, 0},
		{ 800,  600, 16, 40, 128,  88, 1, 4, 23, 1, 1},
		{ 640,  480, 16, 16,  96,  48,10, 2, 33, 0, 0},
	};

	for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
		const cirrus_mode_t *m = &modes[i];
		uint32_t need = (uint32_t)m->width * (uint32_t)m->height * 2u;
		if (vram_bytes && need > vram_bytes) continue;
		if (cirrus_program_mode(m) != 0) continue;
		*w = m->width;
		*h = m->height;
		*bpp = m->bpp;
		*pitch = (uint32_t)m->width * 2u;
		return 0;
	}
	return -1;
}

static int cirrus_init(video_device_t *dev) {
	if (!dev || !g_cirrus_ctx.present) return -1;
	dev->mmio_pa = g_cirrus_ctx.fb_pa;
	if (dev->mmio_pa && dev->mmio_base == NULL) {
		void *va = mmio_map_phys(dev->mmio_pa, g_cirrus_ctx.fb_len);
		if (!va) {
			klogprintf("cirrus: mmio_map_phys failed pa=0x%llx len=%u\n",
			           (unsigned long long)dev->mmio_pa, (unsigned)g_cirrus_ctx.fb_len);
			return -1;
		}
		dev->mmio_base = va;
	}
	dev->width = g_cirrus_ctx.width;
	dev->height = g_cirrus_ctx.height;
	dev->bpp = g_cirrus_ctx.bpp;
	dev->pitch = g_cirrus_ctx.pitch;
	return 0;
}

static void cirrus_shutdown(video_device_t *dev) {
	(void)dev;
}

static void cirrus_flush_region(video_device_t *dev, uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
	(void)dev; (void)x; (void)y; (void)w; (void)h;
}

static int cirrus_set_mode(video_device_t *dev, uint32_t width, uint32_t height, uint32_t bpp) {
	(void)dev; (void)width; (void)height; (void)bpp;
	return -1;
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

static int s_cirrus_kernel_inited;

int cirrus_kernel_init(void) {
	if (s_cirrus_kernel_inited)
		return 0;

	pci_device_t *devs = pci_get_devices();
	int count = pci_get_device_count();
	pci_device_t *cirrus = NULL;
	int was_registered = g_cirrus_ctx.registered;

	memset(&g_cirrus_ctx, 0, sizeof(g_cirrus_ctx));
	g_cirrus_ctx.registered = was_registered;

	for (int i = 0; i < count; i++) {
		pci_device_t *d = &devs[i];
		if (d->vendor_id == CIRRUS_VENDOR_ID && d->class_code == 0x03) {
			cirrus = d;
			break;
		}
	}
	if (!cirrus) return -1;

	uint32_t bar0 = cirrus->bar[0];
	if ((bar0 & 0x1u) != 0 || (bar0 & ~0xFu) == 0) return -1;

	uint32_t cmdreg = pci_config_read_dword(cirrus->bus, cirrus->device, cirrus->function, 0x04);
	if ((cmdreg & 0x2u) == 0) {
		cmdreg |= 0x2u;
		pci_config_write_dword(cirrus->bus, cirrus->device, cirrus->function, 0x04, cmdreg);
	}

	uint16_t bga_id = bga_read(BGA_IDX_ID);
	g_cirrus_ctx.bus = cirrus->bus;
	g_cirrus_ctx.device = cirrus->device;
	g_cirrus_ctx.function = cirrus->function;
	g_cirrus_ctx.fb_pa = (uint64_t)(bar0 & ~0xFu);
	g_cirrus_ctx.fb_len = cirrus_read_bar_size(cirrus, 0);
	if (g_cirrus_ctx.fb_len == 0) g_cirrus_ctx.fb_len = 4u * 1024u * 1024u;

	/* Prefer BGA/Bochs modeset when possible: readback validation inside
	   cirrus_set_best_mode() is more reliable than strict ID matching. */
	if (cirrus_set_best_mode(g_cirrus_ctx.fb_len, &g_cirrus_ctx.width, &g_cirrus_ctx.height,
	                         &g_cirrus_ctx.bpp, &g_cirrus_ctx.pitch) != 0) {
		/* Native Cirrus path (cirrusfb-style register programming), no VBE dependency. */
		if (cirrus_set_best_native_mode(g_cirrus_ctx.fb_len, &g_cirrus_ctx.width, &g_cirrus_ctx.height,
		                                &g_cirrus_ctx.bpp, &g_cirrus_ctx.pitch) != 0) {
			klogprintf("cirrus: no usable modeset path (BGA id=0x%04x)\n", bga_id);
			return -1;
		}
		klogprintf("cirrus: native mode set to %ux%u@%u (BGA id=0x%04x)\n",
		           (unsigned)g_cirrus_ctx.width, (unsigned)g_cirrus_ctx.height,
		           (unsigned)g_cirrus_ctx.bpp, bga_id);
	} else {
		klogprintf("cirrus: BGA mode set to %ux%u@%u (id=0x%04x)\n",
		           (unsigned)g_cirrus_ctx.width, (unsigned)g_cirrus_ctx.height,
		           (unsigned)g_cirrus_ctx.bpp, bga_id);
	}

	g_cirrus_ctx.present = 1;
	if (!g_cirrus_ctx.registered) {
		if (cirrus_driver_register() != 0) return -1;
		g_cirrus_ctx.registered = 1;
	}
	if (video_probe_all() <= 0) return -1;

	video_device_t *vd = video_find_by_name("cirrus");
	if (!vd || !vd->mmio_base) return -1;
	if (cirrusfb_init(vd->mmio_base, vd->width, vd->height, vd->pitch, vd->bpp, g_cirrus_ctx.fb_len, 1) != 0)
		return -1;

	{
		size_t vis = (size_t)vd->pitch * (size_t)vd->height * ((size_t)vd->bpp / 8u);
		if (vis > (size_t)g_cirrus_ctx.fb_len) vis = (size_t)g_cirrus_ctx.fb_len;
		fbdev_register_linear(vd->mmio_base, g_cirrus_ctx.fb_pa, vis,
		                      vd->width, vd->height, vd->pitch, vd->bpp);
	}

	klogprintf("cirrus: ready %02x:%02x.%u mode=%ux%u@%u fb=%p pa=0x%llx len=%u\n",
	           g_cirrus_ctx.bus, g_cirrus_ctx.device, g_cirrus_ctx.function,
	           (unsigned)vd->width, (unsigned)vd->height, (unsigned)vd->bpp,
	           vd->mmio_base, (unsigned long long)g_cirrus_ctx.fb_pa, (unsigned)g_cirrus_ctx.fb_len);
	s_cirrus_kernel_inited = 1;
	return 0;
}



