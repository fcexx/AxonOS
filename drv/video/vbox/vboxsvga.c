/*
 * VirtualBox SVGA (VBoxSVGA) — minimal 2D linear framebuffer.
 *
 * This is intentionally very close to the existing VMware SVGA II driver
 * (`drv/video/vmware/vmwgfx_drv.c`), because VBoxSVGA exposes an SVGA-like
 * register + FIFO ABI sufficient for simple 2D scanout (UPDATE rectangles).
 *
 * Scope:
 * - 32bpp linear framebuffer in VRAM
 * - FIFO ring with SVGA_CMD_UPDATE + SVGA_REG_SYNC flush
 * - no 3D, no cursor, no IRQ usage
 */
#include <vboxsvga.h>
#include <cirrusfb.h>
#include <fbdev.h>
#include <video.h>
#include <klog.h>
#include <mmio.h>
#include <pci.h>
#include <string.h>
#include <stddef.h>
#include <vga.h>
#include <heap.h>

#if defined(__GNUC__) || defined(__clang__)
#define vboxsvga_io_barrier() __asm__ volatile("" ::: "memory")
#else
#define vboxsvga_io_barrier() ((void)0)
#endif

#define VBOX_PCI_VENDOR_ID 0x80EE

#define SVGA_MAGIC        0x900000UL
#define SVGA_MAKE_ID(ver) ((SVGA_MAGIC << 8) | (unsigned long)(ver))
#define SVGA_ID_0         SVGA_MAKE_ID(0)
#define SVGA_ID_1         SVGA_MAKE_ID(1)
#define SVGA_ID_2         SVGA_MAKE_ID(2)
#define SVGA_ID_3         SVGA_MAKE_ID(3)

enum svga_reg {
	SVGA_REG_ID = 0,
	SVGA_REG_ENABLE = 1,
	SVGA_REG_WIDTH = 2,
	SVGA_REG_HEIGHT = 3,
	SVGA_REG_MAX_WIDTH = 4,
	SVGA_REG_MAX_HEIGHT = 5,
	SVGA_REG_DEPTH = 6,
	SVGA_REG_BITS_PER_PIXEL = 7,
	SVGA_REG_BYTES_PER_LINE = 12,
	SVGA_REG_FB_START = 13,
	SVGA_REG_FB_OFFSET = 14,
	SVGA_REG_VRAM_SIZE = 15,
	SVGA_REG_FB_SIZE = 16,
	SVGA_REG_CAPABILITIES = 17,
	SVGA_REG_MEM_START = 18,
	SVGA_REG_MEM_SIZE = 19,
	SVGA_REG_CONFIG_DONE = 20,
	SVGA_REG_SYNC = 21,
	SVGA_REG_BUSY = 22,
	SVGA_REG_GUEST_ID = 23,
	SVGA_REG_MEM_REGS = 30,
};

enum svga_fifo {
	SVGA_FIFO_MIN = 0,
	SVGA_FIFO_MAX = 1,
	SVGA_FIFO_NEXT = 2,
	SVGA_FIFO_STOP = 3,
};

#define SVGA_CMD_UPDATE 1u

#define SVGA_FIFO_QUEUE_START_BYTES (291u * 4u)
#define SVGA_FIFO_MIN_QUEUE_ROOM      (10u * 1024u)
#define SVGA_FIFO_HOST_MAX_BYTES      0x10000u

#define SVGA_DEFAULT_FIFO_BYTES 0x10000u

typedef struct {
	uint8_t bus;
	uint8_t device;
	uint8_t function;
	uint16_t pci_device_id;

	void *regs_va;
	int regs_mmio_linear; /* 0 = index/value dword pair; 1 = linear reg file */

	void *fifo_va;
	void *fb_va;
	uint64_t fb_pa;
	uint32_t fb_len;
	uint32_t fifo_len;

	uint32_t width;
	uint32_t height;
	uint32_t pitch;
	uint32_t bpp;
	uint32_t fb_offset;

	/* When regs are embedded inside FB/FIFO BAR, this is the physical base. */
	uint64_t regs_mmio_pa;

	int scanout_on;
	int present;
	int registered;
} vboxsvga_ctx_t;

static vboxsvga_ctx_t g_vbox;
static int s_vbox_kernel_inited;

static uint32_t vboxsvga_pci_mem_bar_size(const pci_device_t *pdev, int bar_idx) {
	if (!pdev || bar_idx < 0 || bar_idx > 5)
		return 0;
	uint8_t bar_off = (uint8_t)(0x10 + bar_idx * 4);
	uint32_t orig = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, bar_off);
	if ((orig & 0x1u) != 0 || (orig & ~0xFu) == 0)
		return 0;
	pci_config_write_dword(pdev->bus, pdev->device, pdev->function, bar_off, 0xFFFFFFFFu);
	uint32_t mask = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, bar_off);
	pci_config_write_dword(pdev->bus, pdev->device, pdev->function, bar_off, orig);
	mask &= ~0xFu;
	if (mask == 0)
		return 0;
	return (uint32_t)(~mask + 1u);
}

static void *vboxsvga_kmalloc_aligned(size_t size, size_t align, void **out_raw) {
	if (!out_raw || align == 0)
		return NULL;
	void *raw = kmalloc(size + align);
	if (!raw)
		return NULL;
	uintptr_t p = (uintptr_t)raw;
	uintptr_t aligned = (p + (uintptr_t)align - 1u) & ~((uintptr_t)align - 1u);
	*out_raw = raw;
	return (void *)aligned;
}

static uint64_t vboxsvga_pci_mem64_bar_size(const pci_device_t *pdev, int bar_idx) {
	if (!pdev || bar_idx < 0 || bar_idx + 1 > 5)
		return 0;
	uint8_t off = (uint8_t)(0x10 + bar_idx * 4);
	uint32_t ol = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, off);
	uint32_t oh = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, off + 4);
	if ((ol & 0x1u) != 0 || ((ol >> 1) & 3u) != 2u)
		return 0;
	pci_config_write_dword(pdev->bus, pdev->device, pdev->function, off, 0xFFFFFFFFu);
	pci_config_write_dword(pdev->bus, pdev->device, pdev->function, off + 4, 0xFFFFFFFFu);
	uint32_t ml = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, off);
	uint32_t mh = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, off + 4);
	pci_config_write_dword(pdev->bus, pdev->device, pdev->function, off, ol);
	pci_config_write_dword(pdev->bus, pdev->device, pdev->function, off + 4, oh);
	uint64_t mask = ((uint64_t)mh << 32) | (uint64_t)(ml & ~0xFULL);
	if (mask == 0)
		return 0;
	return (~mask + 1u) & ~(uint64_t)0xFULL;
}

typedef struct {
	uint64_t pa;
	uint64_t size;
	int bar_lo;
} vboxsvga_mem_region_t;

static int vboxsvga_collect_mem_regions(const pci_device_t *p, vboxsvga_mem_region_t *out, int max_out) {
	int n = 0;
	for (int i = 0; i < 6; ) {
		uint32_t lo = p->bar[i];
		if (lo & 1u) {
			i++;
			continue;
		}
		if ((lo & ~0xFu) == 0) {
			i++;
			continue;
		}
		int typ = (int)((lo >> 1) & 3u);
		uint64_t pa;
		int cons = 1;
		if (typ == 2) {
			if (i + 1 >= 6)
				break;
			uint32_t hi = p->bar[i + 1];
			pa = ((uint64_t)hi << 32) | (uint64_t)(lo & ~0xFULL);
			cons = 2;
		} else {
			pa = (uint64_t)(lo & ~0xFULL);
		}
		uint64_t sz = 0;
		if (cons == 2)
			sz = vboxsvga_pci_mem64_bar_size(p, i);
		else
			sz = (uint64_t)vboxsvga_pci_mem_bar_size(p, i);
		if (sz == 0)
			sz = 65536ull;
		out[n].pa = pa;
		out[n].size = sz;
		out[n].bar_lo = i;
		n++;
		if (n >= max_out)
			break;
		i += cons;
	}
	return n;
}

static void vboxsvga_mem_region_sort_by_size_asc(vboxsvga_mem_region_t *r, int *order, int n) {
	for (int i = 0; i < n; i++)
		order[i] = i;
	for (int a = 0; a < n - 1; a++) {
		for (int b = a + 1; b < n; b++) {
			if (r[order[b]].size < r[order[a]].size) {
				int t = order[a];
				order[a] = order[b];
				order[b] = t;
			}
		}
	}
}

static int vboxsvga_mmio_regs_verify_window(volatile uint32_t *reg) {
	for (int n = 0; n < 120; n++) {
		reg[0] = SVGA_REG_ID;
		reg[1] = (uint32_t)SVGA_ID_2;
		reg[0] = SVGA_REG_ID;
		uint32_t id = reg[1];
		if (id == 0xffffffffu || id == 0)
			continue;
		if (id != (uint32_t)SVGA_ID_2 && id != (uint32_t)SVGA_ID_1 &&
		    (id == (uint32_t)SVGA_ID_0 || (id >> 8) != (uint32_t)SVGA_MAGIC))
			continue;
		reg[0] = SVGA_REG_MAX_WIDTH;
		uint32_t mw = reg[1];
		reg[0] = SVGA_REG_MAX_HEIGHT;
		uint32_t mh = reg[1];
		if (mw == 0xffffffffu || mh == 0xffffffffu)
			continue;
		int geom_ok = 0;
		if (mw >= 320u && mw <= 16384u && mh >= 240u && mh <= 16384u) {
			reg[0] = SVGA_REG_MAX_WIDTH;
			if (reg[1] == mw)
				geom_ok = 1;
		} else if (mw == 0u && mh == 0u) {
			reg[0] = SVGA_REG_ID;
			reg[1] = (uint32_t)SVGA_ID_2;
			reg[0] = SVGA_REG_ID;
			uint32_t id2 = reg[1];
			geom_ok = (id2 == id && id != (uint32_t)SVGA_ID_0);
		}
		if (!geom_ok) {
			reg[0] = SVGA_REG_DEPTH;
			uint32_t dep = reg[1];
			if (dep != 0xffffffffu &&
			    (dep == 15u || dep == 16u || dep == 24u || dep == 32u)) {
				reg[0] = SVGA_REG_DEPTH;
				if (reg[1] == dep)
					geom_ok = 1;
			}
		}
		if (!geom_ok)
			continue;
		return 1;
	}
	return 0;
}

/* Linear register file probe (SVGA3-style): reg[index] directly. */
static int vboxsvga_mmio_regs_verify_linear(volatile uint32_t *reg) {
	for (int n = 0; n < 120; n++) {
		reg[SVGA_REG_ID] = (uint32_t)SVGA_ID_2;
		uint32_t id = reg[SVGA_REG_ID];
		if (id == 0xffffffffu || id == 0)
			continue;
		if (id != (uint32_t)SVGA_ID_2 && id != (uint32_t)SVGA_ID_1 &&
		    (id == (uint32_t)SVGA_ID_0 || (id >> 8) != (uint32_t)SVGA_MAGIC))
			continue;
		uint32_t mw = reg[SVGA_REG_MAX_WIDTH];
		uint32_t mh = reg[SVGA_REG_MAX_HEIGHT];
		if (mw == 0xffffffffu || mh == 0xffffffffu)
			continue;
		if (mw >= 320u && mw <= 16384u && mh >= 240u && mh <= 16384u)
			return 1;
	}
	return 0;
}

/*
 * Scan a memory region for a dword index/value window. This is robust against
 * cases where the SVGA window is not page-aligned inside a larger BAR.
 */
static int vboxsvga_scan_bar_for_reg_window(uint64_t pa, uint64_t bar_sz, size_t *reg_off_out) {
	size_t scan = (size_t)bar_sz;
	const size_t cap = 4u * 1024u * 1024u;
	if (scan > cap)
		scan = cap;
	if (scan < 16)
		return 0;
	void *va = mmio_map_phys(pa, scan);
	if (!va)
		return 0;
	int found = 0;
	const size_t fine_lim = (scan > 256u * 1024u) ? 256u * 1024u : scan;

	for (size_t off = 0; off + 8 <= fine_lim; off += 4u) {
		volatile uint32_t *reg = (volatile uint32_t *)((uint8_t *)va + off);
		if (!vboxsvga_mmio_regs_verify_window(reg))
			continue;
		*reg_off_out = off;
		found = 1;
		goto out;
	}

	size_t coarse = fine_lim;
	if ((coarse & 4095u) != 0)
		coarse = (coarse + 4095u) & ~(size_t)4095u;
	for (size_t off = coarse; off + 8 <= scan; off += 4096u) {
		volatile uint32_t *reg = (volatile uint32_t *)((uint8_t *)va + off);
		if (!vboxsvga_mmio_regs_verify_window(reg))
			continue;
		*reg_off_out = off;
		found = 1;
		break;
	}
out:
	mmio_unmap(va, scan);
	return found;
}

static uint32_t svga_reg_read32(const vboxsvga_ctx_t *ctx, uint32_t index) {
	volatile uint32_t *r = (volatile uint32_t *)ctx->regs_va;
	if (ctx->regs_mmio_linear)
		return r[index];
	r[0] = index;
	return r[1];
}

static void svga_reg_write32(const vboxsvga_ctx_t *ctx, uint32_t index, uint32_t value) {
	volatile uint32_t *r = (volatile uint32_t *)ctx->regs_va;
	if (ctx->regs_mmio_linear) {
		r[index] = value;
		return;
	}
	r[0] = index;
	r[1] = value;
}

static void svga_sync_and_wait(vboxsvga_ctx_t *ctx) {
	/*
	 * VirtualBox tends to be pickier about completing SYNC before the frame becomes visible.
	 * Keep this bounded so we never hang the kernel if the host ignores BUSY.
	 */
	svga_reg_write32(ctx, SVGA_REG_SYNC, 1);
	for (int i = 0; i < 2000000; i++) {
		if (svga_reg_read32(ctx, SVGA_REG_BUSY) == 0)
			return;
#if defined(__GNUC__) || defined(__clang__)
		__asm__ volatile("pause");
#endif
	}
}

static int svga_negotiate_id(vboxsvga_ctx_t *ctx) {
	/* Try newer IDs first; accept downgrade if host refuses. */
	static const uint32_t ids[] = {
		(uint32_t)SVGA_ID_3,
		(uint32_t)SVGA_ID_2,
		(uint32_t)SVGA_ID_1,
	};
	for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
		svga_reg_write32(ctx, SVGA_REG_ID, ids[i]);
		uint32_t got = svga_reg_read32(ctx, SVGA_REG_ID);
		if (got == ids[i] || ((got >> 8) == (uint32_t)SVGA_MAGIC && got != (uint32_t)SVGA_ID_0)) {
			klogprintf("vboxsvga: negotiated SVGA ID=0x%08x\n", (unsigned)got);
			return 0;
		}
	}
	return -1;
}

static void svga_fifo_reset(vboxsvga_ctx_t *ctx) {
	volatile uint32_t *fifo = (volatile uint32_t *)ctx->fifo_va;
	uint32_t sz = ctx->fifo_len;
	if (!fifo || sz < 64)
		return;

	uint32_t nregs_dw = svga_reg_read32(ctx, SVGA_REG_MEM_REGS);
	uint32_t min = SVGA_FIFO_QUEUE_START_BYTES;
	if (nregs_dw >= 4u && nregs_dw <= 1024u)
		min = nregs_dw * 4u;

	uint32_t max = sz;
	if (max > SVGA_FIFO_HOST_MAX_BYTES)
		max = SVGA_FIFO_HOST_MAX_BYTES;
	if (max < min + SVGA_FIFO_MIN_QUEUE_ROOM)
		max = min + SVGA_FIFO_MIN_QUEUE_ROOM;
	if ((max & 3u) != 0)
		max &= ~3u;

	memset((void *)fifo, 0, (size_t)max);
	fifo[SVGA_FIFO_MIN] = min;
	fifo[SVGA_FIFO_MAX] = max;
	fifo[SVGA_FIFO_NEXT] = min;
	fifo[SVGA_FIFO_STOP] = min;
}

static int vboxsvga_setup_guest_fifo(vboxsvga_ctx_t *ctx) {
	if (!ctx || !ctx->regs_va)
		return -1;

	const uint32_t fifo_bytes = SVGA_DEFAULT_FIFO_BYTES; /* 64 KiB (host-friendly) */
	void *raw = NULL;
	void *fifo = vboxsvga_kmalloc_aligned((size_t)fifo_bytes, 4096u, &raw);
	if (!fifo)
		return -1;

	memset(fifo, 0, (size_t)fifo_bytes);

	/* Program guest-memory FIFO location (physical address). */
	uint64_t fifo_pa = (uint64_t)(uintptr_t)fifo;
	svga_reg_write32(ctx, SVGA_REG_MEM_START, (uint32_t)fifo_pa);
	svga_reg_write32(ctx, SVGA_REG_MEM_SIZE, fifo_bytes);

	ctx->fifo_va = fifo;
	ctx->fifo_len = fifo_bytes;

	klogprintf("vboxsvga: guest FIFO mem_start=0x%x mem_size=%u fifo_va=%p\n",
	           (unsigned)svga_reg_read32(ctx, SVGA_REG_MEM_START),
	           (unsigned)svga_reg_read32(ctx, SVGA_REG_MEM_SIZE),
	           ctx->fifo_va);
	(void)raw;
	return 0;
}

static int vboxsvga_fifo_append_u32(vboxsvga_ctx_t *ctx, uint32_t value) {
	volatile uint32_t *hdr = (volatile uint32_t *)ctx->fifo_va;
	if (!hdr)
		return -1;
	uint32_t mn = hdr[SVGA_FIFO_MIN];
	uint32_t mx = hdr[SVGA_FIFO_MAX];
	uint32_t nx = hdr[SVGA_FIFO_NEXT];
	uint32_t st = hdr[SVGA_FIFO_STOP];

	if (mn < 16u || mx <= mn || nx >= mx || st >= mx)
		return -1;

	/* Ensure at least 4 bytes free. */
	uint32_t room;
	if (nx >= st)
		room = (mx - nx) + (st - mn);
	else
		room = st - nx;
	if (room < 4u)
		return -1;

	uint8_t *base = (uint8_t *)ctx->fifo_va;
	*(volatile uint32_t *)(base + nx) = value;
	nx += 4u;
	if (nx >= mx)
		nx = mn;
	hdr[SVGA_FIFO_NEXT] = nx;
	vboxsvga_io_barrier();
	return 0;
}

static void vboxsvga_fifo_submit_update(vboxsvga_ctx_t *ctx, uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
	if (vboxsvga_fifo_append_u32(ctx, SVGA_CMD_UPDATE) != 0)
		return;
	if (vboxsvga_fifo_append_u32(ctx, x) != 0)
		return;
	if (vboxsvga_fifo_append_u32(ctx, y) != 0)
		return;
	if (vboxsvga_fifo_append_u32(ctx, w) != 0)
		return;
	(void)vboxsvga_fifo_append_u32(ctx, h);
}

static int svga_try_mode(vboxsvga_ctx_t *ctx, uint32_t w, uint32_t h, int leave_enabled) {
	if (!ctx || !ctx->regs_va || !ctx->fifo_va)
		return -1;

	svga_reg_write32(ctx, SVGA_REG_ENABLE, 0);
	svga_reg_write32(ctx, SVGA_REG_CONFIG_DONE, 0);

	svga_reg_write32(ctx, SVGA_REG_WIDTH, w);
	svga_reg_write32(ctx, SVGA_REG_HEIGHT, h);
	svga_reg_write32(ctx, SVGA_REG_BITS_PER_PIXEL, 32);
	svga_reg_write32(ctx, SVGA_REG_DEPTH, 24);

	svga_fifo_reset(ctx);
	svga_reg_write32(ctx, SVGA_REG_CONFIG_DONE, 1);

	uint32_t pitch = svga_reg_read32(ctx, SVGA_REG_BYTES_PER_LINE);
	if (pitch == 0 || pitch > (w * 16u)) /* sanity */
		return -1;

	ctx->width = w;
	ctx->height = h;
	ctx->bpp = 32;
	ctx->pitch = pitch;
	ctx->fb_offset = svga_reg_read32(ctx, SVGA_REG_FB_OFFSET);

	if (leave_enabled) {
		svga_reg_write32(ctx, SVGA_REG_ENABLE, 1);
		ctx->scanout_on = 1;
	} else {
		svga_reg_write32(ctx, SVGA_REG_ENABLE, 0);
		ctx->scanout_on = 0;
	}
	return 0;
}

static int vboxsvga_pick_mode(vboxsvga_ctx_t *ctx) {
	static const struct {
		uint32_t w, h;
	} modes[] = {
		{ 1280, 800 },
		{ 1024, 768 },
		{ 1366, 768 },
		{ 1280, 720 },
		{ 1920, 1080 },
		{ 1600, 1200 },
		{ 1440, 900 },
		{ 1280, 1024 },
		{ 800, 600 },
		{ 640, 480 },
		{ 720, 960 },
	};

	for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
		if (svga_try_mode(ctx, modes[i].w, modes[i].h, 0) == 0) {
			klogprintf("vboxsvga: mode %ux%u pitch=%u fb_off=0x%x (scanout off until fbcon)\n",
			           (unsigned)ctx->width, (unsigned)ctx->height,
			           (unsigned)ctx->pitch, (unsigned)ctx->fb_offset);
			return 0;
		}
	}
	return -1;
}

static int vboxsvga_init(video_device_t *dev) {
	if (!dev || !g_vbox.present)
		return -1;
	dev->mmio_pa = g_vbox.fb_pa;
	if (g_vbox.fb_va == NULL)
		return -1;
	dev->mmio_base = (uint8_t *)g_vbox.fb_va + g_vbox.fb_offset;
	dev->width = g_vbox.width;
	dev->height = g_vbox.height;
	dev->bpp = g_vbox.bpp;
	dev->pitch = g_vbox.pitch;
	return 0;
}

static void vboxsvga_shutdown(video_device_t *dev) {
	(void)dev;
}

static void vboxsvga_flush_region(video_device_t *dev, uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
	(void)dev;
	if (!g_vbox.present || !g_vbox.fifo_va || !g_vbox.scanout_on)
		return;
	if (w == 0 || h == 0)
		return;
	uint32_t fw = g_vbox.width;
	uint32_t fh = g_vbox.height;
	if (fw == 0 || fh == 0)
		return;
	if (x >= fw || y >= fh)
		return;
	if (x + w > fw)
		w = fw - x;
	if (y + h > fh)
		h = fh - y;
	vboxsvga_fifo_submit_update(&g_vbox, x, y, w, h);
}

static void vboxsvga_display_sync(video_device_t *dev) {
	(void)dev;
	if (!g_vbox.present || !g_vbox.scanout_on)
		return;
	svga_sync_and_wait(&g_vbox);
}

static int vboxsvga_set_mode(video_device_t *dev, uint32_t width, uint32_t height, uint32_t bpp) {
	(void)dev;
	if (bpp != 32)
		return -1;
	if (svga_try_mode(&g_vbox, width, height, 1) != 0)
		return -1;
	return 0;
}

static const video_ops_t vboxsvga_video_ops = {
	.init = vboxsvga_init,
	.shutdown = vboxsvga_shutdown,
	.flush_region = vboxsvga_flush_region,
	.display_sync = vboxsvga_display_sync,
	.set_mode = vboxsvga_set_mode,
};

static int vboxsvga_driver_register(void) {
	return video_register_driver("vboxsvga", &vboxsvga_video_ops, NULL);
}

static pci_device_t *vboxsvga_find_pci(void) {
	pci_device_t *list = pci_get_devices();
	int n = pci_get_device_count();
	for (int i = 0; i < n; i++) {
		pci_device_t *d = &list[i];
		if (d->vendor_id != VBOX_PCI_VENDOR_ID)
			continue;
		if (d->class_code == 0x03)
			return d;
		/* Some VirtualBox builds may report display class; keep vendor match as primary. */
		return d;
	}
	return NULL;
}

static int vboxsvga_probe_and_bind_regs(vboxsvga_ctx_t *ctx, uint64_t regs_pa, uint32_t regs_sz) {
	if (!ctx || regs_pa == 0)
		return -1;
	if (regs_sz < 8u)
		regs_sz = 0x1000u;
	ctx->regs_va = mmio_map_phys(regs_pa, (size_t)regs_sz);
	if (!ctx->regs_va)
		return -1;

	/* Prefer index/value window; fallback to linear reg file if it looks like SVGA3 style. */
	if (vboxsvga_mmio_regs_verify_window((volatile uint32_t *)ctx->regs_va)) {
		ctx->regs_mmio_linear = 0;
		return 0;
	}
	if (vboxsvga_mmio_regs_verify_linear((volatile uint32_t *)ctx->regs_va)) {
		ctx->regs_mmio_linear = 1;
		return 0;
	}

	mmio_unmap(ctx->regs_va, (size_t)regs_sz);
	ctx->regs_va = NULL;
	return -1;
}

/*
 * Assign BARs for regs/fb/fifo.
 * Strategy:
 * - If BAR0 looks like SVGA regs at base: treat as dedicated regs BAR, and choose
 *   remaining BARs by size (largest=FB, smallest=FIFO).
 * - Otherwise: scan memory BARs for an embedded index/value regs window; then pick
 *   FB/FIFO similarly (two-region and three-region cases).
 */
static int vboxsvga_bind_from_pci(vboxsvga_ctx_t *ctx, pci_device_t *pdev,
                                 uint64_t *fb_pa_out, uint64_t *fifo_pa_out) {
	if (!ctx || !pdev || !fb_pa_out || !fifo_pa_out)
		return -1;

	*fb_pa_out = 0;
	*fifo_pa_out = 0;

	klogprintf("vboxsvga: pci %02x:%02x.%u dev=%04x:%04x class=%02x/%02x prog_if=%02x\n",
	           pdev->bus, pdev->device, pdev->function,
	           (unsigned)pdev->vendor_id, (unsigned)pdev->device_id,
	           (unsigned)pdev->class_code, (unsigned)pdev->subclass, (unsigned)pdev->prog_if);
	for (int i = 0; i < 6; i++) {
		uint32_t b = pdev->bar[i];
		if ((b & ~0xFu) == 0) {
			klogprintf("vboxsvga: BAR%d: %08x\n", i, (unsigned)b);
			continue;
		}
		if (b & 1u)
			klogprintf("vboxsvga: BAR%d: I/O  %08x\n", i, (unsigned)b);
		else
			klogprintf("vboxsvga: BAR%d: MEM  %08x\n", i, (unsigned)b);
	}

	uint32_t bar0 = pdev->bar[0];
	if ((bar0 & 1u) == 0 && (bar0 & ~0xFu) != 0) {
		uint64_t regs_pa = (uint64_t)(bar0 & ~0xFULL);
		uint32_t regs_sz = vboxsvga_pci_mem_bar_size(pdev, 0);
		if (vboxsvga_probe_and_bind_regs(ctx, regs_pa, regs_sz) == 0) {
			klogprintf("vboxsvga: regs at BAR0 pa=0x%llx\n", (unsigned long long)regs_pa);
		}
	}

	vboxsvga_mem_region_t mr[6];
	int nm = vboxsvga_collect_mem_regions(pdev, mr, 6);
	if (nm < 2)
		return -1;

	/* If we already bound regs at BAR0, just pick FB/FIFO from the remaining BARs. */
	if (ctx->regs_va) {
		/* Collect candidates excluding BAR0. */
		vboxsvga_mem_region_t c[6];
		int nc = 0;
		for (int i = 0; i < nm; i++) {
			if (mr[i].bar_lo == 0)
				continue;
			c[nc++] = mr[i];
		}
		if (nc < 2) {
			/* Some layouts only have 2 mem BARs total; include BAR0 in size selection then. */
			c[0] = mr[0];
			c[1] = mr[1];
			nc = 2;
		}
		/* Largest is framebuffer, smallest is FIFO. */
		for (int a = 0; a < nc - 1; a++) {
			for (int b = a + 1; b < nc; b++) {
				if (c[b].size > c[a].size) {
					vboxsvga_mem_region_t t = c[a];
					c[a] = c[b];
					c[b] = t;
				}
			}
		}
		*fb_pa_out = c[0].pa;
		*fifo_pa_out = c[nc - 1].pa;
		ctx->fb_len = (uint32_t)c[0].size;
		ctx->fifo_len = (uint32_t)c[nc - 1].size;
		if (ctx->fifo_len == 0)
			ctx->fifo_len = SVGA_DEFAULT_FIFO_BYTES;
		klogprintf("vboxsvga: BAR pick (regs@BAR0): fb pa=0x%llx sz=0x%llx fifo pa=0x%llx sz=0x%llx\n",
		           (unsigned long long)*fb_pa_out, (unsigned long long)ctx->fb_len,
		           (unsigned long long)*fifo_pa_out, (unsigned long long)ctx->fifo_len);
		return 0;
	}

	/* No dedicated regs mapping; locate an embedded regs window in memory BARs. */
	int ord[6];
	vboxsvga_mem_region_sort_by_size_asc(mr, ord, nm);

	int i0 = ord[0];
	int i1 = ord[nm - 1];
	int i_fb = i1;
	int i_fifo = i0;

	/* If sizes tie, prefer lower BAR index for FB (mirrors vmwgfx heuristics). */
	if (mr[i0].size == mr[i1].size) {
		if (mr[i0].bar_lo <= mr[i1].bar_lo) {
			i_fb = i0;
			i_fifo = i1;
		} else {
			i_fb = i1;
			i_fifo = i0;
		}
	}

	size_t reg_off = 0;
	int on_fb = vboxsvga_scan_bar_for_reg_window(mr[i_fb].pa, mr[i_fb].size, &reg_off);
	int on_fifo = 0;
	if (!on_fb)
		on_fifo = vboxsvga_scan_bar_for_reg_window(mr[i_fifo].pa, mr[i_fifo].size, &reg_off);
	if (!on_fb && !on_fifo)
		return -1;

	if (on_fb) {
		ctx->regs_mmio_pa = mr[i_fb].pa + (uint64_t)reg_off;
		*fb_pa_out = mr[i_fb].pa;
		*fifo_pa_out = mr[i_fifo].pa;
		ctx->fb_len = (uint32_t)mr[i_fb].size;
		ctx->fifo_len = (uint32_t)mr[i_fifo].size;
	} else {
		ctx->regs_mmio_pa = mr[i_fifo].pa + (uint64_t)reg_off;
		*fb_pa_out = mr[i_fb].pa;
		*fifo_pa_out = mr[i_fifo].pa;
		ctx->fb_len = (uint32_t)mr[i_fb].size;
		ctx->fifo_len = (uint32_t)mr[i_fifo].size;
	}
	if (ctx->fifo_len == 0)
		ctx->fifo_len = SVGA_DEFAULT_FIFO_BYTES;
	klogprintf("vboxsvga: BAR pick (embedded regs): regs pa=0x%llx fb pa=0x%llx sz=0x%llx fifo pa=0x%llx sz=0x%llx\n",
	           (unsigned long long)ctx->regs_mmio_pa,
	           (unsigned long long)*fb_pa_out, (unsigned long long)ctx->fb_len,
	           (unsigned long long)*fifo_pa_out, (unsigned long long)ctx->fifo_len);
	return 0;
}

int vboxsvga_kernel_init(void) {
	if (s_vbox_kernel_inited)
		return 0;

	pci_device_t *pdev = vboxsvga_find_pci();
	if (!pdev)
		return -1;

	int was_reg = g_vbox.registered;
	memset(&g_vbox, 0, sizeof(g_vbox));
	g_vbox.registered = was_reg;
	g_vbox.bus = pdev->bus;
	g_vbox.device = pdev->device;
	g_vbox.function = pdev->function;
	g_vbox.pci_device_id = pdev->device_id;

	uint32_t cmd = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, 0x04);
	cmd |= (1u << 0) | (1u << 1) | (1u << 2);
	pci_config_write_dword(pdev->bus, pdev->device, pdev->function, 0x04, cmd);

	uint64_t fb_pa = 0;
	uint64_t fifo_pa = 0;
	if (vboxsvga_bind_from_pci(&g_vbox, pdev, &fb_pa, &fifo_pa) != 0) {
		klogprintf("vboxsvga: could not derive BAR layout (no SVGA regs window)\n");
		return -1;
	}

	if (!g_vbox.fb_va) {
		g_vbox.fb_va = mmio_map_framebuffer(fb_pa, g_vbox.fb_len);
		if (!g_vbox.fb_va)
			g_vbox.fb_va = mmio_map_phys(fb_pa, g_vbox.fb_len);
	}
	/*
	 * VBoxSVGA frequently uses a FIFO located in guest system memory (SVGA_REG_MEM_START),
	 * not a BAR-backed FIFO aperture. We keep BAR-derived fifo_pa only for diagnostics.
	 */
	g_vbox.fifo_va = NULL;
	if (!g_vbox.fb_va) {
		klogprintf("vboxsvga: MMIO map failed (fb=%p)\n", g_vbox.fb_va);
		return -1;
	}
	g_vbox.fb_pa = fb_pa;
	klogprintf("vboxsvga: mapped fb pa=0x%llx len=%u (BAR fifo pa=0x%llx len=%u) pci %04x:%04x\n",
	           (unsigned long long)fb_pa, (unsigned)g_vbox.fb_len,
	           (unsigned long long)fifo_pa, (unsigned)g_vbox.fifo_len,
	           (unsigned)VBOX_PCI_VENDOR_ID, (unsigned)g_vbox.pci_device_id);

	if (g_vbox.regs_mmio_pa != 0) {
		uint64_t rp = g_vbox.regs_mmio_pa;
		if (rp >= fb_pa && rp + 8u <= fb_pa + (uint64_t)g_vbox.fb_len)
			g_vbox.regs_va = (void *)((uintptr_t)g_vbox.fb_va + (uintptr_t)(rp - fb_pa));
		else {
			g_vbox.regs_va = mmio_map_phys(rp, 0x1000u);
			if (!g_vbox.regs_va) {
				klogprintf("vboxsvga: mmio_map_phys(SVGA regs) failed pa=0x%llx\n",
				           (unsigned long long)rp);
				return -1;
			}
		}
		g_vbox.regs_mmio_linear = 0;
		g_vbox.regs_mmio_pa = 0;
	}

	if (!g_vbox.regs_va) {
		klogprintf("vboxsvga: no regs mapping after BAR probe\n");
		return -1;
	}

	svga_reg_write32(&g_vbox, SVGA_REG_ENABLE, 0);
	g_vbox.scanout_on = 0;
	/* Same guest ID as vmwgfx: it's harmless and can improve host behavior. */
	svga_reg_write32(&g_vbox, SVGA_REG_GUEST_ID, 0x5007u);

	if (svga_negotiate_id(&g_vbox) != 0) {
		klogprintf("vboxsvga: SVGA ID negotiation failed\n");
		return -1;
	}

	if (vboxsvga_setup_guest_fifo(&g_vbox) != 0) {
		klogprintf("vboxsvga: guest FIFO setup failed\n");
		return -1;
	}

	if (vboxsvga_pick_mode(&g_vbox) != 0) {
		klogprintf("vboxsvga: no usable video mode\n");
		return -1;
	}

	uint64_t need = (uint64_t)g_vbox.fb_offset + (uint64_t)g_vbox.pitch * (uint64_t)g_vbox.height;
	if (need > (uint64_t)g_vbox.fb_len) {
		klogprintf("vboxsvga: framebuffer too small for mode (need %llu have %u)\n",
		           (unsigned long long)need, (unsigned)g_vbox.fb_len);
		return -1;
	}

	g_vbox.present = 1;
	if (!g_vbox.registered) {
		if (vboxsvga_driver_register() != 0)
			return -1;
		g_vbox.registered = 1;
	}
	if (video_probe_all() <= 0)
		return -1;

	video_device_t *vd = video_find_by_name("vboxsvga");
	if (!vd || !vd->mmio_base)
		return -1;

	uint32_t usable = g_vbox.fb_len - g_vbox.fb_offset;
	if (cirrusfb_init(vd->mmio_base, vd->width, vd->height, vd->pitch, vd->bpp, usable, 0) != 0)
		return -1;

#if defined(__GNUC__) || defined(__clang__)
	__asm__ volatile("mfence" ::: "memory");
#endif
	svga_reg_write32(&g_vbox, SVGA_REG_ENABLE, 1);
	g_vbox.scanout_on = 1;
	klogprintf("vboxsvga: scanout enabled\n");

	/* Repaint, then push UPDATE to force a host refresh. */
	cirrusfb_clear(WHITE_ON_BLACK);
#if defined(__GNUC__) || defined(__clang__)
	__asm__ volatile("mfence" ::: "memory");
#endif
	video_flush_region_pixels(0, 0, vd->width, vd->height);
	video_display_sync();
	/* Ensure host has consumed the FIFO update before continuing. */
	svga_sync_and_wait(&g_vbox);

	fbdev_register_linear(vd->mmio_base, g_vbox.fb_pa + (uint64_t)g_vbox.fb_offset,
	                      (size_t)usable, vd->width, vd->height, vd->pitch, vd->bpp);

	klogprintf("vboxsvga: ready %02x:%02x.%u %ux%u@%u fb=%p pa=0x%llx\n",
	           g_vbox.bus, g_vbox.device, g_vbox.function,
	           (unsigned)vd->width, (unsigned)vd->height, (unsigned)vd->bpp,
	           vd->mmio_base, (unsigned long long)g_vbox.fb_pa);
	s_vbox_kernel_inited = 1;
	return 0;
}

