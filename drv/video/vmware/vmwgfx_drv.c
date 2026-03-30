/*
 * VMware SVGA II (PCI) — minimal 2D linear framebuffer.
 *
 * Register layout and FIFO header follow the VMware SVGA guest ABI as implemented
 * in QEMU hw/display/vmware_vga.c (CONFIG_DONE + ENABLE required for SVGA mode).
 */
#include <vmwgfx.h>
/* Software glyph console in the linear FB (same module as QEMU Cirrus path; not Cirrus hardware). */
#include <cirrusfb.h>
#include <fbdev.h>
#include <video.h>
#include <klog.h>
#include <mmio.h>
#include <pci.h>
#include <serial.h>
#include <string.h>
#include <stddef.h>
#include <vga.h>

#if defined(__GNUC__) || defined(__clang__)
#define vmwgfx_io_barrier() __asm__ volatile("" ::: "memory")
#else
#define vmwgfx_io_barrier() ((void)0)
#endif

#define VMWARE_PCI_VENDOR_ID   0x15AD
#define VMWARE_PCI_DEVICE_SVGA2 0x0405
#define VMWARE_PCI_DEVICE_SVGA3 0x0406 /* Workstation: MMIO regs @BAR0, VRAM @BAR2 (Linux vmwgfx) */
#define VMWARE_PCI_DEVICE_SVGA1 0x0710

#define SVGA_MAGIC           0x900000UL
#define SVGA_MAKE_ID(ver)    ((SVGA_MAGIC << 8) | (unsigned long)(ver))
#define SVGA_ID_0            SVGA_MAKE_ID(0)
#define SVGA_ID_1            SVGA_MAKE_ID(1)
#define SVGA_ID_2            SVGA_MAKE_ID(2)
#define SVGA_ID_3            SVGA_MAKE_ID(3)

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
	SVGA_REG_FB_OFFSET = 14,
	SVGA_REG_FB_SIZE = 16,
	SVGA_REG_MEM_SIZE = 19,
	SVGA_REG_MEM_REGS = 30, /* FIFO register count * 4 = bytes to reserve before queue (VMware svga_reg.h) */
	SVGA_REG_CONFIG_DONE = 20,
	SVGA_REG_SYNC = 21,
	SVGA_REG_BUSY = 22,
	SVGA_REG_GUEST_ID = 23,
};

enum svga_fifo {
	SVGA_FIFO_MIN = 0,
	SVGA_FIFO_MAX = 1,
	SVGA_FIFO_NEXT = 2,
	SVGA_FIFO_STOP = 3,
};

/* QEMU hw/display/vmware_vga.c — guest pushes dwords, host runs queue on SVGA_REG_SYNC. */
#define SVGA_CMD_UPDATE 1u

/*
 * Command ring starts after SVGA_FIFO_NUM_REGS DWORDs (Linux vmwgfx svga_reg.h ≈ 291), not after 16 bytes.
 * SVGA_REG_MEM_REGS often reads 0; old min=16 put UPDATE inside the register file → black screen on VMware.
 */
#define SVGA_FIFO_QUEUE_START_BYTES (291u * 4u)
#define SVGA_FIFO_MIN_QUEUE_ROOM      (10u * 1024u)
/* QEMU vmware_vga + SVGA-II reference: fifo ring lives in first 64KiB; larger fifo_max → host ignores queue. */
#define SVGA_FIFO_HOST_MAX_BYTES      0x10000u

#define SVGA_DEFAULT_FIFO_BYTES 0x10000u
/* Fixed ISA-style index port (value port is usually index+4 or index+8). */
#define SVGA_LEGACY_IO_INDEX 0x4560u

typedef struct {
	uint8_t bus;
	uint8_t device;
	uint8_t function;
	void *regs_va;
	/* I/O path: separate index and value ports (PCI BAR often idx+0 / idx+4). */
	uint16_t regs_io_idx;
	uint16_t regs_io_val;
	/* SVGA3: MMIO BAR is u32 reg[index]; SVGA2 MMIO window uses index @ [0] value @ [1]. */
	int regs_mmio_linear;
	uint16_t pci_device_id;
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
	/* I/O-dead fallback (nm==2): physical base of SVGA index/value pair; bound to VA after fb+fifo map. */
	uint64_t regs_mmio_pa;
	/* Set when guest has raised ENABLE for final scanout; do not use SVGA_REG_ENABLE readback (often 0 on I/O paths). */
	int scanout_on;
	int present;
	int registered;
} vmwgfx_ctx_t;

static vmwgfx_ctx_t g_vmwgfx;
static int s_vmwgfx_kernel_inited;

static uint32_t vmwgfx_pci_mem_bar_size(const pci_device_t *pdev, int bar_idx) {
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

static uint32_t vmwgfx_pci_io_bar_size(const pci_device_t *pdev, int bar_idx) {
	if (!pdev || bar_idx < 0 || bar_idx > 5)
		return 0;
	uint8_t bar_off = (uint8_t)(0x10 + bar_idx * 4);
	uint32_t orig = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, bar_off);
	if ((orig & 0x1u) == 0)
		return 0;
	pci_config_write_dword(pdev->bus, pdev->device, pdev->function, bar_off, 0xFFFFFFFFu);
	uint32_t mask = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, bar_off);
	pci_config_write_dword(pdev->bus, pdev->device, pdev->function, bar_off, orig);
	mask &= ~0x3u;
	if (mask == 0)
		return 0;
	return (uint32_t)(~mask + 1u) & 0xFFFFu;
}

/* 64-bit memory BAR sizing (low+high dword). */
static uint64_t vmwgfx_pci_mem64_bar_size(const pci_device_t *pdev, int bar_idx) {
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
} vmwgfx_mem_region_t;

static int vmwgfx_collect_mem_regions(const pci_device_t *p, vmwgfx_mem_region_t *out, int max_out) {
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
		uint64_t sz;
		if (cons == 2)
			sz = vmwgfx_pci_mem64_bar_size(p, i);
		else
			sz = (uint64_t)vmwgfx_pci_mem_bar_size(p, i);
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

static void vmwgfx_mem_region_sort_by_size_asc(vmwgfx_mem_region_t *r, int *order, int n) {
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

static void vmwgfx_mem_region_sort_by_size_desc(vmwgfx_mem_region_t *r, int n) {
	for (int a = 0; a < n - 1; a++) {
		for (int b = a + 1; b < n; b++) {
			if (r[b].size > r[a].size) {
				vmwgfx_mem_region_t t = r[a];
				r[a] = r[b];
				r[b] = t;
			}
		}
	}
}

/*
 * True SVGA window: not ID alone (VRAM can fake that). Require stable MAX_* in range,
 * or both zero with stable negotiated ID (some revisions report 0 until CONFIG_DONE).
 */
static int vmwgfx_mmio_regs_verify_window(volatile uint32_t *reg) {
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
			/* Some guests report 0/~0 for MAX_* until CONFIG_DONE; DEPTH often stays sane. */
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

/* Loose ID-only probe for MMIO scan fallback (strict geom can fail on some guests). */
static int vmwgfx_mmio_id_only_window(volatile uint32_t *reg) {
	for (int n = 0; n < 100; n++) {
		reg[0] = SVGA_REG_ID;
		reg[1] = (uint32_t)SVGA_ID_2;
		reg[0] = SVGA_REG_ID;
		uint32_t id = reg[1];
		if (id == 0xffffffffu || id == 0)
			continue;
		if (id == (uint32_t)SVGA_ID_2 || id == (uint32_t)SVGA_ID_1)
			return 1;
		if (id != (uint32_t)SVGA_ID_0 && (id >> 8) == (uint32_t)SVGA_MAGIC)
			return 1;
	}
	return 0;
}

/*
 * Coarse scan (4K step) up to cap — used only after strict verify fails.
 * Confirmed later by svga_negotiate_id / pick_mode (false positives get dropped).
 */
static int vmwgfx_scan_bar_for_reg_window_loose(uint64_t pa, uint64_t bar_sz, size_t *reg_off_out) {
	size_t scan = (size_t)bar_sz;
	const size_t cap = 16u * 1024u * 1024u;
	if (scan > cap)
		scan = cap;
	if (scan < 16)
		return 0;
	void *va = mmio_map_phys(pa, scan);
	if (!va)
		return 0;
	int found = 0;
	for (size_t off = 0; off + 8 <= scan; off += 4096u) {
		volatile uint32_t *reg = (volatile uint32_t *)((uint8_t *)va + off);
		if (!vmwgfx_mmio_id_only_window(reg))
			continue;
		*reg_off_out = off;
		found = 1;
		break;
	}
	mmio_unmap(va, scan);
	return found;
}

static int vmwgfx_mmio_regs_probe_at(uint64_t pa) {
	void *va = mmio_map_phys(pa, 0x4000);
	if (!va)
		return 0;
	int ok = vmwgfx_mmio_regs_verify_window((volatile uint32_t *)va);
	mmio_unmap(va, 0x4000);
	return ok;
}

/*
 * Search start of a memory BAR for dword index / dword value register pair.
 * Pass A: 4-byte step for first 256 KiB (avoid missing non-page-aligned windows).
 * Pass B: 4 KiB step up to min(bar, 4 MiB) for page-aligned MMIO elsewhere.
 */
static int vmwgfx_scan_bar_for_reg_window(uint64_t pa, uint64_t bar_sz, size_t *reg_off_out) {
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
		if (!vmwgfx_mmio_regs_verify_window(reg))
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
		if (!vmwgfx_mmio_regs_verify_window(reg))
			continue;
		*reg_off_out = off;
		found = 1;
		break;
	}
out:
	mmio_unmap(va, scan);
	return found;
}

/*
 * VMware may advertise a useless I/O BAR while real SVGA index/value lives in MMIO.
 * - 3+ memory BARs: smallest region that passes probe = regs; largest other = fb; other = fifo.
 * - 2 memory BARs (typical I/O + FB + FIFO): regs often alias the first dword pair of the larger (FB) BAR.
 */
static int vmwgfx_try_mmio_regs_io_dead_fallback(pci_device_t *pdev, uint64_t *fb_pa, uint64_t *fifo_pa,
                                                 uint32_t *fb_len, uint32_t *fifo_len) {
	vmwgfx_mem_region_t mr[6];
	int nm = vmwgfx_collect_mem_regions(pdev, mr, 6);
	if (nm < 2) {
		klogprintf("vmwgfx: MMIO regs fallback needs >=2 memory BARs, found %d\n", nm);
		return 0;
	}

	int ord[6];
	vmwgfx_mem_region_sort_by_size_asc(mr, ord, nm);

	if (nm == 2) {
		int i0 = ord[0];
		int i1 = ord[1];
		/*
		 * Smaller BAR = FIFO, larger = FB. If sizes tie (common 128M+128M), VMware uses
		 * lower PCI BAR index for guest framebuffer (BAR1), higher for FIFO (BAR2).
		 */
		int i_fifo, i_fb;
		if (mr[i0].size < mr[i1].size) {
			i_fifo = i0;
			i_fb = i1;
		} else if (mr[i0].size > mr[i1].size) {
			i_fifo = i1;
			i_fb = i0;
		} else {
			if (mr[i0].bar_lo <= mr[i1].bar_lo) {
				i_fb = i0;
				i_fifo = i1;
			} else {
				i_fb = i1;
				i_fifo = i0;
			}
		}

		size_t reg_off_fb = 0, reg_off_fifo = 0;
		int on_fb = vmwgfx_scan_bar_for_reg_window(mr[i_fb].pa, mr[i_fb].size, &reg_off_fb);
		int on_fifo = 0;
		if (!on_fb)
			on_fifo = vmwgfx_scan_bar_for_reg_window(mr[i_fifo].pa, mr[i_fifo].size, &reg_off_fifo);
		if (!on_fb && !on_fifo) {
			on_fb = vmwgfx_scan_bar_for_reg_window_loose(mr[i_fb].pa, mr[i_fb].size, &reg_off_fb);
			if (!on_fb)
				on_fifo = vmwgfx_scan_bar_for_reg_window_loose(mr[i_fifo].pa, mr[i_fifo].size, &reg_off_fifo);
		}
		if (!on_fb && !on_fifo) {
			klogprintf("vmwgfx: no SVGA MMIO window (FIFO bar@%x pa=0x%llx sz=0x%llx; FB bar@%x pa=0x%llx sz=0x%llx)\n",
			           0x10 + mr[i_fifo].bar_lo * 4, (unsigned long long)mr[i_fifo].pa,
			           (unsigned long long)mr[i_fifo].size,
			           0x10 + mr[i_fb].bar_lo * 4, (unsigned long long)mr[i_fb].pa,
			           (unsigned long long)mr[i_fb].size);
			return 0;
		}

		if (on_fb) {
			g_vmwgfx.regs_mmio_pa = mr[i_fb].pa + (uint64_t)reg_off_fb;
			klogprintf("vmwgfx: SVGA MMIO in FB BAR pa=0x%llx off=0x%zx size=0x%llx\n",
			           (unsigned long long)mr[i_fb].pa, reg_off_fb, (unsigned long long)mr[i_fb].size);
		} else {
			g_vmwgfx.regs_mmio_pa = mr[i_fifo].pa + (uint64_t)reg_off_fifo;
			klogprintf("vmwgfx: SVGA MMIO in FIFO BAR pa=0x%llx off=0x%zx size=0x%llx\n",
			           (unsigned long long)mr[i_fifo].pa, reg_off_fifo, (unsigned long long)mr[i_fifo].size);
		}

		uint64_t fbl = mr[i_fb].size;
		uint64_t fiol = mr[i_fifo].size;
		*fb_pa = mr[i_fb].pa;
		*fifo_pa = mr[i_fifo].pa;
		*fb_len = (fbl > 0xFFFFFFFFull) ? 0xFFFFFFFFu : (uint32_t)fbl;
		*fifo_len = (fiol > 0xFFFFFFFFull) ? 0xFFFFFFFFu : (uint32_t)fiol;
		if (*fifo_len == 0)
			*fifo_len = SVGA_DEFAULT_FIFO_BYTES;
		/* fb_va / regs_va / fifo_va: vmwgfx_kernel_init maps and binds regs_mmio_pa */
		return 1;
	}

	int reg_i = -1;
	size_t reg_scan_off = 0;
	int reg_at_bar_base = 0;
	for (int j = 0; j < nm; j++) {
		int k = ord[j];
		if (vmwgfx_mmio_regs_probe_at(mr[k].pa)) {
			reg_i = k;
			reg_at_bar_base = 1;
			klogprintf("vmwgfx: SVGA MMIO regs at pa=0x%llx size=0x%llx (PCI bar @0x%x)\n",
			           (unsigned long long)mr[k].pa, (unsigned long long)mr[k].size,
			           0x10 + mr[k].bar_lo * 4);
			break;
		}
		size_t ro = 0;
		if (vmwgfx_scan_bar_for_reg_window(mr[k].pa, mr[k].size, &ro) ||
		    vmwgfx_scan_bar_for_reg_window_loose(mr[k].pa, mr[k].size, &ro)) {
			reg_i = k;
			reg_scan_off = ro;
			klogprintf("vmwgfx: SVGA MMIO regs at pa=0x%llx off=0x%zx (PCI bar @0x%x)\n",
			           (unsigned long long)mr[k].pa, (unsigned long long)ro,
			           0x10 + mr[k].bar_lo * 4);
			break;
		}
	}
	if (reg_i < 0)
		return 0;

	uint64_t rsz = mr[reg_i].size;
	if (rsz > 16ull * 1024ull * 1024ull)
		rsz = 16ull * 1024ull * 1024ull;
	if (rsz < 8192)
		rsz = 8192;

	if (reg_at_bar_base) {
		g_vmwgfx.regs_va = mmio_map_phys(mr[reg_i].pa, (size_t)rsz);
		if (!g_vmwgfx.regs_va) {
			klogprintf("vmwgfx: mmio_map_phys(SVGA regs) failed\n");
			return 0;
		}
	} else {
		g_vmwgfx.regs_mmio_pa = mr[reg_i].pa + (uint64_t)reg_scan_off;
	}

	vmwgfx_mem_region_t rem[5];
	int nr = 0;
	for (int i = 0; i < nm; i++) {
		if (i != reg_i && nr < 5)
			rem[nr++] = mr[i];
	}
	if (nr != 2) {
		klogprintf("vmwgfx: expected 2 remaining memory BARs for fb+fifo, got %d\n", nr);
		if (g_vmwgfx.regs_va) {
			mmio_unmap(g_vmwgfx.regs_va, (size_t)rsz);
			g_vmwgfx.regs_va = NULL;
		}
		g_vmwgfx.regs_mmio_pa = 0;
		return 0;
	}
	vmwgfx_mem_region_sort_by_size_desc(rem, 2);
	*fb_pa = rem[0].pa;
	*fifo_pa = rem[1].pa;
	uint64_t fbl = rem[0].size;
	uint64_t fiol = rem[1].size;
	*fb_len = (fbl > 0xFFFFFFFFull) ? 0xFFFFFFFFu : (uint32_t)fbl;
	*fifo_len = (fiol > 0xFFFFFFFFull) ? 0xFFFFFFFFu : (uint32_t)fiol;
	if (*fifo_len == 0)
		*fifo_len = SVGA_DEFAULT_FIFO_BYTES;
	return 1;
}

static uint32_t svga_io_read32_ports(uint16_t idx_p, uint16_t val_p, uint32_t index) {
	outportl(idx_p, index);
	vmwgfx_io_barrier();
	return inportl(val_p);
}

static void svga_io_write32_ports(uint16_t idx_p, uint16_t val_p, uint32_t index, uint32_t value) {
	outportl(idx_p, index);
	vmwgfx_io_barrier();
	outportl(val_p, value);
}

/*
 * Probe indexed I/O: only ID must look like SVGA. Do not require MAX_WIDTH —
 * on some VMware / SVGA revisions it reads 0 or ~0 until after full init.
 * 0xffffffff usually means no decode (hypervisor disabled path or wrong val port).
 */
static int vmwgfx_probe_io_regpath(uint16_t idx_p, uint16_t val_p) {
	uint32_t pre = svga_io_read32_ports(idx_p, val_p, SVGA_REG_ID);
	if (pre != 0xffffffffu && pre != 0 &&
	    (pre == (uint32_t)SVGA_ID_2 || pre == (uint32_t)SVGA_ID_1 ||
	     (pre != (uint32_t)SVGA_ID_0 && (pre >> 8) == (uint32_t)SVGA_MAGIC)))
		return 1;

	for (int n = 0; n < 400; n++) {
		svga_io_write32_ports(idx_p, val_p, SVGA_REG_ID, (uint32_t)SVGA_ID_2);
		uint32_t id = svga_io_read32_ports(idx_p, val_p, SVGA_REG_ID);
		if (id == 0xffffffffu)
			return 0;
		if (id == (uint32_t)SVGA_ID_2 || id == (uint32_t)SVGA_ID_1)
			return 1;
		if (id != 0 && id != (uint32_t)SVGA_ID_0 && (id >> 8) == (uint32_t)SVGA_MAGIC)
			return 1;
	}
	return 0;
}

static int vmwgfx_try_io_idx_val(uint16_t idx_p, uint16_t val_p, const char *tag) {
	if (!vmwgfx_probe_io_regpath(idx_p, val_p))
		return 0;
	g_vmwgfx.regs_io_idx = idx_p;
	g_vmwgfx.regs_io_val = val_p;
	klogprintf("vmwgfx: SVGA I/O ok (%s) idx=0x%x val=0x%x\n", tag,
	           (unsigned)idx_p, (unsigned)val_p);
	return 1;
}

/* Value port: VMware svga_reg.h uses INDEX=0 VALUE=1 (often dword ports = +0 / +4); try +1 too. */
static int vmwgfx_bind_io_bar(uint16_t pci_idx, uint32_t io_sz) {
	static const unsigned strides[] = { 4u, 1u, 8u };

	for (size_t i = 0; i < sizeof(strides) / sizeof(strides[0]); i++) {
		unsigned s = strides[i];
		uint16_t val = (uint16_t)(pci_idx + s);
		if (val < pci_idx || (uint32_t)(val - pci_idx) + 4u > io_sz)
			continue;
		if (vmwgfx_try_io_idx_val(pci_idx, val, "PCI BAR0"))
			return 1;
	}
	return 0;
}

static int vmwgfx_bind_legacy_io(void) {
	static const unsigned bases[] = { SVGA_LEGACY_IO_INDEX };
	static const unsigned strides[] = { 4u, 8u };

	for (size_t b = 0; b < sizeof(bases) / sizeof(bases[0]); b++) {
		uint16_t idx = (uint16_t)bases[b];
		for (size_t s = 0; s < sizeof(strides) / sizeof(strides[0]); s++) {
			uint16_t val = (uint16_t)(idx + strides[s]);
			if (vmwgfx_try_io_idx_val(idx, val, "legacy"))
				return 1;
		}
	}
	return 0;
}

static uint32_t svga_reg_read32(const vmwgfx_ctx_t *ctx, uint32_t index) {
	if (ctx->regs_io_val != 0) {
		return svga_io_read32_ports(ctx->regs_io_idx, ctx->regs_io_val, index);
	}
	volatile uint32_t *r = (volatile uint32_t *)ctx->regs_va;
	if (ctx->regs_mmio_linear)
		return r[index];
	r[0] = index;
	return r[1];
}

static void svga_reg_write32(const vmwgfx_ctx_t *ctx, uint32_t index, uint32_t value) {
	if (ctx->regs_io_val != 0) {
		svga_io_write32_ports(ctx->regs_io_idx, ctx->regs_io_val, index, value);
		return;
	}
	volatile uint32_t *r = (volatile uint32_t *)ctx->regs_va;
	if (ctx->regs_mmio_linear) {
		r[index] = value;
		return;
	}
	r[0] = index;
	r[1] = value;
}

/*
 * VMware guest ABI: write SVGA_ID_2 to SVGA_REG_ID, then read SVGA_REG_ID until it
 * is no longer SVGA_ID_0 (and typically not 0). Treating SVGA_ID_0 as "ready" was wrong
 * and breaks real VMware I/O BAR paths.
 */
static int svga_negotiate_id(vmwgfx_ctx_t *ctx) {
	uint32_t id = 0;

	unsigned long want = SVGA_ID_2;
	if (ctx->pci_device_id == VMWARE_PCI_DEVICE_SVGA3)
		want = SVGA_ID_3;

	for (int i = 0; i < 100000; i++) {
		svga_reg_write32(ctx, SVGA_REG_ID, (uint32_t)want);
		id = svga_reg_read32(ctx, SVGA_REG_ID);
		if (id != (uint32_t)SVGA_ID_0 && id != 0)
			break;
	}

	if (id == (uint32_t)SVGA_ID_2 || id == (uint32_t)SVGA_ID_1 || id == (uint32_t)SVGA_ID_3)
		return 0;

	/* Newer VMware / SVGA revisions may report 0x90000004+; still same family. */
	if (id != (uint32_t)SVGA_ID_0 && (id >> 8) == (uint32_t)SVGA_MAGIC)
		return 0;

	klogprintf("vmwgfx: SVGA ID unexpected %08x (wanted %08x/%08x)\n",
	           (unsigned)id, (unsigned)(uint32_t)SVGA_ID_2, (unsigned)(uint32_t)SVGA_ID_1);
	return -1;
}

static void svga_fifo_reset(vmwgfx_ctx_t *ctx) {
	volatile uint32_t *fifo = (volatile uint32_t *)ctx->fifo_va;
	uint32_t sz = ctx->fifo_len;
	if (!fifo || sz < 64)
		return;
	/* SVGA_REG_MEM_REGS: optional DWORD count for reserved fifo header; 0 → use SVGA_FIFO_NUM_REGS layout. */
	uint32_t nregs_dw = svga_reg_read32(ctx, SVGA_REG_MEM_REGS);
	uint32_t min = SVGA_FIFO_QUEUE_START_BYTES;
	if (nregs_dw >= 4u && nregs_dw <= 1024u)
		min = nregs_dw * 4u;
	if (min < 4u * (uint32_t)sizeof(uint32_t))
		min = 4u * (uint32_t)sizeof(uint32_t);
	uint32_t max = sz;
	if (max > SVGA_FIFO_HOST_MAX_BYTES)
		max = SVGA_FIFO_HOST_MAX_BYTES;
	if (max > sz)
		max = sz;
	/* Hosts (QEMU vmware_vga) require max - min >= 10KiB of command space. */
	if (min + SVGA_FIFO_MIN_QUEUE_ROOM > max) {
		if (max > SVGA_FIFO_MIN_QUEUE_ROOM + 16u)
			min = max - SVGA_FIFO_MIN_QUEUE_ROOM - 16u;
		else
			min = 16u;
	}
	if (min + 32u > max)
		min = 0u;
	memset((void *)fifo, 0, (size_t)max);
	fifo[SVGA_FIFO_MIN] = min;
	fifo[SVGA_FIFO_MAX] = max;
	fifo[SVGA_FIFO_NEXT] = min;
	fifo[SVGA_FIFO_STOP] = min;
}

static int vmwgfx_fifo_free_bytes(vmwgfx_ctx_t *ctx) {
	volatile uint32_t *hdr = (volatile uint32_t *)ctx->fifo_va;
	uint32_t sz = ctx->fifo_len;
	if (!hdr || sz < 64u)
		return 0;
	uint32_t mn = hdr[SVGA_FIFO_MIN];
	uint32_t mx = hdr[SVGA_FIFO_MAX];
	uint32_t nx = hdr[SVGA_FIFO_NEXT];
	uint32_t st = hdr[SVGA_FIFO_STOP];
	if (mx <= mn || mx > sz || mx > SVGA_FIFO_HOST_MAX_BYTES || (mn | mx | nx | st) & 3u)
		return 0;
	uint32_t ring = mx - mn;
	if (ring < 32u)
		return 0;
	int32_t used = (int32_t)(nx - st);
	if (used < 0)
		used += (int32_t)ring;
	/* leave >=4 bytes slack like common ring conventions */
	int32_t freeb = (int32_t)ring - used - 4;
	if (freeb < 0)
		return 0;
	return (int)freeb;
}

/* Byte-indexed ring; one dword at a time with wrap (VMware guest FIFO convention). */
static int vmwgfx_fifo_append_u32(vmwgfx_ctx_t *ctx, uint32_t value) {
	volatile uint32_t *hdr = (volatile uint32_t *)ctx->fifo_va;
	uint8_t *base = (uint8_t *)ctx->fifo_va;
	uint32_t sz = ctx->fifo_len;
	if (!hdr || sz < 64u)
		return -1;
	if (vmwgfx_fifo_free_bytes(ctx) < 4)
		return -1;
	uint32_t mn = hdr[SVGA_FIFO_MIN];
	uint32_t mx = hdr[SVGA_FIFO_MAX];
	uint32_t nx = hdr[SVGA_FIFO_NEXT];
	if (mx <= mn || mx > sz || mx > SVGA_FIFO_HOST_MAX_BYTES || mn + 20u > mx ||
	    mn < 4u * sizeof(uint32_t))
		return -1;
	if (nx + 4u > mx)
		nx = mn;
	*(volatile uint32_t *)(base + nx) = value;
	nx += 4u;
	if (nx >= mx)
		nx = mn;
	hdr[SVGA_FIFO_NEXT] = nx;
	vmwgfx_io_barrier();
	return 0;
}

static void vmwgfx_fifo_submit_update(vmwgfx_ctx_t *ctx, uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
	if (!ctx->fifo_va || w == 0 || h == 0)
		return;
	if (vmwgfx_fifo_free_bytes(ctx) < 20) {
		svga_reg_write32(ctx, SVGA_REG_SYNC, 1);
		vmwgfx_io_barrier();
	}
	if (vmwgfx_fifo_free_bytes(ctx) < 20)
		return;
	if (vmwgfx_fifo_append_u32(ctx, SVGA_CMD_UPDATE) != 0)
		return;
	if (vmwgfx_fifo_append_u32(ctx, x) != 0)
		return;
	if (vmwgfx_fifo_append_u32(ctx, y) != 0)
		return;
	if (vmwgfx_fifo_append_u32(ctx, w) != 0)
		return;
	(void)vmwgfx_fifo_append_u32(ctx, h);
}

/*
 * leave_enabled: if 0, SVGA_REG_ENABLE is cleared after verify so VGA text/klog stays visible
 * until the guest fills the linear FB (see vmwgfx_kernel_init after cirrusfb_init).
 * If 1, leave scanout enabled (runtime modeset).
 */
static int svga_try_mode(vmwgfx_ctx_t *ctx, uint32_t w, uint32_t h, int leave_enabled) {
	uint32_t maxw = svga_reg_read32(ctx, SVGA_REG_MAX_WIDTH);
	uint32_t maxh = svga_reg_read32(ctx, SVGA_REG_MAX_HEIGHT);
	if (maxw != 0 && w > maxw)
		return -1;
	if (maxh != 0 && h > maxh)
		return -1;

	svga_reg_write32(ctx, SVGA_REG_ENABLE, 0);
	ctx->scanout_on = 0;
	svga_reg_write32(ctx, SVGA_REG_CONFIG_DONE, 0);
	svga_reg_write32(ctx, SVGA_REG_WIDTH, w);
	svga_reg_write32(ctx, SVGA_REG_HEIGHT, h);
	svga_reg_write32(ctx, SVGA_REG_BITS_PER_PIXEL, 32);
	svga_reg_write32(ctx, SVGA_REG_DEPTH, 24); /* 32bpp XRGB: color depth 24 (VMware/QEMU expect this) */

	svga_fifo_reset(ctx);
	svga_reg_write32(ctx, SVGA_REG_CONFIG_DONE, 1);

	uint32_t pitch = svga_reg_read32(ctx, SVGA_REG_BYTES_PER_LINE);
	if (pitch < w * 4u)
		return -1;

	ctx->fb_offset = svga_reg_read32(ctx, SVGA_REG_FB_OFFSET);
	svga_reg_write32(ctx, SVGA_REG_ENABLE, 1);

	uint32_t rw = svga_reg_read32(ctx, SVGA_REG_WIDTH);
	uint32_t rh = svga_reg_read32(ctx, SVGA_REG_HEIGHT);
	if (rw != w || rh != h) {
		svga_reg_write32(ctx, SVGA_REG_ENABLE, 0);
		ctx->scanout_on = 0;
		return -1;
	}

	ctx->width = w;
	ctx->height = h;
	ctx->bpp = 32;
	ctx->pitch = pitch;
	if (!leave_enabled) {
		svga_reg_write32(ctx, SVGA_REG_ENABLE, 0);
		ctx->scanout_on = 0;
	} else {
		ctx->scanout_on = 1;
	}
	return 0;
}

static int vmwgfx_pick_mode(vmwgfx_ctx_t *ctx) {
	static const struct {
		uint32_t w, h;
	} modes[] = {
		/* Landscape first: normal VM window, no portrait scrollbars (fbcon = w/8 × h/16 cells). */
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
		/* Optional: 90×60 text at 8×16 if you really want portrait */
		{ 720, 960 },
	};

	for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
		if (svga_try_mode(ctx, modes[i].w, modes[i].h, 0) == 0) {
			klogprintf("vmwgfx: mode %ux%u pitch=%u fb_off=0x%x (scanout off until fbcon)\n",
			           (unsigned)ctx->width, (unsigned)ctx->height,
			           (unsigned)ctx->pitch, (unsigned)ctx->fb_offset);
			return 0;
		}
	}
	return -1;
}

static int vmwgfx_init(video_device_t *dev) {
	if (!dev || !g_vmwgfx.present)
		return -1;
	dev->mmio_pa = g_vmwgfx.fb_pa;
	if (g_vmwgfx.fb_va == NULL)
		return -1;
	dev->mmio_base = (uint8_t *)g_vmwgfx.fb_va + g_vmwgfx.fb_offset;
	dev->width = g_vmwgfx.width;
	dev->height = g_vmwgfx.height;
	dev->bpp = g_vmwgfx.bpp;
	dev->pitch = g_vmwgfx.pitch;
	return 0;
}

static void vmwgfx_shutdown(video_device_t *dev) {
	(void)dev;
}

static void vmwgfx_flush_region(video_device_t *dev, uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
	(void)dev;
	if (!g_vmwgfx.present || !g_vmwgfx.fifo_va || !g_vmwgfx.scanout_on)
		return;
	if (w == 0 || h == 0)
		return;
	uint32_t fw = g_vmwgfx.width;
	uint32_t fh = g_vmwgfx.height;
	if (fw == 0 || fh == 0)
		return;
	if (x >= fw || y >= fh)
		return;
	if (x + w > fw)
		w = fw - x;
	if (y + h > fh)
		h = fh - y;
	vmwgfx_fifo_submit_update(&g_vmwgfx, x, y, w, h);
	svga_reg_write32(&g_vmwgfx, SVGA_REG_SYNC, 1);
}

static int vmwgfx_set_mode(video_device_t *dev, uint32_t width, uint32_t height, uint32_t bpp) {
	(void)dev;
	if (bpp != 32)
		return -1;
	if (svga_try_mode(&g_vmwgfx, width, height, 1) != 0)
		return -1;
	return 0;
}

const video_ops_t vmwgfx_video_ops = {
	.init = vmwgfx_init,
	.shutdown = vmwgfx_shutdown,
	.flush_region = vmwgfx_flush_region,
	.set_mode = vmwgfx_set_mode,
};

int vmwgfx_driver_register(void) {
	return video_register_driver("vmwgfx", &vmwgfx_video_ops, NULL);
}

static pci_device_t *vmwgfx_find_pci(void) {
	pci_device_t *list = pci_get_devices();
	int n = pci_get_device_count();
	for (int i = 0; i < n; i++) {
		pci_device_t *d = &list[i];
		if (d->vendor_id != VMWARE_PCI_VENDOR_ID)
			continue;
		if (d->device_id == VMWARE_PCI_DEVICE_SVGA2 || d->device_id == VMWARE_PCI_DEVICE_SVGA3 ||
		    d->device_id == VMWARE_PCI_DEVICE_SVGA1)
			return d;
		if (d->class_code == 0x03)
			return d;
	}
	return NULL;
}

int vmwgfx_kernel_init(void) {
	if (s_vmwgfx_kernel_inited)
		return 0;

	pci_device_t *pdev = vmwgfx_find_pci();
	if (!pdev) {
		return -1;
	}

	int was_reg = g_vmwgfx.registered;
	memset(&g_vmwgfx, 0, sizeof(g_vmwgfx));
	g_vmwgfx.registered = was_reg;
	g_vmwgfx.bus = pdev->bus;
	g_vmwgfx.device = pdev->device;
	g_vmwgfx.function = pdev->function;
	g_vmwgfx.pci_device_id = pdev->device_id;

	uint32_t bar0 = pdev->bar[0];
	uint32_t bar1 = pdev->bar[1];
	uint32_t bar2 = pdev->bar[2];

	g_vmwgfx.regs_io_idx = 0;
	g_vmwgfx.regs_io_val = 0;
	g_vmwgfx.regs_va = NULL;

	uint32_t cmd = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, 0x04);
	cmd |= (1u << 0) | (1u << 1) | (1u << 2);
	pci_config_write_dword(pdev->bus, pdev->device, pdev->function, 0x04, cmd);

	uint64_t fb_pa = 0;
	uint64_t fifo_pa = 0;
	uint32_t regs_sz = 0;

	if ((bar0 & 0x1u) != 0) {
		if ((bar0 & ~0x3u) == 0) {
			klogprintf("vmwgfx: invalid I/O BAR0 %08x\n", (unsigned)bar0);
			return -1;
		}
		uint16_t pci_idx = (uint16_t)(bar0 & ~0x3u);
		regs_sz = vmwgfx_pci_io_bar_size(pdev, 0);
		if (regs_sz < 8u)
			regs_sz = 16u;
		klogprintf("vmwgfx: PCI BAR0 I/O base=0x%x (decode size %u)\n",
		           (unsigned)pci_idx, (unsigned)regs_sz);
		if (vmwgfx_bind_io_bar(pci_idx, regs_sz) || vmwgfx_bind_legacy_io()) {
			if ((bar1 & 0x1u) != 0 || (bar1 & ~0xFu) == 0) {
				klogprintf("vmwgfx: bad BAR1 %08x\n", (unsigned)bar1);
				return -1;
			}
			if ((bar2 & 0x1u) != 0 || (bar2 & ~0xFu) == 0) {
				klogprintf("vmwgfx: bad BAR2 %08x\n", (unsigned)bar2);
				return -1;
			}
			if (pdev->device_id == VMWARE_PCI_DEVICE_SVGA3) {
				fifo_pa = (uint64_t)(bar1 & ~0xFULL);
				fb_pa = (uint64_t)(bar2 & ~0xFULL);
				g_vmwgfx.fifo_len = vmwgfx_pci_mem_bar_size(pdev, 1);
				if (g_vmwgfx.fifo_len == 0)
					g_vmwgfx.fifo_len = SVGA_DEFAULT_FIFO_BYTES;
				g_vmwgfx.fb_len = vmwgfx_pci_mem_bar_size(pdev, 2);
			} else {
				fb_pa = (uint64_t)(bar1 & ~0xFULL);
				fifo_pa = (uint64_t)(bar2 & ~0xFULL);
				g_vmwgfx.fifo_len = vmwgfx_pci_mem_bar_size(pdev, 2);
				if (g_vmwgfx.fifo_len == 0)
					g_vmwgfx.fifo_len = SVGA_DEFAULT_FIFO_BYTES;
				g_vmwgfx.fb_len = vmwgfx_pci_mem_bar_size(pdev, 1);
			}
			if (g_vmwgfx.fb_len == 0) {
				klogprintf("vmwgfx: could not size framebuffer BAR\n");
				return -1;
			}
		} else {
			uint32_t dbg4 = svga_io_read32_ports(pci_idx, (uint16_t)(pci_idx + 4u), SVGA_REG_ID);
			uint32_t dbg1 = svga_io_read32_ports(pci_idx, (uint16_t)(pci_idx + 1u), SVGA_REG_ID);
			klogprintf("vmwgfx: SVGA I/O dead (ID val+4=%08x val+1=%08x); trying MMIO\n",
			           (unsigned)dbg4, (unsigned)dbg1);
			if (!vmwgfx_try_mmio_regs_io_dead_fallback(pdev, &fb_pa, &fifo_pa,
			                                           &g_vmwgfx.fb_len, &g_vmwgfx.fifo_len)) {
				klogprintf("vmwgfx: MMIO register probe failed (no dword SVGA regs in memory BARs)\n");
				klogprintf("vmwgfx: hint: turn off 3D in VM Display, or use VBE framebuffer from bootloader.\n");
				return -1;
			}
			if (g_vmwgfx.fifo_len == 0)
				g_vmwgfx.fifo_len = SVGA_DEFAULT_FIFO_BYTES;
		}
	} else {
		if ((bar0 & ~0xFu) == 0) {
			klogprintf("vmwgfx: bad MMIO BAR0 %08x\n", (unsigned)bar0);
			return -1;
		}
		uint64_t regs_pa = (uint64_t)(bar0 & ~0xFULL);
		regs_sz = vmwgfx_pci_mem_bar_size(pdev, 0);
		if (regs_sz < 8u)
			regs_sz = 0x1000u;
		g_vmwgfx.regs_va = mmio_map_phys(regs_pa, (size_t)regs_sz);
		if (!g_vmwgfx.regs_va) {
			klogprintf("vmwgfx: mmio_map_phys(regs) failed pa=0x%llx\n",
			           (unsigned long long)regs_pa);
			return -1;
		}

		/*
		 * VMware SVGA3 (PCI 0x0406): Linux vmwgfx uses MMIO regs @BAR0, FIFO @BAR1, VRAM @BAR2.
		 * SVGA2 / QEMU: index/value MMIO @BAR0, VRAM @BAR1, FIFO @BAR2.
		 */
		if (pdev->device_id == VMWARE_PCI_DEVICE_SVGA3) {
			g_vmwgfx.regs_mmio_linear = 1;
			if ((bar1 & 0x1u) != 0 || (bar1 & ~0xFu) == 0) {
				klogprintf("vmwgfx: SVGA3 bad BAR1 (fifo) %08x\n", (unsigned)bar1);
				return -1;
			}
			if ((bar2 & 0x1u) != 0 || (bar2 & ~0xFu) == 0) {
				klogprintf("vmwgfx: SVGA3 bad BAR2 (fb) %08x\n", (unsigned)bar2);
				return -1;
			}
			fifo_pa = (uint64_t)(bar1 & ~0xFULL);
			fb_pa = (uint64_t)(bar2 & ~0xFULL);
			g_vmwgfx.fifo_len = vmwgfx_pci_mem_bar_size(pdev, 1);
			if (g_vmwgfx.fifo_len == 0)
				g_vmwgfx.fifo_len = SVGA_DEFAULT_FIFO_BYTES;
			g_vmwgfx.fb_len = vmwgfx_pci_mem_bar_size(pdev, 2);
			if (g_vmwgfx.fb_len == 0) {
				klogprintf("vmwgfx: SVGA3 could not size framebuffer BAR2\n");
				return -1;
			}
			klogprintf("vmwgfx: SVGA3 BAR layout regs@0 fb@2 fifo@1\n");
		} else {
			if ((bar1 & 0x1u) != 0 || (bar1 & ~0xFu) == 0) {
				klogprintf("vmwgfx: bad BAR1 (fb) %08x\n", (unsigned)bar1);
				return -1;
			}
			if ((bar2 & 0x1u) != 0 || (bar2 & ~0xFu) == 0) {
				klogprintf("vmwgfx: bad BAR2 (fifo) %08x\n", (unsigned)bar2);
				return -1;
			}
			fb_pa = (uint64_t)(bar1 & ~0xFULL);
			fifo_pa = (uint64_t)(bar2 & ~0xFULL);
			g_vmwgfx.fifo_len = vmwgfx_pci_mem_bar_size(pdev, 2);
			if (g_vmwgfx.fifo_len == 0)
				g_vmwgfx.fifo_len = SVGA_DEFAULT_FIFO_BYTES;
			g_vmwgfx.fb_len = vmwgfx_pci_mem_bar_size(pdev, 1);
			if (g_vmwgfx.fb_len == 0) {
				klogprintf("vmwgfx: could not size framebuffer BAR\n");
				return -1;
			}
		}
	}

	if (!g_vmwgfx.fb_va) {
		g_vmwgfx.fb_va = mmio_map_framebuffer(fb_pa, g_vmwgfx.fb_len);
		if (!g_vmwgfx.fb_va)
			g_vmwgfx.fb_va = mmio_map_phys(fb_pa, g_vmwgfx.fb_len);
	}
	g_vmwgfx.fifo_va = mmio_map_phys(fifo_pa, g_vmwgfx.fifo_len);
	if (!g_vmwgfx.fifo_va || !g_vmwgfx.fb_va) {
		klogprintf("vmwgfx: mmio_map_phys failed (fifo=%p fb=%p)\n",
		           g_vmwgfx.fifo_va, g_vmwgfx.fb_va);
		return -1;
	}
	g_vmwgfx.fb_pa = fb_pa;
	klogprintf("vmwgfx: mapped fb pa=0x%llx len=%u fifo pa=0x%llx pci dev %04x:%04x\n",
	           (unsigned long long)fb_pa, (unsigned)g_vmwgfx.fb_len,
	           (unsigned long long)fifo_pa,
	           (unsigned)VMWARE_PCI_VENDOR_ID, (unsigned)g_vmwgfx.pci_device_id);

	if (g_vmwgfx.regs_mmio_pa != 0) {
		uint64_t rp = g_vmwgfx.regs_mmio_pa;
		if (rp >= fb_pa && rp + 8u <= fb_pa + (uint64_t)g_vmwgfx.fb_len)
			g_vmwgfx.regs_va = (void *)((uintptr_t)g_vmwgfx.fb_va + (uintptr_t)(rp - fb_pa));
		else if (rp >= fifo_pa && rp + 8u <= fifo_pa + (uint64_t)g_vmwgfx.fifo_len)
			g_vmwgfx.regs_va = (void *)((uintptr_t)g_vmwgfx.fifo_va + (uintptr_t)(rp - fifo_pa));
		else {
			g_vmwgfx.regs_va = mmio_map_phys(rp, 0x1000u);
			if (!g_vmwgfx.regs_va) {
				klogprintf("vmwgfx: mmio_map_phys(SVGA regs) failed pa=0x%llx\n",
				           (unsigned long long)rp);
				return -1;
			}
		}
		/* Embedded index/value window — not SVGA3 linear reg file. */
		g_vmwgfx.regs_mmio_linear = 0;
		g_vmwgfx.regs_mmio_pa = 0;
	}

	svga_reg_write32(&g_vmwgfx, SVGA_REG_ENABLE, 0);
	g_vmwgfx.scanout_on = 0;
	/* Linux=0x5007 per VMware GUEST_OS_BASE table; improves host-side SVGA behavior on some builds. */
	svga_reg_write32(&g_vmwgfx, SVGA_REG_GUEST_ID, 0x5007u);
	if (svga_negotiate_id(&g_vmwgfx) != 0) {
		klogprintf("vmwgfx: SVGA ID negotiation failed\n");
		return -1;
	}

	if (vmwgfx_pick_mode(&g_vmwgfx) != 0) {
		klogprintf("vmwgfx: no usable video mode\n");
		return -1;
	}

	uint64_t need = (uint64_t)g_vmwgfx.fb_offset + (uint64_t)g_vmwgfx.pitch * (uint64_t)g_vmwgfx.height;
	if (need > (uint64_t)g_vmwgfx.fb_len) {
		klogprintf("vmwgfx: framebuffer too small for mode (need %llu have %u)\n",
		           (unsigned long long)need, (unsigned)g_vmwgfx.fb_len);
		return -1;
	}

	g_vmwgfx.present = 1;
	if (!g_vmwgfx.registered) {
		if (vmwgfx_driver_register() != 0)
			return -1;
		g_vmwgfx.registered = 1;
	}
	if (video_probe_all() <= 0)
		return -1;

	video_device_t *vd = video_find_by_name("vmwgfx");
	if (!vd || !vd->mmio_base)
		return -1;

	uint32_t usable = g_vmwgfx.fb_len - g_vmwgfx.fb_offset;
	if (cirrusfb_init(vd->mmio_base, vd->width, vd->height, vd->pitch, vd->bpp, usable, 0) != 0)
		return -1; /* fbcon into SVGA linear aperture; hw_cursor=0 (no Cirrus VGA cursor) */

	/* Turn on host scanout only after the FB has real pixels (avoids black gap after VGA text). */
#if defined(__GNUC__) || defined(__clang__)
	__asm__ volatile("mfence" ::: "memory");
#endif
	svga_reg_write32(&g_vmwgfx, SVGA_REG_ENABLE, 1);
	g_vmwgfx.scanout_on = 1;
	klogprintf("vmwgfx: scanout enabled\n");
	/* Some hosts clear or retile the FB on ENABLE; repaint then push UPDATE. */
	cirrusfb_clear(WHITE_ON_BLACK);
#if defined(__GNUC__) || defined(__clang__)
	__asm__ volatile("mfence" ::: "memory");
#endif
	/* Host display refresh: FIFO UPDATE + SYNC (required on many VMware builds). */
	video_flush_region_pixels(0, 0, vd->width, vd->height);

	fbdev_register_linear(vd->mmio_base, g_vmwgfx.fb_pa + (uint64_t)g_vmwgfx.fb_offset,
	                      (size_t)usable, vd->width, vd->height, vd->pitch, vd->bpp);

	klogprintf("vmwgfx: ready %02x:%02x.%u %ux%u@%u fb=%p pa=0x%llx\n",
	           g_vmwgfx.bus, g_vmwgfx.device, g_vmwgfx.function,
	           (unsigned)vd->width, (unsigned)vd->height, (unsigned)vd->bpp,
	           vd->mmio_base, (unsigned long long)g_vmwgfx.fb_pa);
	s_vmwgfx_kernel_inited = 1;
	return 0;
}
