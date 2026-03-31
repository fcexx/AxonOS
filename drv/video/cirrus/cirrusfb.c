#include <cirrusfb.h>
#include <stdint.h>
#include <string.h>
#include <fonts/default_8x16.h>
#include <vga.h>
#include <klog.h>
#include <video.h>
#include <pit.h>

/* VGA Sequencer registers for Cirrus hardware cursor */
#define VGA_SEQ_INDEX   0x3C4
#define VGA_SEQ_DATA    0x3C5

/* Cirrus Sequencer extension registers */
#define SR12_CURSOR_CTL     0x12  /* Cursor control */
#define SR13_CURSOR_X_LO    0x13  /* Cursor X position low */
#define SR14_CURSOR_X_HI    0x14  /* Cursor X position high + addr */
#define SR10_CURSOR_FG      0x10  /* Cursor foreground color */
#define SR11_CURSOR_BG      0x11  /* Cursor background color */

static inline void seq_write(uint8_t reg, uint8_t val) {
	outb(VGA_SEQ_INDEX, reg);
	outb(VGA_SEQ_DATA, val);
}

static inline uint8_t seq_read(uint8_t reg) {
	outb(VGA_SEQ_INDEX, reg);
	return inb(VGA_SEQ_DATA);
}

static void *g_fb = NULL;
static uint32_t g_width = 0;
static uint32_t g_height = 0;
static uint32_t g_pitch = 0;
static uint32_t g_bpp = 0;
static uint32_t g_fb_size = 0;
static int g_ready = 0;
static int g_hwcursor_ok = 0;

static uint32_t g_cols = 0;
static uint32_t g_rows = 0;
static const uint32_t FONT_W = 8;
static const uint32_t FONT_H = 16;

typedef struct { uint8_t ch; uint8_t attr; } cell_t;
static cell_t *g_textbuf = NULL;
static uint32_t g_cursor_x = 0;
static uint32_t g_cursor_y = 0;
static uint8_t g_current_attr = 0x07;

/* Software cursor (used when hardware cursor isn't available).
   Uses "save-under by redraw": cursor draws an underscore on the bottom scanlines,
   and erase restores the original cell by redrawing its glyph from g_textbuf. */
static int g_swcursor_visible = 1;
static uint64_t g_swcursor_last_phase = 0;

/* ANSI: kputchar() goes straight here when Cirrus is active — devfs may not see all output. */
enum { CIR_ESC_NONE = 0, CIR_ESC_ESC = 1, CIR_ESC_CSI = 2, CIR_ESC_SS3 = 3 };
static int g_esc_state = CIR_ESC_NONE;
static int g_csi_params[8];
static int g_csi_np = 0;
static int g_csi_cur = 0;

static uint32_t vga_palette[16] = {
	0x00000000, 0x000000AA, 0x0000AA00, 0x0000AAAA,
	0x00AA0000, 0x00AA00AA, 0x00AA5500, 0x00AAAAAA,
	0x00555555, 0x005555FF, 0x0055FF55, 0x0055FFFF,
	0x00FF5555, 0x00FF55FF, 0x00FFFF55, 0x00FFFFFF
};

static inline uint32_t attr_to_rgb(uint8_t attr, int fg) {
	uint8_t idx = fg ? (attr & 0x0F) : ((attr >> 4) & 0x0F);
	return vga_palette[idx];
}

static inline uint32_t pack_pixel(uint8_t r, uint8_t g, uint8_t b) {
	if (g_bpp == 32 || g_bpp == 24) {
		/* VMware SVGA / many hosts treat A=0 as fully transparent in 32bpp — force opaque. */
		if (g_bpp == 32)
			return 0xFF000000u | ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
		return ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
	} else if (g_bpp == 16) {
		return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
	} else if (g_bpp == 15) {
		return ((r >> 3) << 10) | ((g >> 3) << 5) | (b >> 3);
	}
	return 0;
}

static inline uint32_t rgb_to_pixel(uint32_t rgb) {
	uint8_t r = (rgb >> 16) & 0xFF;
	uint8_t g = (rgb >> 8) & 0xFF;
	uint8_t b = rgb & 0xFF;
	return pack_pixel(r, g, b);
}

static void draw_glyph(uint32_t cx, uint32_t cy, uint8_t ch, uint8_t attr) {
	if (!g_fb) return;
	uint32_t fg = attr_to_rgb(attr, 1);
	uint32_t bg = attr_to_rgb(attr, 0);
	uint32_t fg_pix = rgb_to_pixel(fg);
	uint32_t bg_pix = rgb_to_pixel(bg);

	uint32_t px = cx * FONT_W;
	uint32_t py = cy * FONT_H;
	uint32_t bpp = (g_bpp + 7) / 8;

	for (uint32_t row = 0; row < FONT_H; row++) {
		uint8_t glyph = font8x16[ch][row];
		uint8_t *line = (uint8_t*)g_fb + (py + row) * g_pitch + px * bpp;
		for (uint32_t bit = 0; bit < FONT_W; bit++) {
			uint32_t pix = (glyph & (1 << (7 - bit))) ? fg_pix : bg_pix;
			if (bpp == 4) {
				*(uint32_t*)(line + bit * 4) = pix;
			} else if (bpp == 3) {
				line[bit * 3 + 0] = pix & 0xFF;
				line[bit * 3 + 1] = (pix >> 8) & 0xFF;
				line[bit * 3 + 2] = (pix >> 16) & 0xFF;
			} else if (bpp == 2) {
				*(uint16_t*)(line + bit * 2) = (uint16_t)pix;
			}
		}
	}
	video_flush_region_pixels(px, py, FONT_W, FONT_H);
}

static void swcursor_erase_at(uint32_t cx, uint32_t cy) {
	if (!g_ready || !g_textbuf) return;
	if (cx >= g_cols || cy >= g_rows) return;
	cell_t c = g_textbuf[cy * g_cols + cx];
	draw_glyph(cx, cy, c.ch, c.attr);
}

static void swcursor_draw_at(uint32_t cx, uint32_t cy) {
	if (!g_ready || !g_textbuf || !g_fb) return;
	if (cx >= g_cols || cy >= g_rows) return;

	uint32_t px = cx * FONT_W;
	uint32_t py = cy * FONT_H;
	uint32_t bpp = (g_bpp + 7) / 8;

	uint8_t attr = g_textbuf[cy * g_cols + cx].attr;
	uint32_t fg_pix = rgb_to_pixel(attr_to_rgb(attr, 1));

	/* Underscore cursor: paint bottom 2 scanlines in FG color. */
	for (uint32_t row = (FONT_H - 2); row < FONT_H; row++) {
		uint8_t *line = (uint8_t*)g_fb + (py + row) * g_pitch + px * bpp;
		for (uint32_t bit = 0; bit < FONT_W; bit++) {
			if (bpp == 4) {
				*(uint32_t*)(line + bit * 4) = fg_pix;
			} else if (bpp == 3) {
				line[bit * 3 + 0] = fg_pix & 0xFF;
				line[bit * 3 + 1] = (fg_pix >> 8) & 0xFF;
				line[bit * 3 + 2] = (fg_pix >> 16) & 0xFF;
			} else if (bpp == 2) {
				*(uint16_t*)(line + bit * 2) = (uint16_t)fg_pix;
			}
		}
	}
	video_flush_region_pixels(px, py + (FONT_H - 2), FONT_W, 2);
}

static void scroll_up(void) {
	if (!g_fb || !g_textbuf) return;
	memmove(g_textbuf, g_textbuf + g_cols, g_cols * (g_rows - 1) * sizeof(cell_t));
	for (uint32_t x = 0; x < g_cols; x++) {
		g_textbuf[(g_rows - 1) * g_cols + x].ch = ' ';
		g_textbuf[(g_rows - 1) * g_cols + x].attr = g_current_attr;
	}
	uint32_t bpp = (g_bpp + 7) / 8;
	size_t row_bytes = g_pitch;
	size_t move_bytes = row_bytes * (g_height - FONT_H);
	memmove(g_fb, (uint8_t*)g_fb + FONT_H * row_bytes, move_bytes);
	uint32_t bg_pix = rgb_to_pixel(attr_to_rgb(g_current_attr, 0));
	uint32_t clear_y = g_height - FONT_H;
	for (uint32_t ry = 0; ry < FONT_H; ry++) {
		uint8_t *line = (uint8_t*)g_fb + (clear_y + ry) * row_bytes;
		for (uint32_t x = 0; x < g_width; x++) {
			if (bpp == 4) *(uint32_t*)(line + x * 4) = bg_pix;
			else if (bpp == 3) { line[x*3]=bg_pix&0xFF; line[x*3+1]=(bg_pix>>8)&0xFF; line[x*3+2]=(bg_pix>>16)&0xFF; }
			else if (bpp == 2) *(uint16_t*)(line + x * 2) = (uint16_t)bg_pix;
		}
	}
	video_flush_region_pixels(0, 0, g_width, g_height);
}

/*
 * Cirrus hardware cursor:
 * - 64x64 pixels, 2 bits per pixel = 1024 bytes
 * - Stored at end of VRAM (address set via SR12 bits)
 * - Format: 00=color0, 01=color1, 10=transparent, 11=XOR
 * - Position set via SR13/SR14
 */
#define HW_CURSOR_SIZE 64
#define HW_CURSOR_BYTES (HW_CURSOR_SIZE * HW_CURSOR_SIZE / 4) /* 1024 bytes */

static uint8_t *g_hwcursor_data = NULL;
static uint32_t g_hwcursor_offset = 0;

static void hwcursor_init(void) {
	/* Place cursor data at end of VRAM, aligned to 1KB */
	if (g_fb_size < HW_CURSOR_BYTES + 0x10000) {
		g_hwcursor_ok = 0;
		return;
	}
	
	/* Cursor address: bits come from SR12[3:2] and SR14[3]
	   Address = bits * 256KB. We'll use address near end of 4MB VRAM.
	   For simplicity, put cursor at offset 0x3FC00 (255KB mark) which gives
	   SR12 bits = 0, SR14 bit 3 = 0, and we write to that VRAM offset. */
	g_hwcursor_offset = g_fb_size - HW_CURSOR_BYTES;
	g_hwcursor_offset &= ~0x3FFu; /* align to 1KB */
	g_hwcursor_data = (uint8_t*)g_fb + g_hwcursor_offset;
	
	/* Clear cursor bitmap to transparent (10 pattern = 0xAA) */
	memset(g_hwcursor_data, 0xAA, HW_CURSOR_BYTES);
	
	/* Draw a vertical bar cursor: 2 pixels wide, 16 pixels tall
	   Each byte = 4 pixels, 2bpp each
	   We'll draw at top-left of 64x64 cursor image */
	for (int row = 0; row < 16; row++) {
		/* Row offset in bytes: row * 64 pixels / 4 pixels_per_byte = row * 16 */
		uint8_t *rowptr = g_hwcursor_data + row * 16;
		/* First 2 pixels as foreground color (01 01 = 0x55 for first byte's high bits)
		   Actually byte layout: pixel0 bits 7-6, pixel1 bits 5-4, pixel2 bits 3-2, pixel3 bits 1-0
		   01 01 10 10 = 0x5A for visible + transparent */
		rowptr[0] = 0x5A; /* 2 white pixels + 2 transparent */
	}
	
	/* Set cursor colors: white foreground, black background */
	seq_write(SR10_CURSOR_FG, 0xFF); /* Cursor color 1 = white (index 15) */
	seq_write(SR11_CURSOR_BG, 0x00); /* Cursor color 0 = black (index 0) */
	
	/* Calculate address bits for SR12 and SR14
	   Cursor address = (SR12[3:2] << 18) | (SR14[3] << 20)
	   Our offset in VRAM / 1024 gives the 1KB block number.
	   But Cirrus uses different addressing - let's use simpler approach:
	   Put cursor at a fixed location that we can address easily. */
	
	/* For QEMU Cirrus emulation, cursor memory starts at VRAM end - 16KB
	   and address bits select which 1KB block within that 16KB region */
	uint8_t addr_bits = (uint8_t)((g_hwcursor_offset >> 10) & 0x3F);
	
	/* SR12: bit 0 = enable, bit 1 = 64x64, bits 3:2 = address low */
	uint8_t sr12 = 0x03 | ((addr_bits & 0x03) << 2); /* Enable + 64x64 + addr bits */
	
	/* SR14: bits 2:0 = X position high, bit 3 = address bit */
	/* We'll set position separately, just set address bit here */
	
	seq_write(SR12_CURSOR_CTL, sr12);
	
	g_hwcursor_ok = 1;
	klogprintf("fbcon: hardware cursor (VGA seq) at offset 0x%x\n", g_hwcursor_offset);
}

static void hwcursor_set_pos(uint32_t x, uint32_t y) {
	if (!g_hwcursor_ok) return;
	
	/* Pixel position for cursor hotspot */
	uint32_t px = x * FONT_W;
	uint32_t py = y * FONT_H + FONT_H - 2; /* Position at bottom of cell (underscore style) */
	
	/* SR13: X position bits 7:0 */
	seq_write(SR13_CURSOR_X_LO, (uint8_t)(px & 0xFF));
	
	/* SR14: X position bits 10:8 in bits 2:0, plus address in bit 3 */
	uint8_t sr14_val = seq_read(SR14_CURSOR_X_HI);
	sr14_val = (sr14_val & 0xF8) | ((px >> 8) & 0x07);
	seq_write(SR14_CURSOR_X_HI, sr14_val);
	
	/* Y position via Graphics Controller registers */
	/* GR10: Y position low, GR11: Y position high */
	outb(0x3CE, 0x10);
	outb(0x3CF, (uint8_t)(py & 0xFF));
	outb(0x3CE, 0x11);
	outb(0x3CF, (uint8_t)((py >> 8) & 0x07));
}

static void hwcursor_enable(int enable) {
	if (!g_hwcursor_ok) return;
	uint8_t sr12 = seq_read(SR12_CURSOR_CTL);
	if (enable)
		sr12 |= 0x01;
	else
		sr12 &= ~0x01;
	seq_write(SR12_CURSOR_CTL, sr12);
}

int cirrusfb_init(void *fb, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp, uint32_t fb_size,
                  int hw_cursor) {
	if (!fb || width == 0 || height == 0) return -1;
	g_fb = fb;
	g_width = width;
	g_height = height;
	g_pitch = pitch;
	g_bpp = bpp;
	g_fb_size = fb_size ? fb_size : (pitch * height);
	g_cols = width / FONT_W;
	g_rows = height / FONT_H;
	if (g_cols == 0 || g_rows == 0) return -1;

	extern void *kmalloc(size_t);
	extern void kfree(void*);
	if (g_textbuf) { kfree(g_textbuf); g_textbuf = NULL; }
	g_textbuf = (cell_t*)kmalloc(g_cols * g_rows * sizeof(cell_t));
	if (!g_textbuf) return -1;

	for (uint32_t i = 0; i < g_cols * g_rows; i++) {
		g_textbuf[i].ch = ' ';
		g_textbuf[i].attr = 0x07;
	}
	g_cursor_x = 0;
	g_cursor_y = 0;
	g_current_attr = 0x07;
	g_swcursor_visible = 1;
	g_swcursor_last_phase = 0;
	g_ready = 1;

	cirrusfb_clear(WHITE_ON_BLACK);

	if (hw_cursor) {
		hwcursor_init();
		if (g_hwcursor_ok)
			hwcursor_set_pos(0, 0);
	} else {
		g_hwcursor_ok = 0;
	}

	/* If no HW cursor, draw initial SW cursor so it is visible immediately. */
	if (!g_hwcursor_ok && g_swcursor_visible) {
		swcursor_draw_at(g_cursor_x, g_cursor_y);
	}
	
	klogprintf("fbcon: linear text console %ux%u cols=%u rows=%u bpp=%u hwcursor=%d\n",
	           width, height, g_cols, g_rows, bpp, g_hwcursor_ok);
	return 0;
}

int cirrusfb_is_ready(void) { return g_ready; }
uint32_t cirrusfb_cols(void) { return g_cols; }
uint32_t cirrusfb_rows(void) { return g_rows; }

void cirrusfb_putch_xy(uint32_t x, uint32_t y, uint8_t ch, uint8_t attr) {
	if (!g_ready || !g_textbuf || x >= g_cols || y >= g_rows) return;
	g_textbuf[y * g_cols + x].ch = ch;
	g_textbuf[y * g_cols + x].attr = attr;
	draw_glyph(x, y, ch, attr);
}

static void cirrusfb_putchar_inner(uint8_t ch, uint8_t attr) {
	if (!g_ready || !g_textbuf) return;
	g_current_attr = attr;

	uint32_t ox = g_cursor_x;
	uint32_t oy = g_cursor_y;

	if (ch == '\n') {
		g_cursor_x = 0;
		g_cursor_y++;
	} else if (ch == '\r') {
		g_cursor_x = 0;
	} else if (ch == '\t') {
		uint32_t newx = (g_cursor_x + 8) & ~7u;
		if (newx >= g_cols) { newx = 0; g_cursor_y++; }
		while (g_cursor_x < newx && g_cursor_x < g_cols) {
			g_textbuf[oy * g_cols + g_cursor_x].ch = ' ';
			g_textbuf[oy * g_cols + g_cursor_x].attr = g_current_attr;
			draw_glyph(g_cursor_x, oy, ' ', g_current_attr);
			g_cursor_x++;
		}
	} else if (ch == '\b') {
		if (g_cursor_x > 0) g_cursor_x--;
		g_textbuf[g_cursor_y * g_cols + g_cursor_x].ch = ' ';
		g_textbuf[g_cursor_y * g_cols + g_cursor_x].attr = g_current_attr;
		draw_glyph(g_cursor_x, g_cursor_y, ' ', g_current_attr);
	} else {
		g_textbuf[oy * g_cols + ox].ch = ch;
		g_textbuf[oy * g_cols + ox].attr = g_current_attr;
		draw_glyph(ox, oy, ch, g_current_attr);
		g_cursor_x++;
		if (g_cursor_x >= g_cols) { g_cursor_x = 0; g_cursor_y++; }
	}

	if (g_cursor_y >= g_rows) {
		/* Ensure cursor doesn't get "stuck" in scrolled pixels. */
		if (!g_hwcursor_ok && g_swcursor_visible) {
			swcursor_erase_at(ox, oy);
		}
		scroll_up();
		g_cursor_y = g_rows - 1;
	}

	if (g_hwcursor_ok) {
		hwcursor_set_pos(g_cursor_x, g_cursor_y);
	} else {
		/* If cursor moved without overwriting the old cell (e.g. newline), erase underline there. */
		if (g_swcursor_visible && (ox != g_cursor_x || oy != g_cursor_y)) {
			swcursor_erase_at(ox, oy);
		}
		if (g_swcursor_visible) {
			swcursor_draw_at(g_cursor_x, g_cursor_y);
		}
	}
}

void cirrusfb_putchar_literal(uint8_t ch, uint8_t attr) {
	if (!g_ready || !g_textbuf) return;
	cirrusfb_putchar_inner(ch, attr);
}

void cirrusfb_set_cursor(uint32_t x, uint32_t y) {
	if (!g_ready) return;
	if (x >= g_cols) x = g_cols - 1;
	if (y >= g_rows) y = g_rows - 1;
	uint32_t ox = g_cursor_x, oy = g_cursor_y;
	if (!g_hwcursor_ok && g_swcursor_visible) {
		swcursor_erase_at(ox, oy);
	}
	g_cursor_x = x;
	g_cursor_y = y;
	
	if (g_hwcursor_ok) {
		hwcursor_set_pos(x, y);
	} else {
		if (g_swcursor_visible) swcursor_draw_at(x, y);
	}
}

void cirrusfb_get_cursor(uint32_t *x, uint32_t *y) {
	if (x) *x = g_cursor_x;
	if (y) *y = g_cursor_y;
}

uint8_t cirrusfb_get_cell_attr(uint32_t x, uint32_t y) {
	if (!g_ready || !g_textbuf || x >= g_cols || y >= g_rows)
		return 0x07;
	return g_textbuf[y * g_cols + x].attr;
}

void cirrusfb_snapshot_screen(uint8_t *out, size_t max_bytes) {
	if (!g_ready || !g_textbuf || !out) return;
	size_t need = (size_t)g_cols * (size_t)g_rows * 2u;
	if (need > max_bytes) return;
	memcpy(out, g_textbuf, need);
}

void cirrusfb_restore_screen(const uint8_t *src, uint32_t cols, uint32_t rows) {
	if (!g_ready || !g_textbuf || !src) return;
	if (cols != g_cols || rows != g_rows) return;
	for (uint32_t y = 0; y < rows; y++) {
		for (uint32_t x = 0; x < cols; x++) {
			size_t off = ((size_t)y * cols + x) * 2u;
			cirrusfb_putch_xy(x, y, src[off], src[off + 1]);
		}
	}
}

void cirrusfb_clear(uint8_t attr) {
	if (!g_ready || !g_textbuf) return;
	g_current_attr = attr;
	for (uint32_t i = 0; i < g_cols * g_rows; i++) {
		g_textbuf[i].ch = ' ';
		g_textbuf[i].attr = attr;
	}
	uint32_t bg_pix = rgb_to_pixel(attr_to_rgb(attr, 0));
	uint32_t bpp = (g_bpp + 7) / 8;
	for (uint32_t y = 0; y < g_height; y++) {
		uint8_t *line = (uint8_t*)g_fb + y * g_pitch;
		for (uint32_t x = 0; x < g_width; x++) {
			if (bpp == 4) *(uint32_t*)(line + x * 4) = bg_pix;
			else if (bpp == 3) { line[x*3]=bg_pix&0xFF; line[x*3+1]=(bg_pix>>8)&0xFF; line[x*3+2]=(bg_pix>>16)&0xFF; }
			else if (bpp == 2) *(uint16_t*)(line + x * 2) = (uint16_t)bg_pix;
		}
	}
	g_cursor_x = 0;
	g_cursor_y = 0;
	
	if (g_hwcursor_ok) {
		hwcursor_set_pos(0, 0);
	}
	video_flush_region_pixels(0, 0, g_width, g_height);
}

static void cirrusfb_erase_cells(uint32_t x0, uint32_t x1, uint32_t y) {
	if (!g_ready || !g_textbuf || g_rows == 0 || g_cols == 0 || y >= g_rows) return;
	if (x0 > x1) return;
	if (x1 >= g_cols) x1 = g_cols - 1;
	for (uint32_t x = x0; x <= x1; x++) {
		g_textbuf[y * g_cols + x].ch = ' ';
		g_textbuf[y * g_cols + x].attr = g_current_attr;
		draw_glyph(x, y, ' ', g_current_attr);
	}
}

static void cirrusfb_csi_apply_sgr(void) {
	int np = g_csi_np;
	int *p = g_csi_params;
	if (np == 0) {
		g_current_attr = 0x07;
		return;
	}
	for (int i = 0; i < np; i++) {
		int v = p[i];
		if (v == 0) {
			g_current_attr = 0x07;
		} else if (v == 1) {
			g_current_attr |= 0x08;
		} else if (v == 22) {
			g_current_attr &= (uint8_t)~0x08;
		} else if (v >= 30 && v <= 37) {
			static const uint8_t map[8] = {0, 4, 2, 6, 1, 5, 3, 7};
			int fg = map[v - 30];
			if (g_current_attr & 0x08) fg |= 8;
			int bg = (g_current_attr >> 4) & 0x0F;
			g_current_attr = (uint8_t)((bg << 4) | (fg & 0x0F));
		} else if (v >= 40 && v <= 47) {
			static const uint8_t bmap[8] = {0, 4, 2, 6, 1, 5, 3, 0};
			int bg = bmap[v - 40];
			int fg = g_current_attr & 0x0F;
			g_current_attr = (uint8_t)((bg << 4) | (fg & 0x0F));
		}
	}
}

static void cirrusfb_csi_dispatch(uint8_t fb) {
	int np = g_csi_np;
	int *p = g_csi_params;

	if (fb == 'm') {
		cirrusfb_csi_apply_sgr();
		return;
	}
	if (fb == 'H' || fb == 'f') {
		int row = 1, col = 1;
		if (np >= 1) row = p[0];
		if (np >= 2) col = p[1];
		if (row < 1) row = 1;
		if (col < 1) col = 1;
		if ((uint32_t)row > g_rows) row = (int)g_rows;
		if ((uint32_t)col > g_cols) col = (int)g_cols;
		cirrusfb_set_cursor((uint32_t)(col - 1), (uint32_t)(row - 1));
		return;
	}
	if (fb == 'J') {
		int pm = (np > 0) ? p[0] : 0;
		if (pm == 2 || pm == 3) {
			cirrusfb_clear(g_current_attr);
			return;
		}
		if (pm == 0) {
			cirrusfb_erase_cells(g_cursor_x, g_cols - 1, g_cursor_y);
			for (uint32_t yy = g_cursor_y + 1; yy < g_rows; yy++) {
				cirrusfb_erase_cells(0, g_cols - 1, yy);
			}
			return;
		}
		if (pm == 1) {
			for (uint32_t yy = 0; yy < g_cursor_y; yy++) {
				cirrusfb_erase_cells(0, g_cols - 1, yy);
			}
			cirrusfb_erase_cells(0, g_cursor_x, g_cursor_y);
			return;
		}
	}
	if (fb == 'K') {
		int pm = (np > 0) ? p[0] : 0;
		uint32_t cy = g_cursor_y;
		if (pm == 0) {
			cirrusfb_erase_cells(g_cursor_x, g_cols - 1, cy);
		} else if (pm == 1) {
			cirrusfb_erase_cells(0, g_cursor_x, cy);
		} else {
			cirrusfb_erase_cells(0, g_cols - 1, cy);
		}
		return;
	}
	if (fb == 'A' || fb == 'B' || fb == 'C' || fb == 'D') {
		int n = (np > 0 && p[0] > 0) ? p[0] : 1;
		if (fb == 'A') {
			if (g_cursor_y >= (uint32_t)n) g_cursor_y -= (uint32_t)n;
			else g_cursor_y = 0;
		} else if (fb == 'B') {
			if (g_cursor_y + (uint32_t)n < g_rows) g_cursor_y += (uint32_t)n;
			else g_cursor_y = g_rows - 1;
		} else if (fb == 'C') {
			if (g_cursor_x + (uint32_t)n < g_cols) g_cursor_x += (uint32_t)n;
			else g_cursor_x = g_cols - 1;
		} else {
			if (g_cursor_x >= (uint32_t)n) g_cursor_x -= (uint32_t)n;
			else g_cursor_x = 0;
		}
		if (g_hwcursor_ok) {
			hwcursor_set_pos(g_cursor_x, g_cursor_y);
		}
	}
}

void cirrusfb_putchar(uint8_t ch, uint8_t attr) {
	if (!g_ready || !g_textbuf) return;

	if (g_esc_state == CIR_ESC_NONE) {
		if (ch == 0x1B) {
			g_esc_state = CIR_ESC_ESC;
			return;
		}
		cirrusfb_putchar_inner(ch, attr);
		return;
	}
	if (g_esc_state == CIR_ESC_ESC) {
		if (ch == '[') {
			g_esc_state = CIR_ESC_CSI;
			g_csi_np = 0;
			g_csi_cur = 0;
			return;
		}
		if (ch == 'O') {
			g_esc_state = CIR_ESC_SS3;
			return;
		}
		g_esc_state = CIR_ESC_NONE;
		cirrusfb_putchar_inner(0x1B, attr);
		cirrusfb_putchar_inner(ch, attr);
		return;
	}
	if (g_esc_state == CIR_ESC_SS3) {
		g_esc_state = CIR_ESC_NONE;
		return;
	}
	/* CSI */
	if (ch >= '0' && ch <= '9') {
		g_csi_cur = g_csi_cur * 10 + (ch - '0');
		return;
	}
	if (ch == ';') {
		if (g_csi_np < 8) g_csi_params[g_csi_np++] = g_csi_cur;
		g_csi_cur = 0;
		return;
	}
	if (ch == '?' || ch == '>') {
		return;
	}
	if (g_csi_np < 8) g_csi_params[g_csi_np++] = g_csi_cur;
	g_csi_cur = 0;
	if ((unsigned char)ch >= 0x40 && (unsigned char)ch <= 0x7E) {
		g_current_attr = attr;
		cirrusfb_csi_dispatch((uint8_t)ch);
	}
	g_esc_state = CIR_ESC_NONE;
	g_csi_np = 0;
}

void cirrusfb_update_cursor(void) {
	if (!g_ready) return;
	if (g_hwcursor_ok) {
		/* Hardware cursor blinks automatically. */
		return;
	}
	/* Blink based on absolute monotonic time so it remains stable even if
	   timer IRQs are delayed by load/exception handling (catch-up on next tick). */
	const uint64_t period_ticks = 500; /* ~500ms when timer_ticks is 1ms */
	uint64_t phase = (period_ticks != 0) ? (timer_ticks / period_ticks) : 0;
	if (phase == g_swcursor_last_phase) return;
	g_swcursor_last_phase = phase;
	int want_visible = ((phase & 1ULL) == 0ULL) ? 1 : 0;
	if (want_visible == g_swcursor_visible) return;
	g_swcursor_visible = want_visible;
	if (g_swcursor_visible) swcursor_draw_at(g_cursor_x, g_cursor_y);
	else swcursor_erase_at(g_cursor_x, g_cursor_y);
}
