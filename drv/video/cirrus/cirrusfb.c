#include <cirrusfb.h>
#include <stdint.h>
#include <string.h>
#include <fonts/default_8x16.h>
#include <vga.h>
#include <klog.h>

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
	klogprintf("cirrusfb: hardware cursor enabled at offset 0x%x\n", g_hwcursor_offset);
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

int cirrusfb_init(void *fb, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp, uint32_t fb_size) {
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
	g_ready = 1;

	cirrusfb_clear(WHITE_ON_BLACK);
	
	/* Initialize hardware cursor */
	hwcursor_init();
	if (g_hwcursor_ok) {
		hwcursor_set_pos(0, 0);
	}
	
	klogprintf("cirrusfb: initialized %ux%u cols=%u rows=%u bpp=%u hwcursor=%d\n",
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

void cirrusfb_putchar(uint8_t ch, uint8_t attr) {
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
		scroll_up();
		g_cursor_y = g_rows - 1;
	}
	
	/* Update hardware cursor position */
	if (g_hwcursor_ok) {
		hwcursor_set_pos(g_cursor_x, g_cursor_y);
	}
}

void cirrusfb_set_cursor(uint32_t x, uint32_t y) {
	if (!g_ready) return;
	if (x >= g_cols) x = g_cols - 1;
	if (y >= g_rows) y = g_rows - 1;
	g_cursor_x = x;
	g_cursor_y = y;
	
	if (g_hwcursor_ok) {
		hwcursor_set_pos(x, y);
	}
}

void cirrusfb_get_cursor(uint32_t *x, uint32_t *y) {
	if (x) *x = g_cursor_x;
	if (y) *y = g_cursor_y;
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
}

void cirrusfb_update_cursor(void) {
	/* Hardware cursor blinks automatically - nothing to do here */
	(void)0;
}
