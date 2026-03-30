#include <vbe.h>
#include <stdint.h>
#include <string.h>
#include <mmio.h>
#include <heap.h>
#include <fonts/default_8x16.h>
#include <vga.h>
#include <klog.h>

/* Simple framebuffer console built on top of vbe double-buffer */
extern int vbe_is_available(void);
extern void vbe_flush_full(void);
extern void vbe_flush_region(uint32_t x, uint32_t y, uint32_t w, uint32_t h);
extern void *vbe_get_backbuffer(void);
extern uint32_t vbe_get_pitch(void);
extern uint32_t vbe_get_bpp(void);
extern uint32_t vbe_get_width(void);
extern uint32_t vbe_get_height(void);

static uint32_t fb_width = 0;
static uint32_t fb_height = 0;
static uint32_t fb_pitch = 0;
static uint32_t fb_bpp = 0;
static uint32_t bytes_per_pixel = 4;

static uint32_t cols = 0;
static uint32_t rows = 0;
uint32_t font_w = 8;
uint32_t font_h = 16;

typedef struct { uint8_t ch; uint8_t attr; } cell_t;
static cell_t *textbuf = NULL;
static uint32_t cursor_x = 0;
static uint32_t cursor_y = 0;
static uint8_t current_attr = 0x07; /* default light gray on black */
static int esc_mode = 0;
static char esc_buf[32];
static int esc_len = 0;
static int cursor_visible = 1; /* cursor blink state */
static uint32_t cursor_blink_counter = 0;

void draw_cursor(void);
void erase_cursor(void);

static uint32_t vga_palette[16] = {
	0x00000000, 0x000000AA, 0x0000AA00, 0x0000AAAA,
	0x00AA0000, 0x00AA00AA, 0x00AA5500, 0x00AAAAAA,
	0x00555555, 0x005555FF, 0x0055FF55, 0x0055FFFF,
	0x00FF5555, 0x00FF55FF, 0x00FFFF55, 0x00FFFFFF
};

static inline uint32_t vga_attr_to_rgb(uint8_t attr, int foreground) {
	uint8_t col = foreground ? (attr & 0x0f) : ((attr >> 4) & 0x0f);
	return vga_palette[col];
}

static inline uint32_t vga_attr_bg_to_pixel(uint8_t attr) {
	uint32_t bg = vga_attr_to_rgb(attr, 0);
	uint8_t r = (uint8_t)((bg >> 16) & 0xFF);
	uint8_t g = (uint8_t)((bg >> 8) & 0xFF);
	uint8_t b = (uint8_t)(bg & 0xFF);
	return vbe_pack_pixel(r, g, b);
}

static void draw_cell_to_backbuffer(uint32_t cx, uint32_t cy) {
	if (!textbuf) return;
	uint8_t ch = textbuf[cy * cols + cx].ch;
	uint8_t attr = textbuf[cy * cols + cx].attr;

	uint32_t fg = vga_attr_to_rgb(attr, 1);
	uint32_t bg = vga_attr_to_rgb(attr, 0);

	uint8_t *front = (uint8_t*)vbe_get_frontbuffer();
	if (!front) return;

	uint32_t px = cx * font_w;
	uint32_t py = cy * font_h;
	uint32_t pitch = vbe_get_pitch();
	uint32_t bytespp = (vbe_get_bpp() + 7) / 8;

	for (uint32_t row = 0; row < font_h; row++) {
		uint8_t glyph = font8x16[(uint8_t)ch][row];
		uint8_t *line = front + (size_t)( (py + row) * pitch + px * bytespp );
		for (uint32_t bit = 0; bit < font_w; bit++) {
			uint32_t pal = (glyph & (1 << (7 - bit))) ? fg : bg; /* 0x00RRGGBB */
			/* map pal (8-bit per channel) into framebuffer's RGB fields */
			uint32_t r = (pal >> 16) & 0xFF;
			uint32_t g = (pal >> 8) & 0xFF;
			uint32_t b = pal & 0xFF;
			uint32_t pixel = vbe_pack_pixel((uint8_t)r, (uint8_t)g, (uint8_t)b);
			/* write pixel as little-endian bytes */
			if (bytespp == 4) {
				*(uint32_t*)(line + bit * 4) = pixel;
			} else if (bytespp == 3) {
				line[bit*3 + 0] = (uint8_t)(pixel & 0xFF);
				line[bit*3 + 1] = (uint8_t)((pixel >> 8) & 0xFF);
				line[bit*3 + 2] = (uint8_t)((pixel >> 16) & 0xFF);
			} else if (bytespp == 2) {
				line[bit*2 + 0] = (uint8_t)(pixel & 0xFF);
				line[bit*2 + 1] = (uint8_t)((pixel >> 8) & 0xFF);
			}
		}
	}
}

void vbefb_putch_xy(uint32_t x, uint32_t y, uint8_t ch, uint8_t attr) {
	if (!vbe_is_available() || !textbuf) return;
	if (x >= cols || y >= rows) return;
	textbuf[y * cols + x].ch = ch;
	textbuf[y * cols + x].attr = attr;
	draw_cell_to_backbuffer(x, y);
	vbe_flush_region(x * font_w, y * font_h, font_w, font_h);
}

static void vbefb_erase_cells(uint32_t x0, uint32_t x1, uint32_t y) {
	if (!textbuf || rows == 0 || cols == 0 || y >= rows) return;
	if (x0 > x1) return;
	if (x1 >= cols) x1 = cols - 1;
	for (uint32_t x = x0; x <= x1; x++) {
		textbuf[y * cols + x].ch = ' ';
		textbuf[y * cols + x].attr = current_attr;
		draw_cell_to_backbuffer(x, y);
	}
}

static void vbefb_emit_tty_char(uint8_t ch) {
	int control_path = (ch == '\n' || ch == '\r' || ch == '\t' || ch == '\b');
	uint32_t old_cx = cursor_x;
	uint32_t old_cy = cursor_y;
	if (control_path && cursor_visible && old_cx < cols && old_cy < rows) {
		uint32_t save_x = cursor_x, save_y = cursor_y;
		cursor_x = old_cx; cursor_y = old_cy;
		erase_cursor();
		cursor_x = save_x; cursor_y = save_y;
	}

	uint32_t ox = cursor_x;
	uint32_t oy = cursor_y;

	if (ch == '\n') {
		cursor_x = 0;
		cursor_y++;
	} else if (ch == '\r') {
		cursor_x = 0;
	} else if (ch == '\t') {
		uint32_t newx = (cursor_x + 8) & ~(8 - 1);
		if (newx >= cols) { newx = 0; cursor_y++; }
		for (uint32_t tx = ox; tx != newx; tx = (tx + 1) % cols) {
			textbuf[oy * cols + tx].ch = ' ';
			textbuf[oy * cols + tx].attr = current_attr;
		}
		cursor_x = newx;
	} else if (ch == '\b') {
		if (cursor_x > 0) cursor_x--;
		textbuf[cursor_y * cols + cursor_x].ch = ' ';
		textbuf[cursor_y * cols + cursor_x].attr = current_attr;
		ox = cursor_x; oy = cursor_y;
	} else {
		textbuf[oy * cols + ox].ch = ch;
		textbuf[oy * cols + ox].attr = current_attr;
		cursor_x++;
		if (cursor_x >= cols) { cursor_x = 0; cursor_y++; }
	}

	if (cursor_y >= rows) {
		memmove(textbuf, textbuf + cols, (size_t)(cols * (rows - 1) * sizeof(cell_t)));
		uint32_t last_row = rows - 1;
		for (uint32_t rx = 0; rx < cols; rx++) {
			textbuf[last_row * cols + rx].ch = ' ';
			textbuf[last_row * cols + rx].attr = current_attr;
		}
		cursor_y = rows - 1;
		vbe_scroll_up_pixels(font_h);
		vbe_clear_region(0, last_row * font_h, fb_width, font_h, vga_attr_bg_to_pixel(current_attr));
		if (cursor_visible)
			draw_cursor();
		vbe_flush_region(0, last_row * font_h, fb_width, font_h);
	} else {
		draw_cell_to_backbuffer(ox, oy);
		if (cursor_visible)
			draw_cursor();
	}
}

void vbefb_putchar(uint8_t ch, uint8_t attr) {
	if (!vbe_is_available()) { return; }
	/* Honor caller-selected color when printing raw chars (devfs/tty path). */
	if (!esc_mode && ch != 0x1B) current_attr = attr;
	/* CSI: ESC [ ... final (@ to ~). Was SGR-only; other finals were swallowed and broke the console. */
	if (ch == 0x1B) { esc_mode = 1; esc_len = 0; return; }
	if (esc_mode) {
		if (esc_len < (int)sizeof(esc_buf) - 1) esc_buf[esc_len++] = (char)ch;
		if (ch == 'm') {
			esc_buf[esc_len] = '\0';
			/* Parse CSI SGR: ESC [ ... m — same semantics as VGA console */
			char *s = esc_buf;
			if (*s == '[') s++;
			uint8_t fg = current_attr & 0x0F;
			uint8_t bg = (current_attr >> 4) & 0x0F;
			while (*s && *s != 'm') {
				int val = 0;
				if (*s == ';') { s++; continue; }
				while (*s >= '0' && *s <= '9') { val = val * 10 + (*s - '0'); s++; }
				if (val == 0) { fg = 7; bg = 0; }
				else if (val == 1) { fg |= 0x08; } /* bold -> bright fg */
				else if (val >= 30 && val <= 37) {
					fg = (uint8_t)((fg & 0x08) | (val - 30));
				} else if (val >= 40 && val <= 47) {
					bg = (uint8_t)(val - 40);
				} else if (val >= 90 && val <= 97) {
					fg = (uint8_t)(val - 90 + 8); /* bright fg */
				} else if (val >= 100 && val <= 107) {
					bg = (uint8_t)(val - 100 + 8); /* bright bg */
				}
				if (*s == ';') s++;
			}
			current_attr = (uint8_t)((bg << 4) | (fg & 0x0F));
			esc_mode = 0;
			esc_len = 0;
			return;
		}
		if (ch >= 0x40 && ch <= 0x7E) {
			int p[8], np = 0, cur = 0;
			if (esc_len >= 2 && esc_buf[0] == '[') {
				for (int i = 1; i < esc_len - 1; i++) {
					char c = esc_buf[i];
					if (c >= '0' && c <= '9') { cur = cur * 10 + (c - '0'); continue; }
					if (c == ';') { if (np < 8) p[np++] = cur; cur = 0; continue; }
					if (c == '?' || c == '>') continue;
				}
				if (np < 8) p[np++] = cur;
			}
			if (ch == 'H' || ch == 'f') {
				int row = (np >= 1) ? p[0] : 1;
				int col = (np >= 2) ? p[1] : 1;
				if (row < 1) row = 1;
				if (col < 1) col = 1;
				if ((uint32_t)row > rows) row = (int)rows;
				if ((uint32_t)col > cols) col = (int)cols;
				vbefb_set_cursor((uint32_t)(col - 1), (uint32_t)(row - 1));
			} else if (ch == 'J') {
				int pm = (np > 0) ? p[0] : 0;
				if (pm == 2 || pm == 3) {
					vbefb_clear(current_attr);
				} else if (pm == 0) {
					vbefb_erase_cells(cursor_x, cols - 1, cursor_y);
					for (uint32_t yy = cursor_y + 1; yy < rows; yy++) {
						vbefb_erase_cells(0, cols - 1, yy);
					}
				} else if (pm == 1) {
					for (uint32_t yy = 0; yy < cursor_y; yy++) {
						vbefb_erase_cells(0, cols - 1, yy);
					}
					vbefb_erase_cells(0, cursor_x, cursor_y);
				}
			} else if (ch == 'K') {
				int pm = (np > 0) ? p[0] : 0;
				uint32_t cy = cursor_y;
				if (pm == 0) {
					vbefb_erase_cells(cursor_x, cols - 1, cy);
				} else if (pm == 1) {
					vbefb_erase_cells(0, cursor_x, cy);
				} else {
					vbefb_erase_cells(0, cols - 1, cy);
				}
			} else if (ch == 'A' || ch == 'B' || ch == 'C' || ch == 'D') {
				int n = (np > 0 && p[0] > 0) ? p[0] : 1;
				uint32_t nx = cursor_x, ny = cursor_y;
				if (ch == 'A') {
					if (ny >= (uint32_t)n) ny -= (uint32_t)n; else ny = 0;
				} else if (ch == 'B') {
					if (ny + (uint32_t)n < rows) ny += (uint32_t)n; else ny = rows - 1;
				} else if (ch == 'C') {
					if (nx + (uint32_t)n < cols) nx += (uint32_t)n; else nx = cols - 1;
				} else {
					if (nx >= (uint32_t)n) nx -= (uint32_t)n; else nx = 0;
				}
				vbefb_set_cursor(nx, ny);
			}
			esc_mode = 0;
			esc_len = 0;
			return;
		}
		return;
	}

	vbefb_emit_tty_char(ch);
}

void vbefb_putchar_literal(uint8_t ch, uint8_t attr) {
	if (!vbe_is_available()) return;
	esc_mode = 0;
	esc_len = 0;
	current_attr = attr;
	vbefb_emit_tty_char(ch);
}

void draw_cursor(void) {
	if (!vbe_is_available() || !textbuf) return;
	if (cursor_x >= cols || cursor_y >= rows) return;
	
	uint8_t *front = (uint8_t*)vbe_get_frontbuffer();
	if (!front) return;
	
	uint32_t px = cursor_x * font_w;
	uint32_t py = cursor_y * font_h;
	uint32_t pitch = vbe_get_pitch();
	uint32_t bytespp = (vbe_get_bpp() + 7) / 8;
	
	/* get cell colors */
	uint8_t attr = textbuf[cursor_y * cols + cursor_x].attr;
	uint32_t fg = vga_attr_to_rgb(attr, 1);
	uint32_t bg = vga_attr_to_rgb(attr, 0);
	
	/* cursor: draw foreground color on bottom 2 scanlines (like VGA hardware cursor) */
	uint32_t cursor_start_row = font_h - 2;
	for (uint32_t row = cursor_start_row; row < font_h; row++) {
		uint8_t *line = front + (size_t)( (py + row) * pitch + px * bytespp );
		for (uint32_t bit = 0; bit < font_w; bit++) {
			/* draw cursor with foreground color (visible on dark background) */
			uint32_t r = (fg >> 16) & 0xFF;
			uint32_t g = (fg >> 8) & 0xFF;
			uint32_t b = fg & 0xFF;
			uint32_t pixel = vbe_pack_pixel((uint8_t)r, (uint8_t)g, (uint8_t)b);
			if (bytespp == 4) {
				*(uint32_t*)(line + bit * 4) = pixel;
			} else if (bytespp == 3) {
				line[bit*3 + 0] = (uint8_t)(pixel & 0xFF);
				line[bit*3 + 1] = (uint8_t)((pixel >> 8) & 0xFF);
				line[bit*3 + 2] = (uint8_t)((pixel >> 16) & 0xFF);
			} else if (bytespp == 2) {
				line[bit*2 + 0] = (uint8_t)(pixel & 0xFF);
				line[bit*2 + 1] = (uint8_t)((pixel >> 8) & 0xFF);
			}
		}
	}
}

void erase_cursor(void) {
	if (!vbe_is_available() || !textbuf) return;
	if (cursor_x >= cols || cursor_y >= rows) return;
	/* redraw cell normally (restores original appearance) */
	draw_cell_to_backbuffer(cursor_x, cursor_y);
}

void vbefb_update_cursor(void) {
	if (!vbe_is_available()) return;
	/* Keep blink perceptible on both 100Hz and 1000Hz timer setups. */
	cursor_blink_counter++;
	if (cursor_blink_counter >= 120) {
		cursor_blink_counter = 0;
		cursor_visible = !cursor_visible;
		if (cursor_visible) {
			draw_cursor();
		} else {
			erase_cursor();
		}
	}
}

void vbefb_putn(char ch, int count, uint8_t attr) {
	for (int i = 0; i < count; i++) vbefb_putchar((uint8_t)ch, attr);
}

void vbefb_get_cursor(uint32_t *x, uint32_t *y) {
	if (!x || !y) return;
	*x = cursor_x; *y = cursor_y;
}

void vbefb_set_cursor(uint32_t x, uint32_t y) {
	if (x >= cols) x = cols - 1;
	if (y >= rows) y = rows - 1;
	/* erase old cursor */
	if (cursor_visible) erase_cursor();
	cursor_x = x; cursor_y = y;
	/* draw new cursor */
	if (cursor_visible) draw_cursor();
}

void vbefb_clear(uint8_t attr) {
	if (!vbe_is_available() || !textbuf) return;
	current_attr = attr;
	for (uint32_t i = 0; i < (uint32_t)(cols * rows); i++) {
		textbuf[i].ch = ' ';
		textbuf[i].attr = attr;
	}
	for (uint32_t ry = 0; ry < rows; ry++)
		for (uint32_t rx = 0; rx < cols; rx++)
			draw_cell_to_backbuffer(rx, ry);
	vbefb_set_cursor(0, 0);
}

/* Initialize console state after vbe init; called externally if needed */
int vbefb_init(uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp) {
	fb_width = width; fb_height = height; fb_pitch = pitch; fb_bpp = bpp;
	bytes_per_pixel = (fb_bpp + 7) / 8;
	cols = fb_width / font_w;
	rows = fb_height / font_h;
	if (cols == 0 || rows == 0) return -1;
	if (textbuf) {
		kfree(textbuf);
		textbuf = NULL;
	}
	textbuf = (cell_t*)kmalloc((size_t)cols * rows * sizeof(cell_t));
	if (!textbuf) return -1;
	memset(textbuf, 0, (size_t)cols * rows * sizeof(cell_t));
	cursor_x = 0; cursor_y = 0;
	cursor_visible = 1;
	cursor_blink_counter = 0;
	current_attr = 0x07;
	esc_mode = 0;
	esc_len = 0;
	klogprintf("vbefb: initialized cols=%u rows=%u\n", (unsigned)cols, (unsigned)rows);
	/* Full clear avoids random VRAM garbage after modeset and ensures visible cursor colors. */
	vbefb_clear(WHITE_ON_BLACK);
	return 0;
}


