#include <console.h>
#include <vbe.h>
#include <vga.h>
#include <stdint.h>

void console_putch_xy(uint32_t x, uint32_t y, uint8_t ch, uint8_t attr) {
	if (vbe_is_available()) {
		/* vbefb expects character writes via its putchar; compute linear writes */
		/* Provide simple implementation: set cursor then putchar */
		vbefb_set_cursor(x, y);
		vbefb_putchar(ch, attr);
	} else {
		vga_putch_xy(x, y, ch, attr);
	}
}

int console_max_cols() {
	if (vbe_is_available()) {
		uint32_t w = vbe_get_width();
		uint32_t fontw = 8; /* vbefb uses 8x16 font */
		if (fontw == 0) return MAX_COLS;
		return (int)(w / fontw);
	}
	return MAX_COLS;
}

void console_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint8_t ch, uint8_t attr) {
	if (vbe_is_available()) {
		for (uint32_t ry = 0; ry < h; ry++) {
			for (uint32_t rx = 0; rx < w; rx++) {
				vbefb_set_cursor(x + rx, y + ry);
				vbefb_putchar(ch, attr);
			}
		}
	} else {
		for (uint32_t ry = 0; ry < h; ry++) {
			for (uint32_t rx = 0; rx < w; rx++) {
				vga_putch_xy(x + rx, y + ry, ch, attr);
			}
		}
	}
}

void console_write_str_xy(uint32_t x, uint32_t y, const char *s, uint8_t attr) {
	if (!s) return;
	if (vbe_is_available()) {
		/* write sequentially using putch */
		uint32_t cx = x, cy = y;
		for (size_t i = 0; s[i]; i++) {
			vbefb_set_cursor(cx, cy);
			vbefb_putchar((uint8_t)s[i], attr);
			cx++;
			if (cx >= MAX_COLS) { cx = 0; cy++; }
		}
	} else {
		vga_write_str_xy(x, y, s, attr);
	}
}

void console_set_cursor(uint32_t x, uint32_t y) {
	if (vbe_is_available()) { vbefb_set_cursor(x,y); return; }
	vga_set_cursor(x,y);
}

void console_get_cursor(uint32_t *x, uint32_t *y) {
	if (vbe_is_available()) { vbefb_get_cursor(x,y); return; }
	vga_get_cursor(x,y);
}


