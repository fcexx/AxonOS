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
		/* write sequentially using putch; handle ANSI sequences without advancing cursor */
		uint32_t cx = x, cy = y;
		for (size_t i = 0; s[i]; ) {
			if (s[i] == 0x1B && s[i+1] == '[') {
				/* pass entire CSI sequence to vbefb_putchar without advancing cursor */
				size_t j = i;
				/* find terminator 'm' or end */
				while (s[j] && s[j] != 'm') j++;
				if (s[j] == 'm') {
					for (size_t k = i; k <= j; k++) {
						vbefb_putchar((uint8_t)s[k], attr);
					}
					i = j + 1;
					continue;
				}
				/* malformed: fallthrough to send single char */
			}
			/* printable or normal char: set cursor then print */
			vbefb_set_cursor(cx, cy);
			vbefb_putchar((uint8_t)s[i], attr);
			i++;
			cx++;
			if (cx >= (uint32_t)console_max_cols()) { cx = 0; cy++; }
		}
	} else {
		/* Parse ANSI SGR sequences and map to VGA attributes */
		uint32_t cx = x, cy = y;
		uint8_t cur_attr = attr;
		for (size_t i = 0; s[i]; ) {
			if (s[i] == 0x1B && s[i+1] == '[') {
				/* parse CSI ... m */
				i += 2;
				int nums[16]; int nnums = 0;
				int cur = 0; int hasnum = 0;
				while (s[i] && s[i] != 'm' && nnums < 16) {
					if (s[i] >= '0' && s[i] <= '9') { hasnum = 1; cur = cur * 10 + (s[i] - '0'); i++; }
					else if (s[i] == ';') { nums[nnums++] = cur; cur = 0; hasnum = 0; i++; }
					else { /* unknown, skip */ i++; }
				}
				if (hasnum && nnums < 16) nums[nnums++] = cur;
				if (s[i] == 'm') i++;
				/* apply SGR values */
				if (nnums == 0) { /* reset */ cur_attr = 0x07; }
				for (int k = 0; k < nnums; k++) {
					int v = nums[k];
					if (v == 0) { cur_attr = 0x07; }
					else if (v == 1) { /* bold -> bright fg */ cur_attr |= 0x08; }
					else if (v >= 30 && v <= 37) {
						uint8_t fg = (uint8_t)(v - 30);
						cur_attr = (uint8_t)((cur_attr & 0xF0) | (fg & 0x0F));
					} else if (v >= 40 && v <= 47) {
						uint8_t bg = (uint8_t)(v - 40);
						cur_attr = (uint8_t)((bg << 4) | (cur_attr & 0x0F));
					} else if (v >= 90 && v <= 97) {
						uint8_t fg = (uint8_t)(v - 90 + 8);
						cur_attr = (uint8_t)((cur_attr & 0xF0) | (fg & 0x0F));
					} else if (v >= 100 && v <= 107) {
						uint8_t bg = (uint8_t)(v - 100 + 8);
						cur_attr = (uint8_t)((bg << 4) | (cur_attr & 0x0F));
					}
				}
				continue;
			}
			char ch = s[i++];
			vga_putch_xy(cx, cy, (uint8_t)ch, cur_attr);
			cx++;
			if (cx >= (uint32_t)console_max_cols()) { cx = 0; cy++; }
		}
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


