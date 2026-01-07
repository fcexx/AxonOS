/*
 * Console abstraction: routes to VBE framebuffer console if available,
 * otherwise falls back to VGA text mode.
 */
#pragma once

#include <stdint.h>

/* Put character at (x,y) with attribute */
void console_putch_xy(uint32_t x, uint32_t y, uint8_t ch, uint8_t attr);

/* Write NUL-terminated string at (x,y) with attribute */
void console_write_str_xy(uint32_t x, uint32_t y, const char *s, uint8_t attr);

/* Get / set cursor position (in character cells) */
void console_set_cursor(uint32_t x, uint32_t y);
void console_get_cursor(uint32_t *x, uint32_t *y);
/* Fill rectangle with character and attribute */
void console_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint8_t ch, uint8_t attr);


