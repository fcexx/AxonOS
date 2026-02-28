#ifndef CIRRUSFB_H
#define CIRRUSFB_H

#include <stdint.h>

int cirrusfb_init(void *fb, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp, uint32_t fb_size);
int cirrusfb_is_ready(void);
uint32_t cirrusfb_cols(void);
uint32_t cirrusfb_rows(void);

void cirrusfb_putchar(uint8_t ch, uint8_t attr);
void cirrusfb_putch_xy(uint32_t x, uint32_t y, uint8_t ch, uint8_t attr);
void cirrusfb_set_cursor(uint32_t x, uint32_t y);
void cirrusfb_get_cursor(uint32_t *x, uint32_t *y);
void cirrusfb_clear(uint8_t attr);
void cirrusfb_update_cursor(void);

#endif
