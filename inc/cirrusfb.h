#ifndef CIRRUSFB_H
#define CIRRUSFB_H

#include <stdint.h>
#include <stddef.h>

/*
 * Software text console: 8x16 glyphs into a linear framebuffer.
 * Used by VMware SVGA (vmwgfx) and by the Cirrus PCI driver — not tied to Cirrus silicon.
 * (Name is historical; the GPU is chosen by video_register_driver / vmwgfx_kernel_init.)
 */
/* hw_cursor: Cirrus VGA sequencer cursor only; must be 0 on VMware SVGA (no Cirrus HW). */
int cirrusfb_init(void *fb, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp, uint32_t fb_size,
                  int hw_cursor);
int cirrusfb_is_ready(void);
uint32_t cirrusfb_cols(void);
uint32_t cirrusfb_rows(void);

void cirrusfb_putchar(uint8_t ch, uint8_t attr);
/* TTY/devfs output: no ESC/CSI parsing (devfs already parses; avoids stale klog ANSI state). */
void cirrusfb_putchar_literal(uint8_t ch, uint8_t attr);
void cirrusfb_putch_xy(uint32_t x, uint32_t y, uint8_t ch, uint8_t attr);
void cirrusfb_set_cursor(uint32_t x, uint32_t y);
void cirrusfb_get_cursor(uint32_t *x, uint32_t *y);
void cirrusfb_clear(uint8_t attr);
void cirrusfb_update_cursor(void);
/* Pack screen like devfs tty buffer: [ch,attr] per cell, row-major, size = cols*rows*2 */
void cirrusfb_snapshot_screen(uint8_t *out, size_t max_bytes);
void cirrusfb_restore_screen(const uint8_t *src, uint32_t cols, uint32_t rows);
uint8_t cirrusfb_get_cell_attr(uint32_t x, uint32_t y);

/* Boot logo: mono8 pixels (grayscale byte -> RGB), top-left blit. */
void cirrusfb_blit_mono8(uint32_t x, uint32_t y, uint32_t w, uint32_t h, const uint8_t *pixels);
/* Rows at top excluded from console scroll / minimum cursor Y (0 = off). */
void cirrusfb_set_margin_rows(uint32_t rows);
uint32_t cirrusfb_margin_rows(void);
/* Scroll rows [top..bottom] up by one line within the text buffer (DECSTBM). */
void cirrusfb_scroll_region(uint32_t top, uint32_t bottom);
void cirrusfb_set_logo_visible(int visible);
/* Drop pinned logo: restore console text over logo rows, allow normal scroll. */
void cirrusfb_dismiss_boot_logo(void);

#endif
