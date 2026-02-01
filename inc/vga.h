#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#define VIDEO_ADDRESS 0xb8000
#define MAX_ROWS 25
#define MAX_COLS 80

#define WHITE_ON_BLACK 0x0f
#define GRAY_ON_BLACK 0x07

#define REG_SCREEN_CTRL 0x3d4
#define REG_SCREEN_DATA 0x3d5

void kprint(uint8_t *str);
void kputchar(uint8_t character, uint8_t attribute_byte);
void kprint_colorized(const char* str);
void kclear();
void kclear_col(uint8_t attribute_byte);
void write(uint8_t character, uint8_t attribute_byte, uint16_t offset);
void scroll_line();
uint16_t get_cursor();
void set_cursor(uint16_t pos);
uint16_t get_cursor_x();
uint16_t get_cursor_y();
void set_cursor_x(uint16_t x);
void set_cursor_y(uint16_t y);
void vga_set_cursor(uint32_t x, uint32_t y);
void vga_get_cursor(uint32_t* x, uint32_t* y);

/* Set hardware cursor scanline start/end (0-31). */
void set_cursor_shape(uint8_t start, uint8_t end);

/* Enable hardware VGA cursor (also sets a sane default shape). */
void enable_cursor(void);

/* Kernel printf-like output to VGA text mode. */
void kprintf(const char* fmt, ...);

/* Minimal printf-to-buffer helpers implemented in drv/vga.c */
int vsnprintf(char* out, size_t outsz, const char* fmt, va_list ap);
int snprintf(char* out, size_t outsz, const char* fmt, ...);
int sprintf(char* out, const char* fmt, ...);

/* Fast direct VGA helpers (write directly to video memory) */
void vga_putch_xy(uint32_t x, uint32_t y, uint8_t ch, uint8_t attr);
/* Clear segment [x0..x1] on line y with spaces; does not move cursor. */
void vga_clear_line_segment(uint32_t x0, uint32_t x1, uint32_t y, uint8_t attr);
void vga_clear_screen_attr(uint8_t attr);
void vga_write_str_xy(uint32_t x, uint32_t y, const char *s, uint8_t attr);
void vga_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint8_t ch, uint8_t attr);
// Colorized write with inline tags <(bgfg)>; returns number of visible columns written
uint32_t vga_write_colorized_xy(uint32_t x, uint32_t y, const char *s, uint8_t default_attr);