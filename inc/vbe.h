/*
 * VBE/framebuffer console API
 */
#pragma once

#include <stdint.h>

int vbe_init_from_multiboot(uint32_t multiboot_magic, uint64_t multiboot_info);
int vbe_is_available(void);

/* Simple framebuffer console primitives used by kprintf delegation */
void vbefb_putchar(uint8_t ch, uint8_t attr);
void vbefb_putn(char ch, int count, uint8_t attr);
void vbefb_get_cursor(uint32_t *x, uint32_t *y);
void vbefb_set_cursor(uint32_t x, uint32_t y);
void vbefb_clear(uint8_t attr);
/* Flush helpers and backbuffer access */
void vbe_flush_region(uint32_t x, uint32_t y, uint32_t w, uint32_t h);
void *vbe_get_backbuffer(void);
uint32_t vbe_get_pitch(void);
uint32_t vbe_get_bpp(void);
uint32_t vbe_get_width(void);
uint32_t vbe_get_height(void);
/* Initialize vbe text console after framebuffer is available */
int vbefb_init(uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp);
/* Front buffer access (direct framebuffer VA) */
void *vbe_get_frontbuffer(void);


