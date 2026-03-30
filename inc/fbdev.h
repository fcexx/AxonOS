#pragma once

#include <stddef.h>
#include <stdint.h>

struct fs_file;

/* Register linear FB for /dev/fb0 (kva = first pixel, pa = physical of that byte). */
void fbdev_register_linear(void *kva, uint64_t fb_pa, size_t byte_len,
                           uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp);
void fbdev_unregister(void);

int fbdev_is_active(void);
size_t fbdev_byte_len(void);

int fbdev_is_fb0_file(const struct fs_file *f);
/* Map user [addr, addr+len) to FB bytes [file_off, file_off+len); 2 MiB pages, WC via PCD|PWT. */
int fbdev_mmap_user(uintptr_t addr, size_t len, size_t file_off);

void fbdev_copy_to(void *dst, size_t offset, size_t n);
void fbdev_copy_from(size_t offset, const void *src, size_t n);
