#include <fbdev.h>
#include <devfs.h>
#include <fs.h>
#include <paging.h>
#include <stdint.h>
#include <string.h>

static struct {
	void *kva;
	uint64_t pa;
	size_t len;
	uint32_t width;
	uint32_t height;
	uint32_t pitch;
	uint32_t bpp;
	int active;
} g_fbdev;

/* Non-NULL devfs char-node private (must not be interpreted as tty or int marker). */
static char fbdev_devfs_tag;

void fbdev_register_linear(void *kva, uint64_t fb_pa, size_t byte_len,
                           uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp) {
	memset(&g_fbdev, 0, sizeof(g_fbdev));
	if (!kva || byte_len == 0 || fb_pa == 0) {
		g_fbdev.active = 0;
		return;
	}
	g_fbdev.kva = kva;
	g_fbdev.pa = fb_pa;
	g_fbdev.len = byte_len;
	g_fbdev.width = width;
	g_fbdev.height = height;
	g_fbdev.pitch = pitch;
	g_fbdev.bpp = bpp;
	g_fbdev.active = 1;
	(void)devfs_create_char_node("/dev/fb0", (void *)&fbdev_devfs_tag);
}

void fbdev_unregister(void) {
	g_fbdev.active = 0;
	memset(&g_fbdev, 0, sizeof(g_fbdev));
}

int fbdev_is_active(void) {
	return g_fbdev.active ? 1 : 0;
}

size_t fbdev_byte_len(void) {
	return g_fbdev.active ? g_fbdev.len : 0;
}

int fbdev_is_fb0_file(const struct fs_file *f) {
	return f && f->path && strcmp(f->path, "/dev/fb0") == 0;
}

void fbdev_copy_to(void *dst, size_t offset, size_t n) {
	if (!g_fbdev.active || n == 0 || !dst)
		return;
	memcpy(dst, (const uint8_t *)g_fbdev.kva + offset, n);
}

void fbdev_copy_from(size_t offset, const void *src, size_t n) {
	if (!g_fbdev.active || n == 0 || !src)
		return;
	memcpy((uint8_t *)g_fbdev.kva + offset, src, n);
}

int fbdev_mmap_user(uintptr_t addr, size_t len, size_t file_off) {
	if (!g_fbdev.active || len == 0)
		return -1;
	if ((uint64_t)file_off + (uint64_t)len > (uint64_t)g_fbdev.len)
		return -1;

	const uint64_t mask = (uint64_t)PAGE_SIZE_2M - 1ULL;
	uint64_t fb_start = g_fbdev.pa;
	uintptr_t end = addr + len;

	const uint64_t map_flags = (uint64_t)(PG_PRESENT | PG_RW | PG_US | PG_PCD | PG_PWT);

	for (uintptr_t u = addr & ~(uintptr_t)mask; u < end; u += (uintptr_t)PAGE_SIZE_2M) {
		uint64_t p = fb_start + (uint64_t)file_off + (uint64_t)((intptr_t)u - (intptr_t)addr);
		uint64_t pa_page = p & ~mask;
		if (map_page_2m((uint64_t)u, pa_page, map_flags) != 0)
			return -1;
	}
	return 0;
}
