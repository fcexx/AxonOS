/*
 * Boot logo: blit crox_logo into the linear framebuffer console.
 */

#define CROX_LOGO_DEFINE_DATA 1
#include <pics/crox.h>

#include <boot_logo.h>
#include <cirrusfb.h>
#include <devfs.h>
#include <klog.h>

uint32_t boot_logo_margin_rows(void) {
	return cirrusfb_margin_rows();
}

void boot_logo_show(void) {
	if (!cirrusfb_is_ready())
		return;

	uint32_t margin = (CROX_LOGO_HEIGHT + 15u) / 16u;
	if (margin >= cirrusfb_rows())
		margin = cirrusfb_rows() > 0 ? cirrusfb_rows() - 1 : 0;

	cirrusfb_set_margin_rows(margin);
	cirrusfb_set_logo_visible(1);
	cirrusfb_blit_mono8(0, 0, CROX_LOGO_WIDTH, CROX_LOGO_HEIGHT, crox_logo);
	cirrusfb_set_cursor(0, margin);

	if (devfs_is_ready()) {
		struct devfs_tty *tty = devfs_get_tty_by_index(devfs_get_active());
		if (tty) {
			tty->cursor_x = 0;
			tty->cursor_y = margin;
		}
	}

	klogprintf("boot: crox logo %ux%u (console below row %u)\n",
	           (unsigned)CROX_LOGO_WIDTH, (unsigned)CROX_LOGO_HEIGHT,
	           (unsigned)margin);
}

void boot_logo_dismiss(void) {
	cirrusfb_dismiss_boot_logo();
}
