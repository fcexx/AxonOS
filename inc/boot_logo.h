#pragma once

#include <stdint.h>

/* Draw crox_logo in the top-left after fbcon (vmwgfx/cirrus) is ready. */
void boot_logo_show(void);

/* Unpin logo (before init, or automatically on first console scroll). */
void boot_logo_dismiss(void);

/* Text rows reserved at top (0 if logo not shown / after clear). */
uint32_t boot_logo_margin_rows(void);
