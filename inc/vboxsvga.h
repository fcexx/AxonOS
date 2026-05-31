/*
 * VirtualBox SVGA (VBoxSVGA) — minimal 2D SVGA-II style driver.
 *
 * AxonOS uses early kernel init to bring up a wide framebuffer console shortly
 * after PCI enumeration (see vmwgfx/cirrus paths). VBoxSVGA follows the same
 * pattern and plugs into the generic video registry.
 */
#pragma once

int vboxsvga_kernel_init(void);

