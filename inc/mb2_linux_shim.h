/* mb2_linux_shim.h — GRUB multiboot2 does not pass Linux boot_params; fill a minimal
 * zeropage-shaped buffer from MB2 module tag so initrd is consumed via linux_bootparam.c */
#pragma once

#include <stdint.h>
#include <stddef.h>

/* Zero bp, set HdrS + ramdisk_image/size (+ ext fields zero). module_name e.g. "initfs".
 * Returns 0 if a matching module tag was found, else non-zero. */
int mb2_linux_shim_fill_bootparams(uint32_t multiboot_magic, uint64_t multiboot_info,
                                   void *boot_params, size_t boot_params_sz,
                                   const char *module_name);
