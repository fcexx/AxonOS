/* initfs.h — initrd via Linux boot_params (ramdisk_image/size), cpio newc → VFS */
#pragma once

#include <stdint.h>
#include <stddef.h>

/* Unpack initrd described in Linux zeropage at boot_params_phys (identity-mapped).
 * Returns 0 on success, negative on unpack error, 2/3 on missing/invalid boot_params. */
int initfs_process_linux_bootparams(uint64_t boot_params_phys);

/* First physical byte after the initrd region (4 KiB aligned), or 0 if none / invalid. */
uintptr_t initfs_linux_ramdisk_exclusive_end(uint64_t boot_params_phys);

void initfs_debug_list_vfs(void);
