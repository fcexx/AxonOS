/* bootparam.h — subset of Linux x86 boot protocol (zeropage) for initrd */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* setup_header.header ("HdrS") at boot_params + 0x202 */
#define LINUX_BOOTPARAM_HEADER_MAGIC 0x53726448u

/* ramdisk_image / ramdisk_size live in setup_header (boot_params + 0x218 / 0x21c).
 * High halves are in boot_params.ext_ramdisk_* (NOT in setup_header), per Linux uapi. */
#define LINUX_BOOTPARAM_OFF_HDR_MAGIC   0x202u
#define LINUX_BOOTPARAM_OFF_RAMDISK_IMG 0x218u
#define LINUX_BOOTPARAM_OFF_RAMDISK_SZ  0x21cu
#define LINUX_BOOTPARAM_OFF_EXT_RD_IMG  0x0c0u
#define LINUX_BOOTPARAM_OFF_EXT_RD_SZ   0x0c4u

/* Smallest buffer Linux bootloaders use for boot_params; shim uses the same size. */
#define LINUX_BOOTPARAM_MIN_SIZE 4096u

/* kzip_stub.c copies Multiboot2 modules here before loading the payload at 0x100000.
 * mb2_linux_shim must not extend mod_end to the next module for these: gaps are not copied.
 *
 * 0x02000000 = 32 MiB (note the leading 0 in the constant). Do not substitute 0x20000000
 * (512 MiB): on a 512 MiB RAM machine physical RAM is [0, 0x20000000), so the latter is
 * past RAM and the initrd appears corrupt mid-archive (e.g. cpio bad magic after a large file). */
#define AXON_MB2_MODULE_RELOC_BASE 0x02000000u
#define AXON_MB2_MODULE_RELOC_CEIL 0x05000000u

/* Returns 0 and fills *start_out/*size_out (physical initrd region) if HdrS present and size != 0. */
int linux_bootparams_ramdisk(const void *boot_params, uintptr_t *start_out, size_t *size_out);
