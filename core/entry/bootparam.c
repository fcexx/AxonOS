#include <bootparam.h>
#include <stdint.h>
#include <stddef.h>

int linux_bootparams_ramdisk(const void *boot_params, uintptr_t *start_out, size_t *size_out) {
    const uint8_t *p = (const uint8_t *)boot_params;
    if (!p || !start_out || !size_out)
        return -1;

    uint32_t hdr_magic = *(const uint32_t *)(p + LINUX_BOOTPARAM_OFF_HDR_MAGIC);
    if (hdr_magic != LINUX_BOOTPARAM_HEADER_MAGIC)
        return -2;

    uint32_t img_lo = *(const uint32_t *)(p + LINUX_BOOTPARAM_OFF_RAMDISK_IMG);
    uint32_t img_hi = *(const uint32_t *)(p + LINUX_BOOTPARAM_OFF_EXT_RD_IMG);
    uint32_t sz_lo = *(const uint32_t *)(p + LINUX_BOOTPARAM_OFF_RAMDISK_SZ);
    uint32_t sz_hi = *(const uint32_t *)(p + LINUX_BOOTPARAM_OFF_EXT_RD_SZ);

    uint64_t img = ((uint64_t)img_hi << 32) | (uint64_t)img_lo;
    uint64_t sz64 = ((uint64_t)sz_hi << 32) | (uint64_t)sz_lo;

    if (sz64 == 0)
        return -3;
    if (sz64 != (uint64_t)(size_t)sz64)
        return -4;

    *start_out = (uintptr_t)img;
    *size_out = (size_t)sz64;
    return 0;
}
