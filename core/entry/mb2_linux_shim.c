#include <mb2_linux_shim.h>
#include <bootparam.h>
#include <klog.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#define MB2_MOD_SIZE_CAP ((uint64_t)(512u * 1024u * 1024u))

static int mb2_module_in_kzip_reloc_arena(uint32_t mod_start) {
    return mod_start >= AXON_MB2_MODULE_RELOC_BASE && mod_start < AXON_MB2_MODULE_RELOC_CEIL;
}

/* Smallest mod_start among module tags with start > phys_lo (same address space as tag fields). */
static uint32_t mb2_min_module_start_above(uint8_t *p, uint32_t scan_end, uint32_t first_off, uint32_t phys_lo) {
    uint32_t best = 0u;
    int has = 0;
    uint32_t offset = first_off;
    uint32_t tag_count = 0;
    while (offset + 8u <= scan_end) {
        if (++tag_count > 1024u)
            break;
        uint32_t tag_type = *(uint32_t *)(p + offset);
        uint32_t tag_size = *(uint32_t *)(p + offset + 4);
        if (tag_size < 8u)
            break;
        if ((uint64_t)offset + (uint64_t)tag_size > (uint64_t)scan_end)
            break;
        if (tag_type == 0u)
            break;
        if (tag_type == 3u && tag_size >= 16u) {
            uint32_t ms = *(uint32_t *)(p + offset + 8u);
            if (ms > phys_lo && (!has || ms < best)) {
                best = ms;
                has = 1;
            }
        }
        offset += (tag_size + 7u) & ~7u;
    }
    return has ? best : 0u;
}

/* If the tag's mod_end is too small but another module starts higher, RAM usually holds the full blob until there. */
static uint32_t mb2_extend_mod_end(uint32_t mod_start, uint32_t mod_end, uint32_t next_mod_start) {
    if (next_mod_start == 0u || next_mod_start <= mod_start)
        return mod_end;
    if (next_mod_start <= mod_end)
        return mod_end;
    uint64_t span = (uint64_t)next_mod_start - (uint64_t)mod_start;
    if (span > MB2_MOD_SIZE_CAP)
        return mod_end;
    klogprintf("mb2: initfs tag end 0x%x -> 0x%x (use span to next module)\n", (unsigned)mod_end,
               (unsigned)next_mod_start);
    return next_mod_start;
}

static void shim_write_bootparams(uint32_t mod_start, uint32_t mod_end, void *boot_params, size_t boot_params_sz) {
    if (mod_end <= mod_start || boot_params_sz < LINUX_BOOTPARAM_MIN_SIZE)
        return;
    uint64_t sz64 = (uint64_t)mod_end - (uint64_t)mod_start;
    if (sz64 == 0 || sz64 > MB2_MOD_SIZE_CAP)
        return;
    memset(boot_params, 0, boot_params_sz);
    *(uint32_t *)((uint8_t *)boot_params + LINUX_BOOTPARAM_OFF_HDR_MAGIC) = LINUX_BOOTPARAM_HEADER_MAGIC;
    *(uint32_t *)((uint8_t *)boot_params + LINUX_BOOTPARAM_OFF_RAMDISK_IMG) = mod_start;
    *(uint32_t *)((uint8_t *)boot_params + LINUX_BOOTPARAM_OFF_RAMDISK_SZ) = (uint32_t)sz64;
}

static size_t shim_strnlen(const char *s, size_t maxn) {
    size_t n = 0;
    if (!s)
        return 0;
    while (n < maxn && s[n] != '\0')
        n++;
    return n;
}

static const char *shim_basename(const char *p) {
    if (!p)
        return p;
    const char *b = p;
    for (const char *c = p; *c; c++) {
        if (*c == '/')
            b = c + 1;
    }
    return b;
}

static int shim_module_name_matches(const char *cmdline, size_t maxlen, const char *want_name) {
    if (!cmdline || !want_name || !want_name[0])
        return 0;
    size_t n = shim_strnlen(cmdline, maxlen);
    if (n == 0)
        return 0;

    size_t i = 0;
    while (i < n && (cmdline[i] == ' ' || cmdline[i] == '\t'))
        i++;
    if (i >= n)
        return 0;

    size_t start = i;
    while (i < n && cmdline[i] != ' ' && cmdline[i] != '\t')
        i++;
    size_t tok_len = i - start;
    if (tok_len == 0 || tok_len > 255)
        return 0;

    char tok[256];
    memcpy(tok, cmdline + start, tok_len);
    tok[tok_len] = '\0';

    if (strcmp(tok, want_name) == 0)
        return 1;

    const char *base = shim_basename(tok);
    if (strcmp(base, want_name) == 0)
        return 1;

    size_t want_len = strlen(want_name);
    if (strncmp(base, want_name, want_len) == 0) {
        if (base[want_len] == '\0' || base[want_len] == '.' || base[want_len] == '-')
            return 1;
    }
    return 0;
}

static int shim_try_fill_from_tags(uint8_t *p, uint32_t total_size, uint32_t first_off,
                                   const char *module_name, void *boot_params, size_t boot_params_sz) {
    if (!p || !module_name || !boot_params || boot_params_sz < LINUX_BOOTPARAM_MIN_SIZE)
        return -1;

    uint32_t offset = first_off;
    uint32_t tag_count = 0;
    while (offset + 8 <= total_size) {
        if (++tag_count > 1024)
            break;
        uint32_t tag_type = *(uint32_t *)(p + offset);
        uint32_t tag_size = *(uint32_t *)(p + offset + 4);
        if (tag_size < 8)
            break;
        if ((uint64_t)offset + (uint64_t)tag_size > (uint64_t)total_size)
            break;
        if (tag_type == 0)
            break;

        if (tag_type == 3 && tag_size >= 16) {
            const uint8_t *field_ptr = p + offset + 8;
            uint32_t ms32 = *(uint32_t *)(field_ptr);
            uint32_t me32 = *(uint32_t *)(field_ptr + 4);
            uint64_t mod_start = (uint64_t)ms32;
            uint64_t mod_end = (uint64_t)me32;
            size_t name_max = (size_t)tag_size - 16u;
            const char *name = (const char *)(p + offset + 16);

            if (shim_module_name_matches(name, name_max, module_name)) {
                if (mod_end <= mod_start)
                    return -2;
                uint32_t ms = (uint32_t)mod_start;
                uint32_t me = (uint32_t)mod_end;
                uint32_t next_s = mb2_min_module_start_above(p, total_size, 8u, ms);
                if (!mb2_module_in_kzip_reloc_arena(ms))
                    me = mb2_extend_mod_end(ms, me, next_s);
                if (me <= ms)
                    return -2;
                shim_write_bootparams(ms, me, boot_params, boot_params_sz);
                return 0;
            }
        }
        offset += (tag_size + 7) & ~7u;
    }
    return -3;
}

static int shim_loose_scan(uint8_t *p, const char *module_name, void *boot_params, size_t boot_params_sz) {
    const uint32_t meta_scan = 65536u;
    for (uint32_t off = 0; off + 16u <= meta_scan; off += 4u) {
        uint32_t tag_type = *(uint32_t *)(p + off);
        if (tag_type != 3u)
            continue;
        uint32_t tag_size = *(uint32_t *)(p + off + 4u);
        if (tag_size < 16u || tag_size > 4096u)
            continue;
        if (off + tag_size > meta_scan)
            continue;

        uint32_t ms32 = *(uint32_t *)(p + off + 8u);
        uint32_t me32 = *(uint32_t *)(p + off + 12u);
        if (me32 <= ms32)
            continue;

        uint64_t mod_start = (uint64_t)ms32;
        uint64_t mod_end = (uint64_t)me32;
        size_t mod_size = (size_t)(mod_end - mod_start);
        if (mod_size == 0 || mod_size > (512u * 1024u * 1024u))
            continue;

        const char *name = (const char *)(p + off + 16u);
        size_t name_max = (size_t)tag_size - 16u;
        if (!shim_module_name_matches(name, name_max, module_name))
            continue;

        uint32_t ms = (uint32_t)mod_start;
        uint32_t me = (uint32_t)mod_end;
        uint32_t ts = *(uint32_t *)p;
        uint32_t next_s = 0u;
        if (ts >= 16u && ts <= (256u * 1024u * 1024u))
            next_s = mb2_min_module_start_above(p, ts, 8u, ms);
        else
            next_s = mb2_min_module_start_above(p, meta_scan, 0u, ms);
        if (!mb2_module_in_kzip_reloc_arena(ms))
            me = mb2_extend_mod_end(ms, me, next_s);
        if (me <= ms)
            continue;
        shim_write_bootparams(ms, me, boot_params, boot_params_sz);
        return 0;
    }
    return -1;
}

int mb2_linux_shim_fill_bootparams(uint32_t multiboot_magic, uint64_t multiboot_info,
                                   void *boot_params, size_t boot_params_sz,
                                   const char *module_name) {
    if (multiboot_magic != 0x36d76289u || multiboot_info == 0 || !boot_params ||
        boot_params_sz < LINUX_BOOTPARAM_MIN_SIZE || !module_name)
        return -1;

    uint8_t *p = (uint8_t *)(uintptr_t)multiboot_info;
    uint32_t total_size = *(uint32_t *)p;

    if (total_size >= 16 && total_size <= (256u * 1024u * 1024u)) {
        if (shim_try_fill_from_tags(p, total_size, 8, module_name, boot_params, boot_params_sz) == 0)
            return 0;
    }

    {
        const uint32_t alt_max = 65536u;
        uint32_t alt_off = 0;
        while (alt_off + 8 <= alt_max) {
            uint32_t tag_type = *(uint32_t *)(p + alt_off);
            uint32_t tag_size = *(uint32_t *)(p + alt_off + 4);
            if (tag_size < 8 || tag_size > alt_max)
                break;
            if (tag_type == 0)
                break;
            if (tag_type == 3 && tag_size >= 16) {
                uint32_t ms32 = *(uint32_t *)(p + alt_off + 8);
                uint32_t me32 = *(uint32_t *)(p + alt_off + 12);
                if (me32 > ms32) {
                    size_t name_max = (size_t)tag_size - 16u;
                    const char *name = (const char *)(p + alt_off + 16);
                    if (shim_module_name_matches(name, name_max, module_name)) {
                        uint32_t me = me32;
                        if (!mb2_module_in_kzip_reloc_arena(ms32))
                            me = mb2_extend_mod_end(ms32, me32,
                                                    mb2_min_module_start_above(p, alt_max, 0u, ms32));
                        if (me <= ms32)
                            continue;
                        shim_write_bootparams(ms32, me, boot_params, boot_params_sz);
                        return 0;
                    }
                }
            }
            alt_off += (tag_size + 7) & ~7u;
        }
    }

    if (shim_loose_scan(p, module_name, boot_params, boot_params_sz) == 0)
        return 0;

    return -1;
}
