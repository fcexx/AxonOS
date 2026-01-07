#include <sysinfo.h>
#include <stdint.h>
#include <klog.h>
#include <mmio.h>
#include <string.h>
#include <vbe.h>

char sys_cpu_name[64] = "Unknown CPU";
int sys_ram_mb = -1;
int sys_pc_type = 0;
static char dmi_manufacturer[64];
static char dmi_product[128];
static char dmi_board[128];

/* Normalize hypervisor vendor string to human-friendly name and prefix. */
static void normalize_hv_vendor(const char *raw, char *out_name, size_t out_name_sz, char *out_prefix, size_t out_prefix_sz) {
    if (!raw || !out_name || !out_prefix) return;
    if (strstr(raw, "VMware") != NULL) {
        strncpy(out_name, "VMware, Inc.", out_name_sz-1); out_name[out_name_sz-1]='\0';
        strncpy(out_prefix, "vmware", out_prefix_sz-1); out_prefix[out_prefix_sz-1]='\0';
        return;
    }
    if (strstr(raw, "TCG") != NULL || strstr(raw, "QEMU") != NULL) {
        strncpy(out_name, "QEMU (TCG)", out_name_sz-1); out_name[out_name_sz-1]='\0';
        strncpy(out_prefix, "kvm", out_prefix_sz-1); out_prefix[out_prefix_sz-1]='\0';
        return;
    }
    if (strstr(raw, "KVMKVM") != NULL || strstr(raw, "KVM") != NULL) {
        strncpy(out_name, "KVM", out_name_sz-1); out_name[out_name_sz-1]='\0';
        strncpy(out_prefix, "kvm", out_prefix_sz-1); out_prefix[out_prefix_sz-1]='\0';
        return;
    }
    if (strstr(raw, "Microsoft") != NULL || strstr(raw, "Hyper-V") != NULL) {
        strncpy(out_name, "Microsoft Hyper-V", out_name_sz-1); out_name[out_name_sz-1]='\0';
        strncpy(out_prefix, "hyperv", out_prefix_sz-1); out_prefix[out_prefix_sz-1]='\0';
        return;
    }
    /* fallback: copy raw */
    strncpy(out_name, raw, out_name_sz-1); out_name[out_name_sz-1]='\0';
    size_t pi = 0;
    for (size_t i = 0; raw[i] != '\0' && pi + 1 < out_prefix_sz; i++) {
        char ch = raw[i];
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
            if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
            out_prefix[pi++] = ch;
        } else break;
    }
    out_prefix[pi] = '\0';
}

/* Multiboot2 memory map entry (tag type 6), layout per spec */
typedef struct {
    uint64_t addr;
    uint64_t len;
    uint32_t type;
    uint32_t zero;
} __attribute__((packed)) mb2_mmap_entry_t;

/* Parse Multiboot2 tags and try to compute total available RAM (MB) from MEMMAP.
   Returns -1 if not available. */
static int mb2_total_ram_mb(uint64_t multiboot_info_ptr) {
    if (multiboot_info_ptr == 0) return -1;
    uint8_t *p = (uint8_t*)(uintptr_t)multiboot_info_ptr;
    uint32_t total_size = *(uint32_t*)p;
    if (total_size < 16 || total_size > (64u * 1024u * 1024u)) return -1;

    uint32_t off = 8;
    uint64_t best_bytes = 0;
    int found_memmap = 0;
    uint32_t mem_lower = 0, mem_upper = 0;
    int found_basic = 0;

    while (off + 8 <= total_size) {
        uint32_t tag_type = *(uint32_t*)(p + off);
        uint32_t tag_size = *(uint32_t*)(p + off + 4);
        if (tag_size < 8) break;
        if ((uint64_t)off + (uint64_t)tag_size > (uint64_t)total_size) break;
        if (tag_type == 0) break; /* end tag */

        if (tag_type == 6 && tag_size >= 16) {
            /* MEMORY_MAP */
            uint32_t entry_size = *(uint32_t*)(p + off + 8);
            /* entry_version at off+12 (unused) */
            if (entry_size < sizeof(mb2_mmap_entry_t)) {
                /* spec says 24 bytes; bail out rather than mis-parse */
                found_memmap = 0;
            } else {
                uint32_t entries_off = off + 16;
                uint32_t entries_end = off + tag_size;
                uint64_t total = 0;
                for (uint32_t eoff = entries_off; eoff + entry_size <= entries_end; eoff += entry_size) {
                    mb2_mmap_entry_t *e = (mb2_mmap_entry_t*)(p + eoff);
                    /* type==1 means available RAM */
                    if (e->type == 1) total += e->len;
                }
                best_bytes = total;
                found_memmap = (best_bytes > 0);
            }
        } else if (tag_type == 4 && tag_size >= 16) {
            /* BASIC_MEMINFO (mem_lower/mem_upper in KB) */
            mem_lower = *(uint32_t*)(p + off + 8);
            mem_upper = *(uint32_t*)(p + off + 12);
            found_basic = 1;
        }

        off += (tag_size + 7) & ~7u; /* 8-byte alignment */
    }

    if (found_memmap) {
        return (int)(best_bytes / (1024ULL * 1024ULL));
    }
    if (found_basic) {
        /* mem_upper is KB above 1MB. Add 1MB to get total MB estimate. */
        uint64_t total_kb = (uint64_t)mem_upper + 1024ULL;
        (void)mem_lower; /* usually ~640KB, ignore for a stable "installed RAM" estimate */
        return (int)(total_kb / 1024ULL);
    }
    return -1;
}

/* Print BIOS e820-like map from Multiboot2 MEMORY_MAP (tag 6).
   Prints lines similar to Linux: "BIOS-e820: [mem 0x...-0x...] usable" */
void sysinfo_print_e820(uint32_t multiboot_magic, uint64_t multiboot_info_ptr) {
    if (multiboot_info_ptr == 0) return;
    if (multiboot_magic != 0x36d76289u) return; /* only Multiboot2 handled here */
    uint8_t *p = (uint8_t*)(uintptr_t)multiboot_info_ptr;
    uint32_t total_size = *(uint32_t*)p;
    if (total_size < 16 || total_size > (64u * 1024u * 1024u)) return;

    uint32_t off = 8;
    int printed_header = 0;
    while (off + 8 <= total_size) {
        uint32_t tag_type = *(uint32_t*)(p + off);
        uint32_t tag_size = *(uint32_t*)(p + off + 4);
        if (tag_size < 8) break;
        if ((uint64_t)off + (uint64_t)tag_size > (uint64_t)total_size) break;
        if (tag_type == 0) break; /* end tag */

        if (tag_type == 6 && tag_size >= 16) {
            /* MEMORY_MAP */
            uint32_t entry_size = *(uint32_t*)(p + off + 8);
            if (entry_size >= sizeof(mb2_mmap_entry_t)) {
                uint32_t entries_off = off + 16;
                uint32_t entries_end = off + tag_size;
                if (!printed_header) {
                    klogprintf("BIOS-provided physical RAM map:\n");
                    printed_header = 1;
                }
                for (uint32_t eoff = entries_off; eoff + entry_size <= entries_end; eoff += entry_size) {
                    mb2_mmap_entry_t *e = (mb2_mmap_entry_t*)(p + eoff);
                    uint64_t start = e->addr;
                    uint64_t end = (e->len == 0) ? (e->addr) : (e->addr + e->len - 1);
                    const char *type_str = "reserved";
                    switch (e->type) {
                        case 1: type_str = "usable"; break;
                        case 2: type_str = "reserved"; break;
                        case 3: type_str = "ACPI data"; break;
                        case 4: type_str = "ACPI NVS"; break;
                        case 5: type_str = "badram"; break;
                        default: type_str = "reserved"; break;
                    }
                    klogprintf("BIOS-e820: [mem 0x%016llx-0x%016llx] %s\n",
                            (unsigned long long)start, (unsigned long long)end, type_str);
                }
            }
        }

        off += (tag_size + 7) & ~7u; /* 8-byte alignment */
    }
}

// Вспомогательная функция CPUID
static void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    asm volatile("cpuid"
                 : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                 : "a"(leaf), "c"(subleaf));
}

void sysinfo_init(uint32_t multiboot_magic, uint64_t multiboot_info_ptr) {
    // Попытка получить бренд-строку (0x80000002..0x80000004)
    uint32_t a,b,c,d;
    uint32_t max_ext = 0;
    asm volatile("cpuid" : "=a"(max_ext) : "a"(0x80000000) : "ebx","ecx","edx");
    if (max_ext >= 0x80000004) {
        char *p = sys_cpu_name;
        for (uint32_t leaf = 0x80000002; leaf <= 0x80000004; leaf++) {
            cpuid(leaf, 0, &a, &b, &c, &d);
            *(uint32_t*)p = a; p += 4;
            *(uint32_t*)p = b; p += 4;
            *(uint32_t*)p = c; p += 4;
            *(uint32_t*)p = d; p += 4;
        }
        // Гарантированный нуль-терминатор
        sys_cpu_name[63] = '\0';
    } else {
        // fallback: базовый идентификатор
        cpuid(0, 0, &a, &b, &c, &d);
        ((uint32_t*)sys_cpu_name)[0] = b;
        ((uint32_t*)sys_cpu_name)[1] = d;
        ((uint32_t*)sys_cpu_name)[2] = c;
        sys_cpu_name[12] = '\0';
    }

    // Определяем тип загрузки: если multiboot_info_ptr != 0, считаем, что загрузчик (BIOS/GRUB) передал инфо
    if (multiboot_info_ptr != 0) sys_pc_type = 1; else sys_pc_type = 0;

    /* Detect hypervisor via CPUID and try to read TSC/clock info from CPUID leaves. */
    

    // Попробуем извлечь объём памяти из multiboot structures
    sys_ram_mb = -1;
    if (multiboot_info_ptr != 0) {
        // Для multiboot1 структура: flags(0), mem_lower(4), mem_upper(8)
        if (multiboot_magic == 0x2BADB002u) {
            uint32_t *mb = (uint32_t*)(uintptr_t)multiboot_info_ptr;
            uint32_t flags = mb[0];
            if (flags & 0x1) {
                uint32_t mem_lower = mb[1];
                uint32_t mem_upper = mb[2];
                /* mem_upper is KB above 1MB; add 1MB to get total MB estimate */
                uint32_t total_kb = mem_upper + 1024u;
                (void)mem_lower;
                sys_ram_mb = (int)(total_kb / 1024u);
            }
        }
        // Для multiboot2: информация начинается с total_size (uint32) и reserved (uint32), затем теги
        else if (multiboot_magic == 0x36d76289u) {
            sys_ram_mb = mb2_total_ram_mb(multiboot_info_ptr);
        }
    }
    /* VBE init moved to kernel_main (heap not yet initialized here) */
}

void detect_hv_and_read_tsc()
{
    uint32_t a,b,c,d;
    uint32_t max_ext = 0;
    asm volatile("cpuid" : "=a"(max_ext) : "a"(0x80000000) : "ebx","ecx","edx");
    if (max_ext >= 0x80000004) {
        char *p = sys_cpu_name;
        for (uint32_t leaf = 0x80000002; leaf <= 0x80000004; leaf++) {
            cpuid(leaf, 0, &a, &b, &c, &d);
            *(uint32_t*)p = a; p += 4;
            *(uint32_t*)p = b; p += 4;
            *(uint32_t*)p = c; p += 4;
            *(uint32_t*)p = d; p += 4;
        }
        // Гарантированный нуль-терминатор
        sys_cpu_name[63] = '\0';
    } else {
        // fallback: базовый идентификатор
        cpuid(0, 0, &a, &b, &c, &d);
        ((uint32_t*)sys_cpu_name)[0] = b;
        ((uint32_t*)sys_cpu_name)[1] = d;
        ((uint32_t*)sys_cpu_name)[2] = c;
        sys_cpu_name[12] = '\0';
    }
    uint32_t max_std = 0, hv_max = 0;
    asm volatile("cpuid" : "=a"(max_std) : "a"(0) : "ebx","ecx","edx");
    /* Check hypervisor-present bit (ECX bit 31 of CPUID leaf 1) */
    cpuid(1, 0, &a, &b, &c, &d);
    if (c & (1u << 31)) {
        /* read hypervisor vendor string via 0x40000000 */
        cpuid(0x40000000u, 0, &a, &b, &c, &d);
        hv_max = a;
        char hvname[13];
        *(uint32_t*)&hvname[0] = b;
        *(uint32_t*)&hvname[4] = c;
        *(uint32_t*)&hvname[8] = d;
        hvname[12] = '\0';
        char hv_display[64];
        char hv_prefix[32];
        normalize_hv_vendor(hvname, hv_display, sizeof(hv_display), hv_prefix, sizeof(hv_prefix));
        /* Prefer DMI if available (prints nicer vendor/product strings). Print SMBIOS/DMI earlier; here print hypervisor detection. */
        klogprintf("Hypervisor detected: %s\n", hv_display);

        /* Try CPUID 0x15 if available: provides crystal clock (ECX), numerator (EBX), denominator (EAX) */
        if (max_std >= 0x15) {
            uint32_t a15,b15,c15,d15;
            cpuid(0x15u, 0, &a15, &b15, &c15, &d15);
                if (a15 != 0 && b15 != 0 && c15 != 0) {
                    uint64_t crystal_hz = (uint64_t)c15;
                    uint64_t tsc_hz = (crystal_hz * (uint64_t)b15) / (uint64_t)a15;
                    double tsc_mhz = (double)tsc_hz / 1000000.0;
                    klogprintf("%s: TSC freq read from hypervisor : %0.3f MHz\n", hv_prefix, tsc_mhz);
                    klogprintf("%s: Host bus clock speed read from hypervisor : %llu Hz\n", hv_prefix, (unsigned long long)crystal_hz);
                    /* Provide a simple clock offset estimate (0 for now) to match kernel flavor output */
                    klogprintf("%s: using clock offset of %llu ns\n", hv_prefix, (unsigned long long)0);
            } else {
                /* Try CPUID 0x16 (base frequency in MHz) as a fallback */
                if (max_std >= 0x16) {
                    uint32_t a16,b16,c16,d16;
                    cpuid(0x16u, 0, &a16, &b16, &c16, &d16);
                    if (a16 != 0) {
                            uint64_t tsc_hz = (uint64_t)a16 * 1000000ULL;
                            double tsc_mhz = (double)tsc_hz / 1000000.0;
                            klogprintf("%s: TSC freq read from hypervisor : %0.3f MHz\n", hv_prefix, tsc_mhz);
                    }
                }
            }
        } else {
            /* CPUID 0x15 not available; attempt CPUID 0x16 */
            if (max_std >= 0x16) {
                uint32_t a16,b16,c16,d16;
                cpuid(0x16u, 0, &a16, &b16, &c16, &d16);
                if (a16 != 0) {
                    uint64_t tsc_hz = (uint64_t)a16 * 1000000ULL;
                    double tsc_mhz = (double)tsc_hz / 1000000.0;
                    klogprintf("%s: TSC freq read from hypervisor : %0.3f MHz\n", hv_prefix, tsc_mhz);
                }
            }
        }
    }
}

/* Scan memory for SMBIOS entry point and print DMI vendor/product when found.
   Minimal implementation: searches 0xF0000..0x100000 for "_SM_" and parses table. */
void sysinfo_print_dmi(void) {
    const uint32_t start = 0x000F0000u;
    const uint32_t end = 0x00100000u;
    for (uint32_t addr = start; addr < end; addr += 16) {
        void *m = mmio_map_phys(addr, 0x20);
        if (!m) continue;
        const uint8_t *p = (const uint8_t*)m;
        if (!(p[0] == '_' && p[1] == 'S' && p[2] == 'M' && p[3] == '_')) continue;
        /* SMBIOS 32-bit entry */
        uint8_t major = p[0x06];
        uint8_t minor = p[0x07];
        klogprintf("SMBIOS %u.%u present.\n", (unsigned)major, (unsigned)minor);
        /* DMI length at offset 0x16, table addr at 0x18 */
        uint16_t dmi_len = *(const uint16_t*)(p + 0x16);
        uint32_t table_addr = *(const uint32_t*)(p + 0x18);
        if (dmi_len == 0 || table_addr == 0) continue;
        void *table = mmio_map_phys((uint64_t)table_addr, dmi_len);
        if (!table) continue;
        const uint8_t *t = (const uint8_t*)table;
        uint32_t off = 0;
        const char *manufacturer = NULL;
        const char *product = NULL;
        const char *board = NULL;
        while (off + 4 <= dmi_len) {
            uint8_t type = t[off + 0];
            uint8_t len = t[off + 1];
            if (len < 4 || off + len > dmi_len) break;
            /* pointers to formatted area and strings */
            const uint8_t *fmt = &t[off];
            const uint8_t *str = &t[off + len];
            /* find end of strings area */
            const uint8_t *s = str;
            int found_terminator = 0;
            while ((uint32_t)(s - t) < dmi_len) {
                if (s[0] == 0 && s[1] == 0) { found_terminator = 1; s += 2; break; }
                /* advance to next string */
                while ((uint32_t)(s - t) < dmi_len && *s) s++;
                if ((uint32_t)(s - t) < dmi_len) s++; else break;
            }
            /* Process type 1 (System Information) */
            if (type == 1) {
                /* Manufacturer string index at offset 0x04, Product at 0x05 (if present) */
                if (len > 4) {
                    uint8_t mi = fmt[4];
                    uint8_t pi = (len > 5) ? fmt[5] : 0;
                    /* lookup strings: index 1..n */
                    const char *cur = (const char*)str;
                    int idx = 1;
                    const char *man = NULL;
                    const char *prod = NULL;
                    while ((uint32_t)(cur - (const char*)t) < dmi_len && *cur) {
                        if (idx == mi) man = cur;
                        if (idx == pi) prod = cur;
                        /* move to next */
                        while ((uint32_t)(cur - (const char*)t) < dmi_len && *cur) cur++;
                        if ((uint32_t)(cur - (const char*)t) < dmi_len) cur++; else break;
                        idx++;
                    }
                    if (man) manufacturer = man;
                    if (prod) product = prod;
                }
            }
            /* Process type 2 (Baseboard Information) */
            if (type == 2) {
                if (len > 4) {
                    uint8_t bi_man = fmt[4];
                    uint8_t bi_prod = (len > 5) ? fmt[5] : 0;
                    const char *cur = (const char*)str;
                    int idx = 1;
                    const char *bman = NULL;
                    const char *bprod = NULL;
                    while ((uint32_t)(cur - (const char*)t) < dmi_len && *cur) {
                        if (idx == bi_man) bman = cur;
                        if (idx == bi_prod) bprod = cur;
                        while ((uint32_t)(cur - (const char*)t) < dmi_len && *cur) cur++;
                        if ((uint32_t)(cur - (const char*)t) < dmi_len) cur++; else break;
                        idx++;
                    }
                    if (bman) board = bman;
                    else if (bprod) board = bprod;
                }
            }
            /* advance to next structure (skip strings area) */
            if (!found_terminator) break;
            off = (uint32_t)( (s - t) );
        }
        /* if we have at least system info, copy and print a DMI line */
        if (manufacturer || product || board) {
            if (!manufacturer) manufacturer = "Unknown";
            if (!product) product = "";
            strncpy(dmi_manufacturer, manufacturer, sizeof(dmi_manufacturer)-1);
            dmi_manufacturer[sizeof(dmi_manufacturer)-1] = '\0';
            if (board && board[0]) {
                char combined[256];
                snprintf(combined, sizeof(combined), "%s %s/%s", dmi_manufacturer, product, board);
                strncpy(dmi_product, combined, sizeof(dmi_product)-1);
                dmi_product[sizeof(dmi_product)-1] = '\0';
                klogprintf("DMI: %s\n", dmi_product);
            } else {
                strncpy(dmi_product, product, sizeof(dmi_product)-1);
                dmi_product[sizeof(dmi_product)-1] = '\0';
                klogprintf("DMI: %s %s\n", dmi_manufacturer, dmi_product);
            }
            return;
        }
        /* if we get here, no useful info; continue scanning */
    }
}

const char* sysinfo_cpu_name(void) { return sys_cpu_name; }
int sysinfo_ram_mb(void) { return sys_ram_mb; }
int sysinfo_pc_type(void) { return sys_pc_type; }


