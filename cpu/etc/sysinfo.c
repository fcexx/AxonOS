#include <sysinfo.h>
#include <stdint.h>

char sys_cpu_name[64] = "Unknown CPU";
int sys_ram_mb = -1;
int sys_pc_type = 0;

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
}

const char* sysinfo_cpu_name(void) { return sys_cpu_name; }
int sysinfo_ram_mb(void) { return sys_ram_mb; }
int sysinfo_pc_type(void) { return sys_pc_type; }


