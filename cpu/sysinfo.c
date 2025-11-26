#include "../inc/sysinfo.h"
#include <stdint.h>

char sys_cpu_name[64] = "Unknown CPU";
int sys_ram_mb = -1;
int sys_pc_type = 0;

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
                uint32_t total_kb = mem_lower + mem_upper;
                sys_ram_mb = (int)(total_kb / 1024);
            }
        }
        // Для multiboot2: информация начинается с total_size (uint32) и reserved (uint32), затем теги
        else if (multiboot_magic == 0x36d76289u) {
            uint8_t *p = (uint8_t*)(uintptr_t)multiboot_info_ptr;
            uint32_t total_size = *(uint32_t*)p;
            // tags start at offset 8
            uint32_t offset = 8;
            while (offset + 8 <= total_size) {
                uint32_t tag_type = *(uint32_t*)(p + offset);
                uint32_t tag_size = *(uint32_t*)(p + offset + 4);
                if (tag_type == 4) { // BASIC_MEMINFO
                    // layout: tag header (8) then mem_lower(uint32) mem_upper(uint32)
                    uint32_t mem_lower = *(uint32_t*)(p + offset + 8);
                    uint32_t mem_upper = *(uint32_t*)(p + offset + 12);
                    uint32_t total_kb = mem_lower + mem_upper;
                    sys_ram_mb = (int)(total_kb / 1024);
                    break;
                }
                if (tag_type == 0) break; // end tag
                // tags are aligned to 8 bytes
                uint32_t next = ((tag_size + 7) & ~7u);
                offset += next;
            }
        }
    }
}

const char* sysinfo_cpu_name(void) { return sys_cpu_name; }
int sysinfo_ram_mb(void) { return sys_ram_mb; }
int sysinfo_pc_type(void) { return sys_pc_type; }


