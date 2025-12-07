#pragma once

#include <stdint.h>

// Простая структура/переменные для информации о системе
extern char sys_cpu_name[64];
extern int sys_ram_mb; // -1 если неизвестно
// pc_type: 1 - BIOS/legacy boot, 0 - UEFI/other/unknown
extern int sys_pc_type;

// Инициализация — вызывается из kernel_main
void sysinfo_init(uint32_t multiboot_magic, uint64_t multiboot_info_ptr);

// Получатели
const char* sysinfo_cpu_name(void);
int sysinfo_ram_mb(void);
int sysinfo_pc_type(void);


