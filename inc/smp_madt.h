#ifndef SMP_MADT_H
#define SMP_MADT_H

#include <stdint.h>
#include <smp.h>

/* mb_magic/mb_info: Multiboot2 for scanning ACPI regions in mmap (VMware puts RSDP there). */
int smp_madt_enumerate(uint8_t bsp_apic, int *out_n, uint8_t out_map[SMP_MAX_CPUS],
		       uint32_t mb_magic, uint64_t mb_info);

#endif
