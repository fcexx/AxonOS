#ifndef SMP_H
#define SMP_H

#include <stdint.h>

#define SMP_MAX_CPUS 16

#define SMP_MAILBOX_PHYS 0x9000
/* Avoid 0x8000: many firmwares/VMs reserve or touch the legacy 32 KiB region; SIPI starts at vector<<12. */
#define SMP_TRAMPOLINE_PHYS 0x10000u
#define SMP_SIPI_VECTOR       (SMP_TRAMPOLINE_PHYS >> 12)

/* Fixed phys scratch for AP bring-up diagnostics (identity map; outside BDA 0x40..0x4FF). */
#define SMP_DIAG_PING_RM   0x5000u /* real mode started */
#define SMP_DIAG_PING_LM   0x5004u /* long mode entered */
#define SMP_DIAG_PING_PM32 0x5008u /* protected 32-bit reached */
#define SMP_DIAG_MAGIC_RM   0x31505341u   /* 'ASP1' */
#define SMP_DIAG_MAGIC_PM32 0xDEAD0032u
#define SMP_DIAG_MAGIC_LM   0xDEAD0044u

void smp_early_init(void);
/* mb_*: used to parse ACPI MADT before LAPIC is up (real CPU count vs wrong CPUID.1 EBX[23:16]). */
void smp_init(uint32_t multiboot_magic, uint64_t multiboot_info_ptr);
/* After apic_init(): re-read CPU count + APIC IDs from ACPI MADT if present. Call before thread_init(). */
void smp_finalize_topology(uint32_t multiboot_magic, uint64_t multiboot_info_ptr);
int smp_cpu_count(void);
/* Non-zero if CPU count / APIC map came from ACPI MADT (pre-LAPIC or finalize). */
int smp_have_acpi_cpu_topology(void);
uint64_t smp_default_affinity_mask(void);
int smp_sched_cpu_id(void);

/* Boot non-BSP processors (INIT-SIPI-SIPI + trampoline). Call after apic_init, pit_init, thread_init. */
void smp_boot_aps(void);

/* LAPIC id for logical cpu index (0..smp_cpu_count()-1); valid after smp_boot_aps for fallback topology too. */
uint8_t smp_apic_id_for_logical_cpu(int logical_cpu);
/* Wake another logical CPU (APIC fixed IPI); no-op if target is current or APIC not up. */
void smp_ipi_reschedule(int target_logical_cpu);

#endif
