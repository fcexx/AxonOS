#ifndef APIC_H
#define APIC_H

#include <stdint.h>
#include <stdbool.h>

#define LAPIC_ID_REG          0x020
#define LAPIC_VERSION_REG     0x030
#define LAPIC_EOI_REG         0x0B0
#define LAPIC_SVR_REG         0x0F0
#define LAPIC_LVT_TIMER_REG   0x320
#define LAPIC_TIMER_INIT_REG  0x380
#define LAPIC_TIMER_CURRENT_REG 0x390  // <-- ДОБАВЬ ЭТУ СТРОКУ
#define LAPIC_TIMER_DIV_REG   0x3E0

#define LAPIC_SVR_ENABLE      (1 << 8)
#define LAPIC_TIMER_MODE_PERIODIC  (1 << 17)
#define LAPIC_TIMER_MASKED    (1 << 16)

#define APIC_TIMER_VECTOR     0x30
#define APIC_SPURIOUS_VECTOR  0xFF
/* Fixed delivery IPI for scheduler kick (must not collide with timer/RTC/PIC vectors). */
#define APIC_IPI_RESCHED_VECTOR 0xFDu

#define LAPIC_ICR_LOW         0x300
#define LAPIC_ICR_HIGH        0x310

/* ICR low: delivery mode in bits 10:8; bit 13 Level (1=assert) required for INIT (Intel SDM). */
#define LAPIC_ICR_DM_INIT     0x500u
#define LAPIC_ICR_DM_STARTUP  0x600u
#define LAPIC_ICR_LEVEL_ASSERT (1u << 13)
#define LAPIC_ICR_BUSY        (1u << 12)

void apic_init(void);
/* Enable this CPU's LAPIC after SIPI (no klog; avoid re-entering printk/heap from AP). */
void apic_ap_enable_local(void);
uint32_t apic_read(uint32_t reg);
void apic_write(uint32_t reg, uint32_t value);
void apic_eoi(void);
void apic_set_lvt_timer(uint32_t vector, uint32_t mode, bool masked);
bool apic_is_initialized(void);

/* Local APIC id: LAPIC_ID >> 24 in xAPIC; IA32_X2APIC_ID MSR when EXTD=1. */
uint32_t apic_local_apic_id(void);

/* INIT / Startup IPI for AP bring-up (xAPIC destination field in ICR high). */
void lapic_send_init(uint8_t apic_id);
void lapic_send_init_deassert(uint8_t apic_id);
void lapic_send_init_deassert_broadcast(void);
void lapic_send_sipi(uint8_t apic_id, uint8_t vector);
/* Fixed delivery, physical destination, edge — vector in low 8 bits of ICR low. */
void lapic_send_ipi_vector(uint8_t apic_id, uint8_t vector);

#endif