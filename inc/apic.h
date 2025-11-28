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

void apic_init(void);
uint32_t apic_read(uint32_t reg);
void apic_write(uint32_t reg, uint32_t value);
void apic_eoi(void);
void apic_set_lvt_timer(uint32_t vector, uint32_t mode, bool masked);
bool apic_is_initialized(void);

#endif