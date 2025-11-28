#ifndef APIC_H
#define APIC_H

#include <stdint.h>
#include <stdbool.h>

#define LAPIC_ID_REG          0x020
#define LAPIC_VERSION_REG     0x030
#define LAPIC_TPR_REG         0x080
#define LAPIC_APR_REG         0x090
#define LAPIC_PPR_REG         0x0A0
#define LAPIC_EOI_REG         0x0B0
#define LAPIC_SVR_REG         0x0F0
#define LAPIC_LVT_TIMER_REG   0x320
#define LAPIC_TIMER_INIT_REG  0x380
#define LAPIC_TIMER_CURRENT_REG 0x390
#define LAPIC_TIMER_DIV_REG   0x3E0

#define LAPIC_SVR_ENABLE      (1 << 8)
#define LAPIC_SVR_SPURIOUS_VECTOR_MASK 0xFF

#define LAPIC_TIMER_MODE_PERIODIC  (1 << 17)
#define LAPIC_TIMER_MODE_ONESHOT   0x00000
#define LAPIC_TIMER_MASKED    (1 << 16)

#define LAPIC_TIMER_DIV_16    0x3

#define MSR_APIC_BASE         0x1B
#define APIC_BASE_MSR_ENABLE  (1 << 11)
#define APIC_BASE_MSR_BSP     (1 << 8)
#define APIC_BASE_MSR_ADDR_MASK 0xFFFFF000

#define APIC_TIMER_VECTOR     0x20

// Добавим функции для работы с прерываниями
void apic_init(void);
uint32_t apic_read(uint32_t reg);
void apic_write(uint32_t reg, uint32_t value);
void apic_eoi(void);
uint32_t apic_get_id(void);
bool apic_is_initialized(void);
void apic_enable(void);
void apic_disable(void);

#endif