#ifndef APIC_TIMER_H
#define APIC_TIMER_H

#include <stdint.h>
#include <stdbool.h>

#define APIC_TIMER_VECTOR     0x20

// Timer modes
#define APIC_TIMER_PERIODIC   0x20000
#define APIC_TIMER_ONESHOT    0x00000

// Divider values
#define APIC_DIV_1   0xB
#define APIC_DIV_2   0x0
#define APIC_DIV_4   0x1
#define APIC_DIV_8   0x2
#define APIC_DIV_16  0x3
#define APIC_DIV_32  0x8
#define APIC_DIV_64  0x9
#define APIC_DIV_128 0xA

void apic_timer_init(void);
void apic_timer_stop(void);
void apic_timer_start(uint32_t freq_hz);
void apic_timer_calibrate_with_pit(void);
void apic_timer_handler(void);
uint64_t apic_timer_get_ticks(void);
uint64_t apic_timer_get_time_ms(void);
bool apic_timer_is_running(void);
uint32_t apic_timer_get_frequency(void);

extern volatile uint64_t apic_timer_ticks;

#endif