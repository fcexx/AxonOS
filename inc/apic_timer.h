#ifndef APIC_TIMER_H
#define APIC_TIMER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define APIC_TIMER_VECTOR     0x30

// Timer modes
typedef enum {
    APIC_TIMER_ONESHOT = 0,
    APIC_TIMER_PERIODIC = (1 << 17),
    APIC_TIMER_TSC_DEADLINE = (1 << 18)
} apic_timer_mode_t;

// Timer state
typedef struct {
    uint64_t ticks;
    uint32_t frequency;
    uint32_t base_frequency;
    uint32_t calibration_value;
    apic_timer_mode_t mode;
    bool running;
    bool calibrated;
} apic_timer_state_t;

// Public API
void apic_timer_init(void);
void apic_timer_start(uint32_t freq_hz);
void apic_timer_start_oneshot(uint32_t microseconds);
void apic_timer_stop(void);
void apic_timer_handler(void);

uint64_t apic_timer_get_ticks(void);
uint64_t apic_timer_get_time_ms(void);
uint64_t apic_timer_get_time_us(void);
uint32_t apic_timer_get_frequency(void);
bool apic_timer_is_running(void);
bool apic_timer_is_calibrated(void);

void apic_timer_calibrate(void);
void apic_timer_set_frequency(uint32_t freq_hz);
void apic_timer_sleep_ms(uint32_t ms);
void apic_timer_sleep_us(uint32_t us);

// Uptime functions
uint64_t apic_timer_get_uptime_seconds(void);
void apic_timer_format_uptime(char* buffer, size_t buffer_size);

// Global state
extern volatile uint64_t apic_timer_ticks;
extern apic_timer_state_t apic_timer_state;

#endif