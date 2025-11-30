#include <apic_timer.h>
#include <apic.h>
#include <pit.h>
#include <stdio.h>
#include <string.h>

volatile uint64_t apic_timer_ticks = 0;
apic_timer_state_t apic_timer_state = {0};

// Timer divider values (encoded for APIC timer divider register)
static const uint8_t apic_dividers[] = {0x3, 0x0, 0x1, 0x2, 0x8, 0x9, 0xA, 0xB};
static const uint32_t divider_values[] = {16, 2, 4, 8, 32, 64, 128, 1};

// Find best divider for target frequency
static uint8_t find_best_divider(uint32_t target_freq, uint32_t base_freq, uint32_t* out_count) {
    for (int i = 0; i < 8; i++) {
        uint32_t div = divider_values[i];
        uint32_t count = (base_freq / div) / target_freq;
        
        if (count > 0 && count <= 0xFFFFF) {
            *out_count = count;
            return apic_dividers[i];
        }
    }
    
    // Fallback to divider 16
    *out_count = base_freq / 16 / target_freq;
    return 0x3;
}

// Quick calibration using busy loop
static uint32_t quick_calibrate(void) {
    kprintf("APIC Timer: Quick calibration...\n");
    
    // Setup timer for one-shot
    apic_set_lvt_timer(APIC_TIMER_VECTOR, APIC_TIMER_ONESHOT, false);
    apic_write(LAPIC_TIMER_DIV_REG, 0x3); // Divider 16
    
    // Set maximum count
    apic_write(LAPIC_TIMER_INIT_REG, 0xFFFFFFFF);
    
    // Busy wait for ~10ms
    for (volatile int i = 0; i < 100000; i++) {
        asm volatile("pause");
    }
    
    // Calculate elapsed ticks
    uint32_t remaining = apic_read(LAPIC_TIMER_CURRENT_REG);
    uint32_t elapsed = 0xFFFFFFFF - remaining;
    
    // Stop timer
    apic_write(LAPIC_TIMER_INIT_REG, 0);
    
    kprintf("APIC Timer: Calibration result: %u ticks/10ms\n", elapsed);
    return elapsed * 100; // Convert to Hz
}

// Simple integer to string conversion
static void uint_to_str(uint64_t value, char* buffer) {
    if (value == 0) {
        buffer[0] = '0';
        buffer[1] = '\0';
        return;
    }
    
    char temp[20];
    int i = 0;
    
    while (value > 0) {
        temp[i++] = '0' + (value % 10);
        value /= 10;
    }
    
    for (int j = 0; j < i; j++) {
        buffer[j] = temp[i - j - 1];
    }
    buffer[i] = '\0';
}

// Simple string copy
static void str_copy(char* dest, const char* src) {
    while (*src) {
        *dest++ = *src++;
    }
    *dest = '\0';
}

// Format uptime into human readable string
void apic_timer_format_uptime(char* buffer, size_t buffer_size) {
    uint64_t seconds = apic_timer_get_uptime_seconds();
    
    if (seconds == 0) {
        str_copy(buffer, "00:00:00");
        return;
    }
    
    uint64_t days = seconds / (24 * 3600);
    uint64_t hours = (seconds % (24 * 3600)) / 3600;
    uint64_t minutes = (seconds % 3600) / 60;
    uint64_t secs = seconds % 60;
    
    char days_str[10];
    char hours_str[3];
    char minutes_str[3];
    char secs_str[3];
    
    // Format hours, minutes, seconds with leading zeros
    uint_to_str(hours, hours_str);
    uint_to_str(minutes, minutes_str);
    uint_to_str(secs, secs_str);
    
    // Ensure two digits
    if (hours < 10) {
        char temp[3];
        temp[0] = '0';
        temp[1] = hours_str[0];
        temp[2] = '\0';
        str_copy(hours_str, temp);
    }
    
    if (minutes < 10) {
        char temp[3];
        temp[0] = '0';
        temp[1] = minutes_str[0];
        temp[2] = '\0';
        str_copy(minutes_str, temp);
    }
    
    if (secs < 10) {
        char temp[3];
        temp[0] = '0';
        temp[1] = secs_str[0];
        temp[2] = '\0';
        str_copy(secs_str, temp);
    }
    
    if (days > 0) {
        uint_to_str(days, days_str);
        // Format: Xd HH:MM:SS
        char* ptr = buffer;
        str_copy(ptr, days_str);
        ptr += strlen(days_str);
        *ptr++ = 'd';
        *ptr++ = ' ';
        str_copy(ptr, hours_str);
        ptr += 2;
        *ptr++ = ':';
        str_copy(ptr, minutes_str);
        ptr += 2;
        *ptr++ = ':';
        str_copy(ptr, secs_str);
    } else {
        // Format: HH:MM:SS
        char* ptr = buffer;
        str_copy(ptr, hours_str);
        ptr += 2;
        *ptr++ = ':';
        str_copy(ptr, minutes_str);
        ptr += 2;
        *ptr++ = ':';
        str_copy(ptr, secs_str);
    }
}

uint64_t apic_timer_get_uptime_seconds(void) {
    return apic_timer_get_time_ms() / 1000;
}

void apic_timer_handler(void) {
    apic_timer_ticks++;
    apic_timer_state.ticks = apic_timer_ticks;
    apic_eoi();
}

void apic_timer_init(void) {
    kprintf("APIC Timer: Initializing...\n");
    
    // Initialize state
    apic_timer_ticks = 0;
    apic_timer_state.ticks = 0;
    apic_timer_state.frequency = 0;
    apic_timer_state.running = false;
    apic_timer_state.calibrated = false;
    apic_timer_state.mode = APIC_TIMER_PERIODIC;
    
    // Perform quick calibration
    apic_timer_state.base_frequency = quick_calibrate();
    apic_timer_state.calibration_value = apic_timer_state.base_frequency / 100;
    apic_timer_state.calibrated = true;
    
    // Stop timer initially
    apic_timer_stop();
    
    kprintf("APIC Timer: Ready (base freq: %u Hz)\n", apic_timer_state.base_frequency);
}

void apic_timer_start(uint32_t freq_hz) {
    if (!apic_timer_state.calibrated) {
        kprintf("APIC Timer: Not calibrated, cannot start\n");
        return;
    }
    
    if (apic_timer_state.running) {
        apic_timer_stop();
    }
    
    kprintf("APIC Timer: Starting at %u Hz\n", freq_hz);
    
    uint32_t count;
    uint8_t divider = find_best_divider(freq_hz, apic_timer_state.base_frequency, &count);
    
    // Apply limits
    if (count < 10) count = 10;
    if (count > 0xFFFFF) count = 0xFFFFF;
    
    kprintf("APIC Timer: Divider: %u, Count: %u\n", divider_values[divider & 0x7], count);
    
    // Configure timer
    apic_write(LAPIC_TIMER_DIV_REG, divider);
    apic_write(LAPIC_TIMER_INIT_REG, count);
    apic_set_lvt_timer(APIC_TIMER_VECTOR, APIC_TIMER_PERIODIC, false);
    
    // Update state
    apic_timer_state.frequency = freq_hz;
    apic_timer_state.running = true;
    apic_timer_state.mode = APIC_TIMER_PERIODIC;
    apic_timer_ticks = 0;
    
    kprintf("APIC Timer: Started successfully\n");
}

void apic_timer_start_oneshot(uint32_t microseconds) {
    if (!apic_timer_state.calibrated) return;
    
    uint32_t count = (apic_timer_state.base_frequency * microseconds) / 1000000;
    if (count < 10) count = 10;
    
    apic_write(LAPIC_TIMER_DIV_REG, 0x3); // Divider 16
    apic_write(LAPIC_TIMER_INIT_REG, count);
    apic_set_lvt_timer(APIC_TIMER_VECTOR, APIC_TIMER_ONESHOT, false);
    
    apic_timer_state.running = true;
    apic_timer_state.mode = APIC_TIMER_ONESHOT;
}

void apic_timer_stop(void) {
    apic_set_lvt_timer(0, 0, true); // Mask timer
    apic_write(LAPIC_TIMER_INIT_REG, 0); // Stop counter
    apic_timer_state.running = false;
    kprintf("APIC Timer: Stopped\n");
}

void apic_timer_set_frequency(uint32_t freq_hz) {
    if (apic_timer_state.running) {
        apic_timer_start(freq_hz);
    } else {
        apic_timer_state.frequency = freq_hz;
    }
}

uint64_t apic_timer_get_ticks(void) {
    return apic_timer_ticks;
}

uint64_t apic_timer_get_time_ms(void) {
    if (apic_timer_state.frequency == 0) return 0;
    return (apic_timer_ticks * 1000) / apic_timer_state.frequency;
}

uint64_t apic_timer_get_time_us(void) {
    if (apic_timer_state.frequency == 0) return 0;
    return (apic_timer_ticks * 1000000) / apic_timer_state.frequency;
}

uint32_t apic_timer_get_frequency(void) {
    return apic_timer_state.frequency;
}

bool apic_timer_is_running(void) {
    return apic_timer_state.running;
}

bool apic_timer_is_calibrated(void) {
    return apic_timer_state.calibrated;
}

void apic_timer_sleep_ms(uint32_t ms) {
    if (!apic_timer_state.running) {
        pit_sleep_ms(ms);
        return;
    }
    
    uint64_t target_ticks = apic_timer_ticks + (ms * apic_timer_state.frequency) / 1000;
    while (apic_timer_ticks < target_ticks) {
        asm volatile("pause");
    }
}

void apic_timer_sleep_us(uint32_t us) {
    if (!apic_timer_state.running) {
        // Busy wait fallback
        for (volatile uint32_t i = 0; i < us; i++) {
            asm volatile("pause");
        }
        return;
    }
    
    uint64_t target_ticks = apic_timer_ticks + (us * apic_timer_state.frequency) / 1000000;
    while (apic_timer_ticks < target_ticks) {
        asm volatile("pause");
    }
}

void apic_timer_calibrate(void) {
    apic_timer_state.base_frequency = quick_calibrate();
    apic_timer_state.calibration_value = apic_timer_state.base_frequency / 100;
    apic_timer_state.calibrated = true;
    kprintf("APIC Timer: Recalibrated (base freq: %u Hz)\n", apic_timer_state.base_frequency);
}