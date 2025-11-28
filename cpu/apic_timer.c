#include <apic_timer.h>
#include <apic.h>
#include <stdio.h>
#include <pit.h>

volatile uint64_t apic_timer_ticks = 0;
static uint32_t apic_current_frequency = 0;
static bool apic_timer_running = false;
static uint32_t apic_timer_calib_count = 0;

// Обработчик прерывания ДОЛЖЕН быть объявлен как ISR
void apic_timer_handler(void) {
    apic_timer_ticks++;
    apic_eoi(); // Важно: отправляем EOI в APIC
}

uint64_t apic_timer_get_ticks(void) {
    return apic_timer_ticks;
}

uint64_t apic_timer_get_time_ms(void) {
    if (apic_current_frequency == 0) return 0;
    return (apic_timer_ticks * 1000) / apic_current_frequency;
}

bool apic_timer_is_running(void) {
    return apic_timer_running;
}

uint32_t apic_timer_get_frequency(void) {
    return apic_current_frequency;
}

void apic_timer_stop(void) {
    // Маскируем таймер и останавливаем
    apic_write(LAPIC_LVT_TIMER_REG, LAPIC_TIMER_MASKED);
    apic_write(LAPIC_TIMER_INIT_REG, 0);
    apic_timer_running = false;
    kprintf("APIC Timer: Stopped\n");
}

void apic_timer_calibrate_with_pit(void) {
    kprintf("APIC Timer: Calibrating with PIT...\n");
    
    // Останавливаем таймер
    apic_timer_stop();
    
    // Настраиваем APIC таймер в oneshot режиме
    apic_write(LAPIC_LVT_TIMER_REG, APIC_TIMER_VECTOR | APIC_TIMER_ONESHOT);
    apic_write(LAPIC_TIMER_DIV_REG, APIC_DIV_16);
    
    // Устанавливаем большое значение
    uint32_t initial_count = 0xFFFFF;
    apic_write(LAPIC_TIMER_INIT_REG, initial_count);
    
    // Ждем 10ms через PIT
    uint64_t start = pit_get_ticks();
    while (pit_get_ticks() - start < 10) {
        asm volatile("pause");
    }
    
    // Читаем оставшееся значение
    uint32_t remaining = apic_read(LAPIC_TIMER_CURRENT_REG);
    uint32_t elapsed = initial_count - remaining;
    
    // Сохраняем калибровочное значение (тиков на 10ms)
    apic_timer_calib_count = elapsed;
    
    kprintf("APIC Timer: Calibration: %u ticks in 10ms\n", apic_timer_calib_count);
    
    // Останавливаем таймер
    apic_timer_stop();
}

void apic_timer_start(uint32_t freq_hz) {
    if (!apic_is_initialized()) {
        kprintf("APIC Timer: APIC not initialized\n");
        return;
    }
    
    kprintf("APIC Timer: Starting at %u Hz\n", freq_hz);
    
    // Если не откалиброван, используем разумное значение
    if (apic_timer_calib_count == 0) {
        apic_timer_calib_count = 100000; // Эмпирическое значение для 10ms
        kprintf("APIC Timer: Using default calibration\n");
    }
    
    // Вычисляем начальное значение счетчика
    // apic_timer_calib_count = ticks per 10ms
    // Для freq_hz: ticks per second = freq_hz
    // initial_count = (calib_count * freq_hz) / 100
    uint32_t initial_count = (apic_timer_calib_count * freq_hz) / 100;
    
    // Ограничиваем разумными значениями
    if (initial_count < 100) initial_count = 100;
    if (initial_count > 0xFFFFF) initial_count = 0xFFFFF;
    
    kprintf("APIC Timer: Initial count: %u\n", initial_count);
    
    // 1. Маскируем таймер перед настройкой
    apic_write(LAPIC_LVT_TIMER_REG, LAPIC_TIMER_MASKED);
    
    // 2. Настраиваем делитель
    apic_write(LAPIC_TIMER_DIV_REG, APIC_DIV_16);
    
    // 3. Устанавливаем начальное значение
    apic_write(LAPIC_TIMER_INIT_REG, initial_count);
    
    // 4. Настраиваем LVT (vector + periodic mode + unmasked)
    uint32_t lvt_value = APIC_TIMER_VECTOR | APIC_TIMER_PERIODIC;
    apic_write(LAPIC_LVT_TIMER_REG, lvt_value);
    
    kprintf("APIC Timer: LVT configured to 0x%x\n", lvt_value);
    
    // Проверяем настройки
    uint32_t verify_lvt = apic_read(LAPIC_LVT_TIMER_REG);
    uint32_t verify_div = apic_read(LAPIC_TIMER_DIV_REG);
    uint32_t verify_init = apic_read(LAPIC_TIMER_INIT_REG);
    
    kprintf("APIC Timer: Verify - LVT: 0x%x, DIV: 0x%x, INIT: %u\n", 
            verify_lvt, verify_div, verify_init);
    
    // Проверяем что таймер не маскирован
    if ((verify_lvt & LAPIC_TIMER_MASKED) != 0) {
        kprintf("APIC Timer: ERROR - Timer is masked!\n");
        return;
    }
    
    apic_current_frequency = freq_hz;
    apic_timer_running = true;
    apic_timer_ticks = 0;
    
    kprintf("APIC Timer: Started successfully\n");
}

void apic_timer_init(void) {
    if (!apic_is_initialized()) {
        kprintf("APIC Timer: APIC not initialized\n");
        return;
    }
    
    kprintf("APIC Timer: Initializing\n");
    
    // Проверяем что APIC работает
    uint32_t apic_id = apic_get_id();
    uint32_t svr = apic_read(LAPIC_SVR_REG);
    
    kprintf("APIC Timer: APIC ID: 0x%x, SVR: 0x%x\n", apic_id, svr);
    
    if (!(svr & LAPIC_SVR_ENABLE)) {
        kprintf("APIC Timer: WARNING - APIC not enabled in SVR!\n");
        return;
    }
    
    // Калибруем таймер
    apic_timer_calibrate_with_pit();
    
    kprintf("APIC Timer: Ready\n");
}