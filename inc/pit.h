#ifndef PIT_H
#define PIT_H

#include <stdint.h>
#include <idt.h>

// PIT ports
#define PIT_CHANNEL0            0x40
#define PIT_COMMAND             0x43

// PIT command byte
#define PIT_CMD_CHANNEL0        0x00
#define PIT_CMD_ACCESS_LO       0x10
#define PIT_CMD_ACCESS_HI       0x20
#define PIT_CMD_ACCESS_BOTH     0x30
#define PIT_CMD_MODE0           0x00  // interrupt on terminal count
#define PIT_CMD_MODE2           0x04  // rate generator
#define PIT_CMD_MODE3           0x06  // square wave generator
#define PIT_CMD_MODE4           0x08  // software triggered strobe
#define PIT_CMD_MODE5           0x0A  // hardware triggered strobe
#define PIT_CMD_BINARY          0x00
#define PIT_CMD_BCD             0x01

// PIT frequency (1193180 Hz)
#define PIT_FREQUENCY           1193180

// function declarations
void pit_init();
void pit_disable(void);  // Добавь эту строку
void pit_set_frequency(uint32_t frequency);
void pit_set_divisor(uint16_t divisor);
uint16_t pit_get_current_count();
void pit_handler(cpu_registers_t* regs);
void pit_sleep_ms(uint32_t milliseconds);
uint64_t pit_get_ticks();
uint64_t pit_get_time_ms();
uint64_t pit_get_frequency();

// global variables
extern volatile uint64_t pit_ticks;
extern volatile uint32_t pit_frequency;

#endif // PIT_H