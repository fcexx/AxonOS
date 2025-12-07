#ifndef MMIO_H
#define MMIO_H

#include <stdint.h>
#include <stdbool.h>

static inline uint8_t mmio_read8(uintptr_t addr) {
    return *(volatile uint8_t*)addr;
}

static inline uint16_t mmio_read16(uintptr_t addr) {
    return *(volatile uint16_t*)addr;
}

static inline uint32_t mmio_read32(uintptr_t addr) {
    return *(volatile uint32_t*)addr;
}

static inline void mmio_write8(uintptr_t addr, uint8_t value) {
    *(volatile uint8_t*)addr = value;
}

static inline void mmio_write16(uintptr_t addr, uint16_t value) {
    *(volatile uint16_t*)addr = value;
}

static inline void mmio_write32(uintptr_t addr, uint32_t value) {
    *(volatile uint32_t*)addr = value;
}

static inline void mmio_memory_barrier(void) {
    asm volatile("mfence" ::: "memory");
}

static inline void mmio_set_bits16(uintptr_t addr, uint16_t mask) {
    uint16_t val = mmio_read16(addr);
    mmio_write16(addr, val | mask);
}

static inline void mmio_clear_bits16(uintptr_t addr, uint16_t mask) {
    uint16_t val = mmio_read16(addr);
    mmio_write16(addr, val & ~mask);
}

static inline void mmio_set_bits32(uintptr_t addr, uint32_t mask) {
    uint32_t val = mmio_read32(addr);
    mmio_write32(addr, val | mask);
}

static inline void mmio_clear_bits32(uintptr_t addr, uint32_t mask) {
    uint32_t val = mmio_read32(addr);
    mmio_write32(addr, val & ~mask);
}

void mmio_init(void);
int mmio_command(int argc, char** argv);

#endif // MMIO_H