#include <apic.h>
#include <stdio.h>

static uint32_t* lapic_base = NULL;
static bool apic_initialized = false;

static uint64_t msr_read(uint32_t msr) {
    uint32_t low, high;
    asm volatile ("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

static void msr_write(uint32_t msr, uint64_t value) {
    uint32_t low = value & 0xFFFFFFFF;
    uint32_t high = value >> 32;
    asm volatile ("wrmsr" : : "c"(msr), "a"(low), "d"(high));
}

void apic_init(void) {
    kprintf("APIC: Initializing...\n");
    
    // Enable APIC in MSR
    uint64_t apic_base_msr = msr_read(0x1B);
    apic_base_msr |= (1 << 11);
    msr_write(0x1B, apic_base_msr);
    
    // Get base address
    uint32_t base_addr = apic_base_msr & 0xFFFFF000;
    lapic_base = (uint32_t*)base_addr;
    
    // Enable APIC in SVR
    uint32_t svr = apic_read(LAPIC_SVR_REG);
    apic_write(LAPIC_SVR_REG, svr | LAPIC_SVR_ENABLE | APIC_SPURIOUS_VECTOR);
    
    apic_initialized = true;
    kprintf("APIC: Initialized at 0x%x\n", base_addr);
}

uint32_t apic_read(uint32_t reg) {
    if (!lapic_base) return 0;
    return *(volatile uint32_t*)((uint8_t*)lapic_base + reg);
}

void apic_write(uint32_t reg, uint32_t value) {
    if (!lapic_base) return;
    *(volatile uint32_t*)((uint8_t*)lapic_base + reg) = value;
}

void apic_eoi(void) {
    if (lapic_base) {
        apic_write(LAPIC_EOI_REG, 0);
    }
}

void apic_set_lvt_timer(uint32_t vector, uint32_t mode, bool masked) {
    uint32_t val = vector | mode;
    if (masked) val |= LAPIC_TIMER_MASKED;
    apic_write(LAPIC_LVT_TIMER_REG, val);
}

bool apic_is_initialized(void) {
    return apic_initialized;
}