#include <apic.h>
#include <stdio.h>  // для kprintf

static uint32_t* lapic_base = NULL;
static bool apic_initialized = false;
static uint32_t apic_phys_base = 0;

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

static uint32_t mmio_read32(uint32_t addr) {
    return *((volatile uint32_t*)(apic_phys_base + addr));
}

static void mmio_write32(uint32_t addr, uint32_t value) {
    *((volatile uint32_t*)(apic_phys_base + addr)) = value;
}

void apic_enable(void) {
    uint64_t apic_base_msr = msr_read(MSR_APIC_BASE);
    if (!(apic_base_msr & APIC_BASE_MSR_ENABLE)) {
        kprintf("APIC: Enabling in MSR\n");
        apic_base_msr |= APIC_BASE_MSR_ENABLE;
        msr_write(MSR_APIC_BASE, apic_base_msr);
    }
}

void apic_disable(void) {
    uint64_t apic_base_msr = msr_read(MSR_APIC_BASE);
    if (apic_base_msr & APIC_BASE_MSR_ENABLE) {
        kprintf("APIC: Disabling in MSR\n");
        apic_base_msr &= ~APIC_BASE_MSR_ENABLE;
        msr_write(MSR_APIC_BASE, apic_base_msr);
    }
}

void apic_init(void) {
    kprintf("APIC: Initializing...\n");
    
    // Включаем APIC
    apic_enable();
    
    uint64_t apic_base_msr = msr_read(MSR_APIC_BASE);
    kprintf("APIC: MSR 0x1B = 0x%llx\n", apic_base_msr);
    
    if (!(apic_base_msr & APIC_BASE_MSR_ENABLE)) {
        kprintf("APIC: ERROR - Failed to enable APIC\n");
        return;
    }
    
    apic_phys_base = apic_base_msr & APIC_BASE_MSR_ADDR_MASK;
    lapic_base = (uint32_t*)apic_phys_base;
    
    kprintf("APIC: Base address = 0x%x\n", apic_phys_base);
    
    // Проверяем, что можем читать/писать в APIC
    uint32_t apic_id = apic_get_id();
    uint32_t apic_version = apic_read(LAPIC_VERSION_REG);
    kprintf("APIC: ID = 0x%x, Version = 0x%x\n", apic_id, apic_version);
    
    if (apic_id == 0 && apic_version == 0) {
        kprintf("APIC: WARNING - Possible APIC access issues\n");
    }
    
    // Включаем APIC и настраиваем spurious interrupt vector
    uint32_t svr = apic_read(LAPIC_SVR_REG);
    kprintf("APIC: SVR before = 0x%x\n", svr);
    
    svr |= LAPIC_SVR_ENABLE;
    svr = (svr & ~LAPIC_SVR_SPURIOUS_VECTOR_MASK) | APIC_TIMER_VECTOR;
    apic_write(LAPIC_SVR_REG, svr);
    
    kprintf("APIC: SVR after = 0x%x\n", apic_read(LAPIC_SVR_REG));
    
    apic_initialized = true;
    kprintf("APIC: Initialization complete\n");
}

uint32_t apic_read(uint32_t reg) {
    if (!lapic_base) {
        return 0;
    }
    return mmio_read32(reg);
}

void apic_write(uint32_t reg, uint32_t value) {
    if (!lapic_base) {
        return;
    }
    mmio_write32(reg, value);
}

void apic_eoi(void) {
    apic_write(LAPIC_EOI_REG, 0);
}

uint32_t apic_get_id(void) {
    return (apic_read(LAPIC_ID_REG) >> 24) & 0xFF;
}

bool apic_is_initialized(void) {
    return apic_initialized;
}