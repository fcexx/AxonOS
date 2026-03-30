#include <apic.h>
#include <vga.h>
#include <klog.h>
#include <stdint.h>

/* Volatile: AP may call apic_local_enable later; avoid C11 data races / stale loads of the pointer. */
static volatile uintptr_t lapic_base_va;
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

#define MSR_IA32_APIC_BASE 0x1Bu
#define MSR_IA32_X2APIC_ID 0x802u
#define MSR_X2APIC_ICR 0x830u
#define MSR_X2APIC_EOI 0x80Bu
#define APIC_BASE_EXTD (1ULL << 10)
#define LAPIC_ICR_DEST_EXCLUDE_SELF (3u << 18)

/* Per-logical-CPU LAPIC bring-up (MMIO at the same canonical address aliases to local). */
static uint32_t apic_local_enable(void) {
    uint64_t apic_base_msr = msr_read(0x1B);
    apic_base_msr |= (1ULL << 11);
    msr_write(0x1B, apic_base_msr);
    apic_base_msr = msr_read(0x1B);

    uintptr_t base_addr = (uintptr_t)(apic_base_msr & 0xFFFFF000ULL);
    lapic_base_va = base_addr;

    uint32_t svr = apic_read(LAPIC_SVR_REG);
    apic_write(LAPIC_SVR_REG, svr | LAPIC_SVR_ENABLE | APIC_SPURIOUS_VECTOR);

    /* Firmware may leave the local timer LVT unmasked; mask and stop the counter. */
    apic_set_lvt_timer(0, 0, true);
    apic_write(LAPIC_TIMER_INIT_REG, 0);

    return (uint32_t)base_addr;
}

void apic_init(void) {
    uint32_t base_addr = apic_local_enable();
    apic_initialized = true;
    klogprintf("APIC: Initializing timer at 0x%x\n", base_addr);
}

void apic_ap_enable_local(void) {
    (void)apic_local_enable();
}

uint32_t apic_read(uint32_t reg) {
    uintptr_t b = lapic_base_va;
    if (!b)
        return 0;
    return *(volatile uint32_t *)((uint8_t *)b + reg);
}

void apic_write(uint32_t reg, uint32_t value) {
    uintptr_t b = lapic_base_va;
    if (!b)
        return;
    *(volatile uint32_t *)((uint8_t *)b + reg) = value;
    /* Serialize MMIO (ICR especially); avoids reorder vs next insn / other CPU observers. */
    asm volatile("mfence" ::: "memory");
}

void apic_eoi(void) {
    /* x2APIC mode: MMIO to 0xFEE0xxxx is not used; EOI must go via MSR (SDM). */
    uint64_t ab = msr_read(MSR_IA32_APIC_BASE);
    if (ab & APIC_BASE_EXTD) {
        msr_write(MSR_X2APIC_EOI, 0);
        return;
    }
    if (lapic_base_va)
        apic_write(LAPIC_EOI_REG, 0);
}

void apic_set_lvt_timer(uint32_t vector, uint32_t mode, bool masked) {
    uint32_t val = vector | mode;
    if (masked) val |= LAPIC_TIMER_MASKED;
    apic_write(LAPIC_LVT_TIMER_REG, val);
}

bool apic_is_initialized(void) {
    return apic_initialized;
}

uint32_t apic_local_apic_id(void) {
    uint64_t ab = msr_read(MSR_IA32_APIC_BASE);
    if (ab & APIC_BASE_EXTD)
        return (uint32_t)msr_read(MSR_IA32_X2APIC_ID);
    if (!lapic_base_va)
        return 0;
    return apic_read(LAPIC_ID_REG) >> 24;
}

static void lapic_icr_wait(void) {
        /* Do not time out: overlapping ICR writes while Delivery Status=1 corrupts bring-up. */
        while (apic_read(LAPIC_ICR_LOW) & LAPIC_ICR_BUSY)
                asm volatile("pause" ::: "memory");
}

static void lapic_icr_wait_x2(void) {
        for (;;) {
                uint64_t v = msr_read(MSR_X2APIC_ICR);
                if ((v & (1ULL << 12)) == 0)
                        break;
                asm volatile("pause" ::: "memory");
        }
}

/* Physical destination: xAPIC uses id<<24 in MMIO high dword; x2APIC uses 32-bit id in MSR high half. */
static void lapic_icr_send_phy(uint8_t apic_id, uint32_t icr_low) {
        uint64_t ab = msr_read(MSR_IA32_APIC_BASE);
        if (ab & APIC_BASE_EXTD) {
                uint64_t v = ((uint64_t)(uint32_t)apic_id << 32) | (uint64_t)icr_low;
                msr_write(MSR_X2APIC_ICR, v);
                lapic_icr_wait_x2();
                return;
        }
        if (!lapic_base_va)
                return;
        apic_write(LAPIC_ICR_HIGH, (uint32_t)apic_id << 24);
        asm volatile("" ::: "memory");
        apic_write(LAPIC_ICR_LOW, icr_low);
        lapic_icr_wait();
}

void lapic_send_init(uint8_t apic_id) {
        /* INIT: delivery INIT (8:10), trigger level (14), level assert (13). */
        lapic_icr_send_phy(apic_id, LAPIC_ICR_DM_INIT | LAPIC_ICR_LEVEL_ASSERT | (1u << 14));
}

void lapic_send_init_deassert(uint8_t apic_id) {
        lapic_icr_send_phy(apic_id, LAPIC_ICR_DM_INIT | (1u << 14));
}

void lapic_send_init_deassert_broadcast(void) {
        /* Level-triggered INIT de-assert; destination field ignored when shorthand != 0. */
        if (!lapic_base_va)
                return;
        lapic_icr_send_phy(0, LAPIC_ICR_DM_INIT | (1u << 14) | LAPIC_ICR_DEST_EXCLUDE_SELF);
}

void lapic_send_sipi(uint8_t apic_id, uint8_t vec) {
        /* SIPI must be edge-triggered (bit14=0). Intel SDM Vol.3A §10.6. */
        lapic_icr_send_phy(apic_id, LAPIC_ICR_DM_STARTUP | ((uint32_t)vec & 0xFFu));
}

void lapic_send_ipi_vector(uint8_t apic_id, uint8_t vector) {
        /* Fixed delivery (ICR 10:8 = 0), physical destination, assert edge. */
        lapic_icr_send_phy(apic_id, (uint32_t)vector & 0xFFu);
}