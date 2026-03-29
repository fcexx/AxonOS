#include <smp.h>
#include <smp_madt.h>
#include <apic.h>
#include <klog.h>
#include <paging.h>
#include <string.h>
#include <gdt.h>
#include <thread.h>
#include <debug.h>
#include <vga.h>

#define MSR_IA32_TSC_AUX 0xC0000103u

extern uint8_t ap_trampoline_bin_start[];
extern uint8_t ap_trampoline_bin_end[];

static int smp_ncpus = 1;
static int smp_early_done;
static uint8_t smp_apic_per_cpu[SMP_MAX_CPUS];
static int smp_topology_from_madt;

/* AP trampoline mailbox at fixed phys 0x9000 (see linker.payload.ld). */
struct __attribute__((packed)) smp_mailbox {
        volatile uint32_t cookie;
        uint32_t cpu_index;
        uint64_t cr3;
        uint64_t stack_top;
        uint64_t entry;
        uint16_t gdt_lim;
        uint32_t gdt_base32;
        uint16_t _pad_ist;
        uint64_t saved_cr4;
};

__attribute__((section(".smp_mailbox"), aligned(64))) static struct smp_mailbox smp_mbox;

volatile uint32_t smp_online_mask;

/* BSP sets to 1 after INIT/SIPI and mailbox work complete; APs must not run
 * thread_schedule until then (avoids races with BSP smp_boot_aps and guest reboot loops). */
static uint32_t smp_boot_done;

static volatile struct smp_mailbox *smp_mbox_hw(void) {
        return (volatile struct smp_mailbox *)(uintptr_t)SMP_MAILBOX_PHYS;
}

/* Evict mailbox from BSP data cache so another vCPU reads RAM (VMware may not snoop WB lines). */
static void smp_mailbox_clflush(volatile struct smp_mailbox *mb) {
        uintptr_t start = (uintptr_t)mb & ~63u;
        uintptr_t end = ((uintptr_t)mb + sizeof(struct smp_mailbox) + 63u) & ~63u;
        for (uintptr_t a = start; a < end; a += 64u) {
                void *ln = (void *)a;
                asm volatile("clflush (%0)" :: "r"(ln) : "memory");
        }
        asm volatile("mfence" ::: "memory");
}

/* Nth APIC id in ascending order, skipping BSP (never send INIT/SIPI to bsp_lapic). */
static uint8_t smp_apic_id_for_ap_index(uint32_t bsp_lapic, int ap_index) {
        int seen = 0;
        for (int aid = 0; aid < 256; aid++) {
                if (aid == (int)(bsp_lapic & 0xFFu))
                        continue;
                seen++;
                if (seen == ap_index)
                        return (uint8_t)aid;
        }
        return 0xFFu;
}

static void wrmsr_u32(uint32_t msr, uint32_t lo, uint32_t hi) {
        asm volatile("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

static void rdmsr_u32(uint32_t msr, uint32_t *lo, uint32_t *hi) {
        uint32_t a = 0, d = 0;
        asm volatile("rdmsr" : "=a"(a), "=d"(d) : "c"(msr));
        if (lo)
                *lo = a;
        if (hi)
                *hi = d;
}

/* Intel/AMD extended topology (CPUID.0Bh): product of EBX[15:0] at each non-zero level.
 * VMware/QEMU often leave CPUID.1 EBX[23:16] at 1 even with several vCPUs. */
static int smp_ncpus_from_cpuid_leaf_b(void) {
        uint32_t max_leaf = 0;
        asm volatile("cpuid" : "=a"(max_leaf) : "a"(0) : "ebx", "ecx", "edx");
        if (max_leaf < 11u)
                return 0;

        uint64_t prod = 1;
        for (uint32_t sub = 0; sub < 32u; sub++) {
                uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
                asm volatile("cpuid"
                             : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                             : "a"(11u), "c"(sub)
                             : "memory");
                uint32_t level_type = (ecx >> 8) & 0xffu;
                if (level_type == 0)
                        break;
                uint32_t cnt = ebx & 0xffffu;
                if (cnt == 0)
                        continue;
                uint64_t next = prod * (uint64_t)cnt;
                if (next > (uint64_t)SMP_MAX_CPUS)
                        return SMP_MAX_CPUS;
                prod = next;
        }
        if (prod <= 1u)
                return 0;
        return (int)prod;
}

void smp_early_init(void) {
        if (smp_early_done)
                return;
        smp_early_done = 1;
        wrmsr_u32(MSR_IA32_TSC_AUX, 0u, 0u);

        uint32_t a = 0, b = 0, c = 0, d = 0;
        asm volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
        int n = (int)((b >> 16) & 0xFFu);
        if (n < 1)
                n = 1;
        if (n > SMP_MAX_CPUS)
                n = SMP_MAX_CPUS;

        int n_b = smp_ncpus_from_cpuid_leaf_b();
        if (n_b > n)
                n = n_b;
        if (n > SMP_MAX_CPUS)
                n = SMP_MAX_CPUS;
        smp_ncpus = n;
}

void smp_init(uint32_t mb_magic, uint64_t mb_info) {
        smp_early_init();
        kprintf("SMP: CPUID.1 EBX[23:16] (often wrong on QEMU/VMs) -> %d logical\n", smp_ncpus);

        uint32_t a = 0, b = 0, c = 0, d = 0;
        asm volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
        uint8_t bsp_guess = (uint8_t)((b >> 24) & 0xffu);
        int n = 0;
        uint8_t map[SMP_MAX_CPUS];
        if (smp_madt_enumerate(bsp_guess, &n, map, mb_magic, mb_info) == 0 && n >= 1 &&
            n <= SMP_MAX_CPUS) {
                smp_ncpus = n;
                memcpy(smp_apic_per_cpu, map, (size_t)n);
                smp_topology_from_madt = 1;
                kprintf("SMP: ACPI MADT (pre-LAPIC): %d CPUs\n", n);
        }
}

void smp_finalize_topology(uint32_t multiboot_magic, uint64_t multiboot_info_ptr) {
        if (!apic_is_initialized())
                return;
        uint8_t bsp = (uint8_t)(apic_local_apic_id() & 0xFFu);
        int n = 0;
        uint8_t map[SMP_MAX_CPUS];
        if (smp_madt_enumerate(bsp, &n, map, multiboot_magic, multiboot_info_ptr) != 0) {
                if (!smp_topology_from_madt)
                        klogprintf("SMP: MADT not used (sequential APIC guess vs BSP apic %u)\n",
                                   (unsigned)bsp);
                return;
        }
        if (n < 1 || n > SMP_MAX_CPUS)
                return;
        smp_ncpus = n;
        memcpy(smp_apic_per_cpu, map, (size_t)n);
        smp_topology_from_madt = 1;
        klogprintf("SMP: MADT topology (BSP lapic %u): %d CPUs\n", (unsigned)bsp, n);
        for (int i = 0; i < n; i++)
                klogprintf("SMP:   logical cpu %d -> lapic id %u\n", i, (unsigned)smp_apic_per_cpu[i]);
}

int smp_cpu_count(void) {
        return smp_ncpus;
}

int smp_have_acpi_cpu_topology(void) {
        return smp_topology_from_madt;
}

uint64_t smp_default_affinity_mask(void) {
        int n = smp_ncpus;
        if (n <= 0)
                return 1ULL;
        if (n >= 64)
                return ~0ULL;
        return (1ULL << n) - 1ULL;
}

int smp_sched_cpu_id(void) {
        uint32_t lo = 0, hi = 0;
        rdmsr_u32(MSR_IA32_TSC_AUX, &lo, &hi);
        int id = (int)lo;
        if (id < 0 || id >= SMP_MAX_CPUS)
                return 0;
        return id;
}

uint8_t smp_apic_id_for_logical_cpu(int logical_cpu) {
        if (logical_cpu < 0 || logical_cpu >= smp_ncpus)
                return 0;
        return smp_apic_per_cpu[logical_cpu];
}

void smp_ipi_reschedule(int target_logical_cpu) {
        (void)target_logical_cpu;
        /* Disabled: fixed-delivery IPI + per-CPU sched_target caused triple-fault regressions
         * on VMware/SMP; idle hlt + bound_cpu affinity is enough until a safer kick path exists. */
}

void smp_ap_entry(void);

/* Millisecond-scale busy wait from TSC; works with IF=0 (unlike pit_sleep_ms + timer_ticks). */
static void smp_mdelay_tsc(unsigned ms) {
        uint32_t lo, hi;
        asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
        uint64_t t0 = ((uint64_t)hi << 32) | lo;
        uint64_t delta;
        if (klog_tsc_per_us != 0)
                delta = (uint64_t)ms * 1000ULL * klog_tsc_per_us;
        else
                delta = (uint64_t)ms * 5000000ULL;
        uint64_t goal = t0 + delta;
        for (;;) {
                asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
                uint64_t t1 = ((uint64_t)hi << 32) | lo;
                if (t1 >= goal)
                        break;
                asm volatile("pause" ::: "memory");
        }
}

void smp_boot_aps(void) {
        if (smp_ncpus <= 1)
                return;
        if (!apic_is_initialized()) {
                klogprintf("SMP: apic not ready, skip AP boot\n");
                return;
        }

        size_t tr_sz = (size_t)(ap_trampoline_bin_end - ap_trampoline_bin_start);
        if (tr_sz == 0 || tr_sz > 4096) {
                klogprintf("SMP: bad trampoline size %zu\n", tr_sz);
                return;
        }

        uint32_t bsp_lapic = apic_local_apic_id();
        if (!smp_topology_from_madt && smp_ncpus > 0) {
                smp_apic_per_cpu[0] = (uint8_t)(bsp_lapic & 0xFFu);
                for (int i = 1; i < smp_ncpus; i++) {
                        uint8_t aid = smp_apic_id_for_ap_index(bsp_lapic, i);
                        smp_apic_per_cpu[i] = aid;
                }
        }
        if ((uintptr_t)&smp_mbox != (uintptr_t)SMP_MAILBOX_PHYS)
                klogprintf("SMP: mailbox symbol %p (expected phys %#x); AP uses fixed %#x\n",
                           (void *)&smp_mbox, SMP_MAILBOX_PHYS, SMP_MAILBOX_PHYS);

        __atomic_store_n(&smp_boot_done, 0u, __ATOMIC_RELEASE);

        /* INIT/SIPI and mailbox must not interleave with timer IRQ -> thread_schedule on BSP. */
        unsigned long irq_save;
        asm volatile("pushfq; pop %0" : "=r"(irq_save));
        asm volatile("cli" ::: "memory");
        qemu_debug_printf("SMP: BSP cli, memcpy trampoline -> %#x\n", SMP_TRAMPOLINE_PHYS);

        /* Trampoline + mailbox live in the first 2MiB. If any path marked that range user (PG_US) and
         * firmware left CR4.SMEP set, the AP faults on the first instruction fetch before smp_ap_entry. */
        if (map_page_2m(0, 0, PG_PRESENT | PG_RW | PG_GLOBAL) != 0)
                klogprintf("SMP: map_page_2m(0..2MiB) failed; AP boot may fault under SMEP\n");

        memcpy((void *)(uintptr_t)SMP_TRAMPOLINE_PHYS, ap_trampoline_bin_start, tr_sz);
        asm volatile("" ::: "memory");
        invlpg((void *)(uintptr_t)SMP_TRAMPOLINE_PHYS);
        asm volatile("wbinvd" ::: "memory");

        smp_online_mask |= 1u;

        uint64_t cr4 = 0;
        asm volatile("mov %%cr4, %0" : "=r"(cr4));
        cr4 |= (1ULL << 5); /* PAE */
        cr4 &= ~((1ULL << 20) | (1ULL << 21)); /* SMEP, SMAP — AP must fetch trampoline from low phys */

        for (int cpu = 1; cpu < smp_ncpus; cpu++) {
                thread_t *idle = thread_idle_for_cpu(cpu);
                if (!idle) {
                        klogprintf("SMP: no idle for cpu %d, skip\n", cpu);
                        continue;
                }

                uint8_t apic_id = smp_topology_from_madt ? smp_apic_per_cpu[cpu]
                                                         : smp_apic_id_for_ap_index(bsp_lapic, cpu);
                if (!smp_topology_from_madt && apic_id == 0xFFu) {
                        klogprintf("SMP: no APIC id for cpu %d (bsp_lapic=%u)\n", cpu, (unsigned)bsp_lapic);
                        continue;
                }

                *(volatile uint32_t *)(uintptr_t)SMP_DIAG_PING_RM = 0u;
                *(volatile uint32_t *)(uintptr_t)SMP_DIAG_PING_LM = 0u;
                *(volatile uint32_t *)(uintptr_t)SMP_DIAG_PING_PM32 = 0u;
                asm volatile("mfence" ::: "memory");

                volatile struct smp_mailbox *mb = smp_mbox_hw();
                memset((void *)mb, 0, sizeof(struct smp_mailbox));
                mb->cpu_index = (uint32_t)cpu;
                mb->cr3 = paging_read_cr3();
                mb->stack_top = idle->kernel_stack;
                mb->entry = (uint64_t)(uintptr_t)smp_ap_entry;
                mb->saved_cr4 = cr4;
                {
                        uint16_t glim = 0;
                        uint32_t gb = 0;
                        gdt_fill_smp_mailbox_lgdt(&glim, &gb);
                        mb->gdt_lim = glim;
                        mb->gdt_base32 = gb;
                }
                mb->cookie = 1;
                asm volatile("mfence" ::: "memory");
                smp_mailbox_clflush(mb);
                /* clflush may not be enough on some hosts; flush caches entirely before INIT/SIPI. */
                asm volatile("wbinvd" ::: "memory");

                qemu_debug_printf("SMP: INIT apic_id=%u cpu_index=%d\n", (unsigned)apic_id, cpu);
                lapic_send_init(apic_id);
                smp_mdelay_tsc(20);
                /* Targeted de-assert only: some VMware builds mishandle ICR shorthand "all excl. self". */
                lapic_send_init_deassert(apic_id);
                smp_mdelay_tsc(10);
                lapic_send_sipi(apic_id, SMP_SIPI_VECTOR);
                smp_mdelay_tsc(10);
                lapic_send_sipi(apic_id, SMP_SIPI_VECTOR);

                qemu_debug_printf("SMP: wait AP cpu=%d online (mask now %#x)\n", cpu,
                                  (unsigned)__atomic_load_n(&smp_online_mask, __ATOMIC_RELAXED));
                int spins = 0;
                while (spins < 200000000) {
                        uint32_t m = __atomic_load_n(&smp_online_mask, __ATOMIC_ACQUIRE);
                        if (m & (1u << (unsigned)cpu))
                                break;
                        asm volatile("pause" ::: "memory");
                        spins++;
                }
                if (!(__atomic_load_n(&smp_online_mask, __ATOMIC_RELAXED) & (1u << (unsigned)cpu))) {
                        uint32_t d0 = *(volatile uint32_t *)(uintptr_t)SMP_DIAG_PING_RM;
                        uint32_t d4 = *(volatile uint32_t *)(uintptr_t)SMP_DIAG_PING_LM;
                        uint32_t d8 = *(volatile uint32_t *)(uintptr_t)SMP_DIAG_PING_PM32;
                        qemu_debug_printf("SMP: TIMEOUT cpu=%d mask=%#x\n", cpu,
                                          (unsigned)__atomic_load_n(&smp_online_mask, __ATOMIC_RELAXED));
                        klogprintf("SMP: AP cpu=%d apic_id=%u did not come online (diag phys %#x=%#x %#x=%#x %#x=%#x; "
                                   "exp RM %#x PM32 %#x LM %#x)\n",
                                   cpu, (unsigned)apic_id,
                                   SMP_DIAG_PING_RM, (unsigned)d0, SMP_DIAG_PING_LM, (unsigned)d4,
                                   SMP_DIAG_PING_PM32, (unsigned)d8,
                                   (unsigned)SMP_DIAG_MAGIC_RM, (unsigned)SMP_DIAG_MAGIC_PM32,
                                   (unsigned)SMP_DIAG_MAGIC_LM);
                } else {
                        qemu_debug_printf("SMP: AP cpu=%d online\n", cpu);
                        klogprintf("SMP: AP cpu=%d apic_id=%u online\n", cpu, (unsigned)apic_id);
                }
        }

        /* Release APs before restoring IF on BSP so they are not stuck behind popfq. */
        __atomic_store_n(&smp_boot_done, 1u, __ATOMIC_RELEASE);
        asm volatile("mfence" ::: "memory");
        qemu_debug_printf("SMP: boot_done=1, restoring IF on BSP\n");
        asm volatile("push %0; popfq" :: "r"(irq_save) : "memory");
}

void smp_ap_entry(void) {
        uint32_t cpu = smp_mbox_hw()->cpu_index;
        if (cpu >= (uint32_t)SMP_MAX_CPUS)
                cpu = 0;

        /* Unblock BSP wait before TR/TSS/LAPIC: if ltr or TSS faults, BSP no longer spins forever. */
        __atomic_or_fetch(&smp_online_mask, 1u << cpu, __ATOMIC_SEQ_CST);
        asm volatile("mfence" ::: "memory");

        wrmsr_u32(MSR_IA32_TSC_AUX, cpu, 0u);

        gdt_ltr_for_cpu((int)cpu);

        thread_t *idle = thread_idle_for_cpu((int)cpu);
        if (idle && idle->kernel_stack)
                tss_set_rsp0(idle->kernel_stack);

        while (!__atomic_load_n(&smp_boot_done, __ATOMIC_ACQUIRE))
                asm volatile("pause" ::: "memory");

        apic_ap_enable_local();

        for (;;) {
                thread_schedule();
                asm volatile("sti; hlt" ::: "memory");
        }
}
