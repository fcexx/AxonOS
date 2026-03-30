#include <gdt.h>
#include <vga.h>
#include <stdint.h>
#include <axonos.h>
#include <debug.h>
#include <mmio.h>
#include <smp.h>

#pragma pack(push,1)
struct gdtr {
        uint16_t limit;
        uint64_t base;
};

struct tss64 {
        uint32_t reserved0;
        uint64_t rsp0;
        uint64_t rsp1;
        uint64_t rsp2;
        uint64_t reserved1;
        uint64_t ist1;
        uint64_t ist2;
        uint64_t ist3;
        uint64_t ist4;
        uint64_t ist5;
        uint64_t ist6;
        uint64_t ist7;
        uint64_t reserved2;
        uint16_t reserved3;
        uint16_t io_map_base;
};
#pragma pack(pop)

/* Segments 0..4, then one 16-byte TSS descriptor per logical CPU (indices 5+2*i). */
#define GDT_SEG_SLOTS 5
#define GDT_TSS_SLOTS (2 * SMP_MAX_CPUS)
static uint8_t gdt[8 * (GDT_SEG_SLOTS + GDT_TSS_SLOTS)] = {0};
static struct gdtr gdt_desc;
static struct tss64 cpu_tss[SMP_MAX_CPUS];

uint16_t KERNEL_CS = 0x08;
uint16_t KERNEL_DS = 0x10;
uint16_t USER_CS   = 0x1B; // index 3, RPL=3
uint16_t USER_DS   = 0x23; // index 4, RPL=3

static void set_seg_desc(int idx, uint32_t base, uint32_t limit, uint8_t access, uint8_t flags) {
        uint8_t* d = &gdt[idx * 8];

        // limit 15:0
        d[0] = limit & 0xFF;
        d[1] = (limit >> 8) & 0xFF;

        // base 15:0
        d[2] = base & 0xFF;
        d[3] = (base >> 8) & 0xFF;

        // base 23:16
        d[4] = (base >> 16) & 0xFF;

        // access
        d[5] = access;

        // flags and limit 19:16
        d[6] = ((flags & 0xF0)) | ((limit >> 16) & 0x0F);

        // base 31:24
        d[7] = (base >> 24) & 0xFF;
}

static void set_tss_desc(int idx, uint64_t base, uint32_t limit) {
        // TSS descriptor occupies 16 bytes at idx and idx+1
        uint8_t* d = &gdt[idx * 8];

        // lower 8 bytes
        d[0] = limit & 0xFF;                       // limit 0:7
        d[1] = (limit >> 8) & 0xFF;                // limit 8:15
        d[2] = base & 0xFF;                        // base 0:7
        d[3] = (base >> 8) & 0xFF;                 // base 8:15
        d[4] = (base >> 16) & 0xFF;                // base 16:23
        d[5] = 0x89;                               // type=0x9, present=1, DPL=0 (64-bit TSS available)
        d[6] = ((limit >> 16) & 0x0F);             // limit 16:19, flags=0
        d[7] = (base >> 24) & 0xFF;                // base 24:31

        // upper 8 bytes
        d[8]  = (base >> 32) & 0xFF;           // base 32:39
        d[9]  = (base >> 40) & 0xFF;           // base 40:47
        d[10] = (base >> 48) & 0xFF;           // base 48:55
        d[11] = (base >> 56) & 0xFF;           // base 56:63
        d[12] = 0;
        d[13] = 0;
        d[14] = 0;
        d[15] = 0;
}

void lgdt_load(void* gdtr_ptr);
void ltr_load(uint16_t sel);
void enter_user_mode_asm(uint64_t entry, uint64_t user_stack, uint16_t user_ds, uint16_t user_cs);

void gdt_init() {
        // null descriptor
        set_seg_desc(0, 0, 0, 0, 0);

        // kernel code (long mode): access=0x9A (present|ring0|code|read), flags L=1 (0x20), G can be 0
        set_seg_desc(1, 0, 0, 0x9A, 0x20);

        // kernel data: access=0x92 (present|ring0|data|write), flags=0
        set_seg_desc(2, 0, 0, 0x92, 0x00);

        // user code: access=0xFA (present|ring3|code|read), flags L=1
        set_seg_desc(3, 0, 0, 0xFA, 0x20);

        // user data: access=0xF2 (present|ring3|data|write)
        set_seg_desc(4, 0, 0, 0xF2, 0x00);

        for (int ti = 0; ti < SMP_MAX_CPUS; ti++) {
                for (int i = 0; i < (int)sizeof(cpu_tss[0]) / 8; ++i)
                        ((uint64_t *)&cpu_tss[ti])[i] = 0;
                cpu_tss[ti].io_map_base = sizeof(cpu_tss[0]);
                uint64_t tss_base = (uint64_t)&cpu_tss[ti];
                uint32_t tss_limit = (uint32_t)sizeof(cpu_tss[0]) - 1u;
                set_tss_desc(5 + 2 * ti, tss_base, tss_limit);
        }

        gdt_desc.limit = sizeof(gdt) - 1;
        gdt_desc.base = (uint64_t)&gdt[0];

        lgdt_load(&gdt_desc);
        
        // Load TR with TSS selector (index 5 -> selector 0x28)
        ltr_load(0x28);

        /* no debug prints */
        /* ВАЖНО:
           Многие libc (musl/glibc) при наличии FSGSBASE в CPUID начинают использовать
           WRFSBASE напрямую и менять FS base *внутри* функций со stack-protector.
           Если до этого FS==0, canary берётся из fs:0x28 (адрес 0x28), а после WRFSBASE
           сравнение идёт уже по новому TLS -> ложный "*** stack smashing detected ***".
           Пока у нас нет полноценного TLS/TCB, держим CR4.FSGSBASE выключенным и
           эмулируем нужные инструкции через #UD (см. cpu/idt.c). */
        
        // Check if FSGSBASE is supported via CPUID
        uint32_t eax, ebx, ecx, edx;
        asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(7), "c"(0));
        int fsgsbase_supported = (ebx & (1 << 0)) != 0;
        /* no debug prints */
        
        if (fsgsbase_supported) {
                uint64_t cr4;
                asm volatile("mov %%cr4, %0" : "=r"(cr4));
                cr4 &= ~(1ULL << 16); // CR4.FSGSBASE OFF (see comment above)
                asm volatile("mov %0, %%cr4" :: "r"(cr4) : "memory");
        }
}

void gdt_fill_smp_mailbox_lgdt(uint16_t *gdt_lim, uint32_t *gdt_base32) {
        if (gdt_lim)
                *gdt_lim = gdt_desc.limit;
        if (gdt_base32)
                *gdt_base32 = (uint32_t)gdt_desc.base;
}

void gdt_ltr_for_cpu(int cpu_index) {
        if (cpu_index < 0 || cpu_index >= SMP_MAX_CPUS)
                cpu_index = 0;
        ltr_load((uint16_t)((5 + 2 * cpu_index) * 8));
}

void tss_set_rsp0(uint64_t rsp0) {
        int c = smp_sched_cpu_id();
        if (c < 0 || c >= SMP_MAX_CPUS)
                c = 0;
        cpu_tss[c].rsp0 = rsp0;
        extern uint64_t syscall_kernel_rsp0;
        if (c == 0)
                syscall_kernel_rsp0 = rsp0;
}

void tss_set_ist_for_cpu(int cpu, int idx, uint64_t rsp_top) {
        if (cpu < 0 || cpu >= SMP_MAX_CPUS)
                return;
        uint64_t *istp = NULL;
        switch (idx) {
        case 1:
                istp = &cpu_tss[cpu].ist1;
                break;
        case 2:
                istp = &cpu_tss[cpu].ist2;
                break;
        case 3:
                istp = &cpu_tss[cpu].ist3;
                break;
        case 4:
                istp = &cpu_tss[cpu].ist4;
                break;
        case 5:
                istp = &cpu_tss[cpu].ist5;
                break;
        case 6:
                istp = &cpu_tss[cpu].ist6;
                break;
        case 7:
                istp = &cpu_tss[cpu].ist7;
                break;
        default:
                return;
        }
        *istp = rsp_top;
}

void tss_set_ist(int idx, uint64_t rsp_top) {
        tss_set_ist_for_cpu(smp_sched_cpu_id(), idx, rsp_top);
}

void enter_user_mode(uint64_t user_entry, uint64_t user_stack_top) {
        enter_user_mode_asm(user_entry, user_stack_top, USER_DS, USER_CS);
} 

// Set the user FS base MSR for the CPU. Used when switching a thread into user mode.
void set_user_fs_base(uint64_t base) {
        uint32_t lo = (uint32_t)(base & 0xFFFFFFFFu);
        uint32_t hi = (uint32_t)(base >> 32);
        asm volatile("wrmsr" :: "c"(0xC0000100u), "a"(lo), "d"(hi));
}

/* Called from assembly trampoline right before iret frame is pushed.
   We are still in kernel context; print the exact iret-frame values and a small
   stack/code dump to diagnose mis-frames or bad mappings. */
void enter_user_pre_iret(uint64_t entry, uint64_t user_stack, uint16_t user_ds, uint16_t user_cs, uint64_t rflags) {
    uint64_t cr3 = 0;
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
}

void enter_user_post_iret(uint64_t ss, uint64_t user_rsp, uint64_t rflags, uint16_t user_cs, uint64_t rip) {
}