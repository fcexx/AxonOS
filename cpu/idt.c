#include <idt.h>
#include <vga.h>
#include <pic.h>
#include <thread.h>
#include <rtc.h>
//#include <pit.h>
#include <stdint.h>
//#include <thread.h>
#include <stdint.h>
#include <stddef.h>
#include <apic_timer.h>
#include <debug.h>
#include <mmio.h>
// Avoid including <cstdint> because cross-toolchain headers may not provide it; use uint64_t instead

// Forward declare C-linkage helpers from other compilation units
uint64_t dbg_saved_rbx_in;
uint64_t dbg_saved_rbx_out;

// локальные таблицы обработчиков (неиспользуемые предупреждения устраним использованием ниже)
static void (*irq_handlers[16])() = {NULL};
static void (*isr_handlers[256])(cpu_registers_t*) = {NULL};

static struct idt_entry_t idt[256];
static struct idt_ptr_t idt_ptr;
// сообщения об исключениях — определение для внешней декларации из idt.h
const char* exception_messages[] = {
        "Division By Zero","Debug","Non Maskable Interrupt","Breakpoint","Into Detected Overflow",
        "Out of Bounds","Invalid Opcode","No Coprocessor","Double fault","Coprocessor Segment Overrun",
        "Bad TSS","Segment not present","Stack fault","General protection fault","Page fault",
        "Unknown Interrupt","Coprocessor Fault","Alignment Fault","Machine Check",
        "Reserved","Reserved","Reserved","Reserved","Reserved","Reserved","Reserved","Reserved",
        "Reserved","Reserved","Reserved","Reserved","Reserved"
};

static inline void read_crs(uint64_t* cr0, uint64_t* cr2, uint64_t* cr3, uint64_t* cr4){
        uint64_t t0=0,t2=0,t3=0,t4=0; (void)t0; (void)t2; (void)t3; (void)t4;
        asm volatile("mov %%cr0, %0" : "=r"(t0));
        asm volatile("mov %%cr2, %0" : "=r"(t2));
        asm volatile("mov %%cr3, %0" : "=r"(t3));
        asm volatile("mov %%cr4, %0" : "=r"(t4));
        if (cr0) *cr0 = t0; if (cr2) *cr2 = t2; if (cr3) *cr3 = t3; if (cr4) *cr4 = t4;
}

static void dump(const char* what, const char* who, cpu_registers_t* regs, uint64_t cr2, uint64_t err, bool user_mode){
        kprintf("Oops! %s in %s at RIP=0x%llx err=0x%llx\n", what, who, (unsigned long long)regs->rip, (unsigned long long)regs->error_code);
        kprintf("RIP: 0x%llx\n", (unsigned long long)regs->rip);
        kprintf("RSP: 0x%llx\n", (unsigned long long)regs->rsp);
        kprintf("RBP: 0x%llx\n", (unsigned long long)regs->rbp);
        kprintf("RDI: 0x%llx\n", (unsigned long long)regs->rdi);
        kprintf("RSI: 0x%llx\n", (unsigned long long)regs->rsi);
        kprintf("RDX: 0x%llx\n", (unsigned long long)regs->rdx);
        kprintf("RCX: 0x%llx\n", (unsigned long long)regs->rcx);
}

static inline uint64_t rdmsr_u64(uint32_t msr) {
        uint32_t lo=0, hi=0;
        asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
        return ((uint64_t)hi << 32) | lo;
}
static inline void wrmsr_u64(uint32_t msr, uint64_t v) {
        uint32_t lo = (uint32_t)(v & 0xFFFFFFFFu);
        uint32_t hi = (uint32_t)(v >> 32);
        asm volatile("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

static void ud_fault_handler(cpu_registers_t* regs) {
        /* Invalid Opcode (#UD).
           В ring3 перехватываем FSGSBASE инструкции (RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE),
           которые libc может использовать при наличии CPUID.FSGSBASE. Мы держим CR4.FSGSBASE
           выключенным ради совместимости (см. cpu/gdt.c), поэтому эти опкоды попадают сюда. */
        if ((regs->cs & 3) == 3) {
                const uint8_t *ip = (const uint8_t*)(uintptr_t)regs->rip;
                /* Encoding: F3 0F AE /r with reg field:
                   /0 RDFSBASE, /1 RDGSBASE, /2 WRFSBASE, /3 WRGSBASE */
                if ((uintptr_t)ip + 4 < (uintptr_t)MMIO_IDENTITY_LIMIT &&
                    ip[0] == 0xF3 && ip[1] == 0x0F && ip[2] == 0xAE) {
                        uint8_t modrm = ip[3];
                        uint8_t mod = (modrm >> 6) & 3;
                        uint8_t reg = (modrm >> 3) & 7;
                        uint8_t rm  = (modrm >> 0) & 7;
                        if (mod == 3 && reg <= 3) {
                                /* helpers to access GPR by index (rm) */
                                uint64_t *gpr = NULL;
                                switch (rm) {
                                        case 0: gpr = &regs->rax; break;
                                        case 1: gpr = &regs->rcx; break;
                                        case 2: gpr = &regs->rdx; break;
                                        case 3: gpr = &regs->rbx; break;
                                        case 4: gpr = &regs->rsp; break;
                                        case 5: gpr = &regs->rbp; break;
                                        case 6: gpr = &regs->rsi; break;
                                        case 7: gpr = &regs->rdi; break;
                                }

                                enum { MSR_FS_BASE = 0xC0000100u, MSR_GS_BASE = 0xC0000101u };

                                if (reg == 0 /* RDFSBASE */) {
                                        if (gpr) *gpr = rdmsr_u64(MSR_FS_BASE);
                                        regs->rip += 4;
                                        return;
                                } else if (reg == 1 /* RDGSBASE */) {
                                        if (gpr) *gpr = rdmsr_u64(MSR_GS_BASE);
                                        regs->rip += 4;
                                        return;
                                } else if (reg == 2 /* WRFSBASE */) {
                                        uint64_t new_fs = gpr ? *gpr : 0;
                                        /* keep stack canary stable across FS changes: copy old fs:0x28 into new fs:0x28 */
                                        uint64_t old_fs = rdmsr_u64(MSR_FS_BASE);
                                        uint64_t old_guard = 0;
                                        if (old_fs + 0x30 < (uint64_t)MMIO_IDENTITY_LIMIT) old_guard = *(volatile uint64_t*)(uintptr_t)(old_fs + 0x28);
                                        else if (0x30 < (uint64_t)MMIO_IDENTITY_LIMIT) old_guard = *(volatile uint64_t*)(uintptr_t)0x28;
                                        wrmsr_u64(MSR_FS_BASE, new_fs);
                                        if (new_fs + 0x30 < (uint64_t)MMIO_IDENTITY_LIMIT) *(volatile uint64_t*)(uintptr_t)(new_fs + 0x28) = old_guard;
                                        regs->rip += 4;
                                        return;
                                } else if (reg == 3 /* WRGSBASE */) {
                                        uint64_t new_gs = gpr ? *gpr : 0;
                                        wrmsr_u64(MSR_GS_BASE, new_gs);
                                        regs->rip += 4;
                                        return;
                                }
                        }
                }

                dump("invalid opcode", "user", regs, 0, 0, true);
                /* Dump nearby code bytes to help diagnose user UD */
                {
                    uintptr_t rip = (uintptr_t)regs->rip;
                    const int BYTES = 32;
                    uintptr_t start = rip > BYTES ? rip - BYTES : rip;
                    if (start + BYTES*2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                        kprintf("user code dump around RIP=0x%llx:\n", (unsigned long long)rip);
                        const unsigned char *p = (const unsigned char*)(uintptr_t)start;
                        for (int i = 0; i < BYTES*2; i++) {
                            kprintf("%02x ", (unsigned int)p[i]);
                            if ((i & 0xF) == 0xF) kprintf("\n");
                        }
                        kprintf("\n");
                    } else {
                        kprintf("user code dump skipped (out of identity range)\n");
                    }
                }
                for(;;){ asm volatile("sti; hlt" ::: "memory"); }
        }
        // Иначе — ядро: печатаем и стоп
        dump("invalid opcode", "kernel", regs, 0, 0, false);
        /* Dump nearby kernel code bytes and kernel syscall stack top to diagnose why UD happened */
        {
            uintptr_t rip = (uintptr_t)regs->rip;
            const int BYTES = 32;
            uintptr_t start = rip > BYTES ? rip - BYTES : rip;
            if (start + BYTES*2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                qemu_debug_printf("kernel code dump around RIP=0x%llx:\n", (unsigned long long)rip);
                const unsigned char *p = (const unsigned char*)(uintptr_t)start;
                for (int i = 0; i < BYTES*2; i++) {
                        qemu_debug_printf("%02x ", (unsigned int)p[i]);
                    if ((i & 0xF) == 0xF) kprintf("\n");
                }
                qemu_debug_printf("\n");
            } else {
                qemu_debug_printf("kernel code dump skipped (out of identity range)\n");
            }
        }
        {
            extern uint64_t syscall_kernel_rsp0;
            if ((uintptr_t)syscall_kernel_rsp0 != 0 && (uintptr_t)syscall_kernel_rsp0 + 8*16 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                qemu_debug_printf("syscall_kernel_rsp0=0x%llx\n", (unsigned long long)syscall_kernel_rsp0);
                uint64_t *stk = (uint64_t*)(uintptr_t)syscall_kernel_rsp0;
                qemu_debug_printf("kernel syscall stack top qwords:\n");
                for (int i = 0; i < 16; i++) {
                        qemu_debug_printf("[%2d] 0x%016llx\n", i, (unsigned long long)stk[i]);
                }
                qemu_debug_printf("saved RIP slot (offset +104) = 0x%016llx\n", (unsigned long long)stk[13]);
            } else {
                qemu_debug_printf("syscall_kernel_rsp0 not set or out of range\n");
            }
        }
        for(;;){ asm volatile("sti; hlt":::"memory"); }
}

// Handle Divide-by-zero (INT 0). For user faults: kill process and return to idle;
// for kernel faults: print diagnostics and halt.
static void div_zero_handler(cpu_registers_t* regs) {
        qemu_debug_printf("[div0] divide by zero at RIP=0x%llx err=0x%llx\n", (unsigned long long)regs->rip, (unsigned long long)regs->error_code);
        // If fault originated from user mode, terminate the user process safely
        if ((regs->cs & 3) == 3) {
                dump("divide by zero", "user", regs, 0, regs->error_code, true);
                // leave CPU in idle loop to avoid returning into faulty user code
                for(;;){ asm volatile("sti; hlt" ::: "memory"); }
        }
        // Kernel fault: print and halt
        dump("divide by zero", "kernel", regs, 0, regs->error_code, false);
        for(;;){ asm volatile("sti; hlt" ::: "memory"); }
}

static void page_fault_handler(cpu_registers_t* regs) {
        uint64_t cr2;
        asm volatile("mov %%cr2, %0" : "=r"(cr2));
        int user = (regs->cs & 3) == 3;
        dump("page fault", user ? "user" : "kernel", regs, cr2, regs->error_code, user);
        // Read MSR_FS_BASE to help diagnose faults caused by missing TLS base
        uint64_t fsbase_lo = 0, fsbase_hi = 0;
        asm volatile("rdmsr" : "=a"(fsbase_lo), "=d"(fsbase_hi) : "c"(0xC0000100u));
        uint64_t fsbase = ((uint64_t)fsbase_hi << 32) | fsbase_lo;
        kprintf("page fault MSR_FS_BASE=0x%016llx\n", (unsigned long long)fsbase);
        kprintf("page fault details: CR2=0x%llx err=0x%llx user=%d\n", (unsigned long long)cr2, (unsigned long long)regs->error_code, user);
        for (;;) { asm volatile("sti; hlt" ::: "memory"); }
}

static void gp_fault_handler(cpu_registers_t* regs){
    // Никакого рендера/свапа из обработчика GP
    // Строгая семантика для POSIX-подобного поведения: никаких эмуляций в ring3.
    // General Protection Fault в пользовательском процессе рассматривается как фатальная ошибка процесса.
    if ((regs->cs & 3) == 3) {
        kprintf("<(0c)>\nGPF (user-mode) trap.\n");
        kprintf("RIP: 0x%016llx\n", (unsigned long long)regs->rip);
        kprintf("RSP: 0x%016llx\n", (unsigned long long)regs->rsp);
        kprintf("RBP: 0x%016llx\n", (unsigned long long)regs->rbp);
        kprintf("RDI: 0x%016llx\n", (unsigned long long)regs->rdi);
        kprintf("RSI: 0x%016llx\n", (unsigned long long)regs->rsi);
        kprintf("RDX: 0x%016llx\n", (unsigned long long)regs->rdx);
        kprintf("RCX: 0x%016llx\n", (unsigned long long)regs->rcx);
        kprintf("RBX: 0x%016llx\n", (unsigned long long)regs->rbx);
        kprintf("RAX: 0x%016llx\n", (unsigned long long)regs->rax);
        kprintf("ERR: 0x%016llx  RFLAGS: 0x%016llx  CS: 0x%04x  SS: 0x%04x\n",
                (unsigned long long)regs->error_code, (unsigned long long)regs->rflags,
                (uint16_t)(regs->cs & 0xFFFF), (uint16_t)(regs->ss & 0xFFFF));
        uint64_t cr2 = 0, cr3 = 0;
        asm volatile("mov %%cr2, %0" : "=r"(cr2));
        asm volatile("mov %%cr3, %0" : "=r"(cr3));
        kprintf("CR2=0x%016llx CR3=0x%016llx\n", (unsigned long long)cr2, (unsigned long long)cr3);

        /* Attempt to dump a few instruction bytes at RIP (if in identity region) */
        if ((uintptr_t)regs->rip < (uintptr_t)0x100000000ULL) {
            const uint8_t *code = (const uint8_t*)(uintptr_t)regs->rip;
            kprintf("code @ RIP: ");
            for (int i = 0; i < 16; i++) kprintf("%02x ", (unsigned)code[i]);
            kprintf("\n");
        } else {
            kprintf("code @ RIP: (outside identity map)\n");
        }

        /* Dump few stack words */
        if ((uintptr_t)regs->rsp < (uintptr_t)0x100000000ULL) {
            const uint64_t *stk = (const uint64_t*)(uintptr_t)regs->rsp;
            kprintf("stack @ RSP: ");
            for (int i = 0; i < 8; i++) kprintf("0x%016llx ", (unsigned long long)stk[i]);
            kprintf("\n");
        } else {
            kprintf("stack @ RSP: (outside identity map)\n");
        }

        kprintf("GPF: terminating user thread and returning to shell\n");
        /* terminate current user thread safely and return to ring0 shell */
        extern void syscall_return_to_shell(void);
        syscall_return_to_shell();
    }
    // kernel GP — стоп, но оставляем PIT активным для мигания курсора
    (void)regs;
    for(;;){ asm volatile("sti; hlt" ::: "memory"); }
}

static void df_fault_handler(cpu_registers_t* regs){
        // Double Fault (#DF) — используем отдельный IST стек, чтобы избежать triple fault
        kprint("DOUBLE FAULT\n");
        dump("double fault", "kernel", regs, 0, regs->error_code, false);
        // Застываем в безопасной петле с включёнными прерываниями
        for(;;){ asm volatile("sti; hlt" ::: "memory"); }
}

void isr_dispatch(cpu_registers_t* regs) {
        uint8_t vec = (uint8_t)regs->interrupt_number;

        // Если пришёл IRQ1 (клавиатура) — гарантируем EOI даже при отсутствии обработчика
        if (vec == 33) {
                if (isr_handlers[vec]) {
                        isr_handlers[vec](regs);
                }
                pic_send_eoi(1);
                return;
        }

        // IRQ 32..47: EOI required
        if (vec >= 32 && vec <= 47) {
                if (isr_handlers[vec]) {
                        isr_handlers[vec](regs);
                } else {
                        qemu_debug_printf("Unhandled IRQ %d\n", vec - 32);
                }
                pic_send_eoi(vec - 32);
                return;
                }
                
        // Any other vector: call registered handler if present (e.g., int 0x80)
        if (isr_handlers[vec]) {
                isr_handlers[vec](regs);
                return;
        }
        
        // Exceptions 0..31 without specific handler: print and halt
        if (vec < 32) {
                for (;;);
        }
        
        // Unknown vector
        qemu_debug_printf("Unknown interrupt %d (0x%x)\n", vec, vec);
        qemu_debug_printf("RIP: 0x%x, RSP: 0x%x\n", regs->rip, regs->rsp);
        for (;;);
        // no swap in VGA text mode
        for (;;);
}

void idt_set_gate(uint8_t num, uint64_t handler, uint16_t selector, uint8_t flags) {
        idt[num].offset_low = handler & 0xFFFF;
        idt[num].offset_mid = (handler >> 16) & 0xFFFF;
        idt[num].offset_high = (handler >> 32) & 0xFFFFFFFF;
        idt[num].selector = selector;
        idt[num].ist = 0;
        idt[num].flags = flags;
        idt[num].reserved = 0;
}

void idt_set_handler(uint8_t num, void (*handler)(cpu_registers_t*)) {
        isr_handlers[num] = handler;
}

void idt_init() {
        idt_ptr.limit = sizeof(idt) - 1;
        idt_ptr.base = (uint64_t)&idt;
        
        for (int i = 0; i < 256; i++) {
                idt_set_gate(i, isr_stub_table[i], 0x08, 0x8E);
        }
        
        // Register detailed page fault handler
        idt_set_handler(14, page_fault_handler);
        // Register divide-by-zero handler (#0)
        idt_set_handler(0, div_zero_handler);
        // Register UD handler (#6)
        idt_set_handler(6, ud_fault_handler);
        // Register GP fault handler (#13)
        idt_set_handler(13, gp_fault_handler);
        // Register DF handler (#8) and put it on IST1
        idt_set_handler(8, df_fault_handler);
        // Пометим IST=1 у вектора 8
        idt[8].ist = 1;
        
        // Register RTC handler (IRQ 8 = vector 40)
        idt_set_handler(40, rtc_handler);

        idt_set_handler(APIC_TIMER_VECTOR, apic_timer_handler);
        
        asm volatile("lidt %0" : : "m"(idt_ptr));
}