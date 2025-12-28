#include <axonos.h>
#include <keyboard.h>
#include <stdint.h>
#include <gdt.h>
#include <string.h>
#include <vga.h>
#include <idt.h>
#include <pic.h>
#include <pit.h>
#include <rtc.h>
#include <heap.h>
#include <paging.h>
#include <sysinfo.h>
#include <thread.h>
#include <axosh.h>
#include <apic.h>
#include <apic_timer.h>
#include <stat.h>
#include <syscall.h>
#include <iothread.h>
#include <fs.h>
#include <ext2.h>
#include <ramfs.h>
#include <sysfs.h>
#include <procfs.h>
#include <initfs.h>
#include <editor.h>
#include <fat32.h>
#include <intel_chipset.h>
#include <disk.h>
#include <mmio.h>
#include <pci.h>
#include <devfs.h>
#include <user.h>
#include <serial.h>
#include <exec.h>
#include <klog.h>

/* ====== FIRMWARE AND CPU DETECTION ====== */

#define FIRMWARE_BIOS   0
#define FIRMWARE_UEFI   1
#define FIRMWARE_UNKNOWN 2

struct cpu_regs {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

struct cpu_info {
    char vendor[13];
    char brand[49];
    uint32_t family;
    uint32_t model;
    uint32_t stepping;
    uint8_t apic_id;
    uint32_t features_ecx;
    uint32_t features_edx;
};

// Глобальные переменные
static int g_firmware_type = FIRMWARE_UNKNOWN;
static struct cpu_info g_cpu_info = {0};

static inline void cpuid(uint32_t code, struct cpu_regs *regs) {
    asm volatile("cpuid"
        : "=a"(regs->eax), "=b"(regs->ebx), "=c"(regs->ecx), "=d"(regs->edx)
        : "a"(code));
}

static int detect_firmware_type(uint32_t multiboot_magic, uint64_t multiboot_info) {
    // 1. Multiboot2 EFI tag
    if (multiboot_magic == 0x36d76289u && multiboot_info != 0) {
        uint8_t *p = (uint8_t*)(uintptr_t)multiboot_info;
        uint32_t total_size = *(uint32_t*)p;
        uint32_t off = 8;
        
        while (off + 8 <= total_size) {
            uint32_t type = *(uint32_t*)(p + off);
            uint32_t size = *(uint32_t*)(p + off + 4);
            
            if (type == 0) break;
            if (size < 8) break;
            
            if (type == 14) { // EFI system table
                return FIRMWARE_UEFI;
            }
            off += (size + 7) & ~7u;
        }
    }
    
    // 2. Check ACPI RSDP
    for (uintptr_t addr = 0xE0000; addr < 0x100000; addr += 16) {
        if (*(uint64_t*)addr == 0x2052545020445352) { // "RSD PTR "
            uint8_t sum = 0;
            for (int i = 0; i < 20; i++) sum += ((uint8_t*)addr)[i];
            if (sum == 0) {
                uint64_t xsdt_addr = *(uint64_t*)(addr + 24);
                if (xsdt_addr != 0) {
                    return FIRMWARE_UEFI;
                }
            }
        }
    }
    
    // 3. Check EBDA
    uint16_t ebda_seg = *(uint16_t*)0x40E;
    if (ebda_seg != 0) {
        uintptr_t ebda_addr = (uintptr_t)ebda_seg << 4;
        if (ebda_addr >= 0x80000 && ebda_addr < 0xA0000) {
            return FIRMWARE_BIOS;
        }
    }
    
    return FIRMWARE_BIOS; // Assume BIOS if not detected
}

static void detect_cpu(void) {
    struct cpu_regs regs;
    
    // Get vendor string
    cpuid(0, &regs);
    uint32_t max_cpuid = regs.eax;
    
    // Copy vendor string
    *(uint32_t*)(g_cpu_info.vendor) = regs.ebx;
    *(uint32_t*)(g_cpu_info.vendor + 4) = regs.edx;
    *(uint32_t*)(g_cpu_info.vendor + 8) = regs.ecx;
    g_cpu_info.vendor[12] = 0;
    
    // Get processor info
    if (max_cpuid >= 1) {
        cpuid(1, &regs);
        
        g_cpu_info.stepping = regs.eax & 0xF;
        g_cpu_info.model = (regs.eax >> 4) & 0xF;
        g_cpu_info.family = (regs.eax >> 8) & 0xF;
        
        // Extended family/model
        if (g_cpu_info.family == 0xF) {
            g_cpu_info.family += (regs.eax >> 20) & 0xFF;
            g_cpu_info.model |= ((regs.eax >> 16) & 0xF) << 4;
        }
        
        g_cpu_info.apic_id = (regs.ebx >> 24) & 0xFF;
        g_cpu_info.features_ecx = regs.ecx;
        g_cpu_info.features_edx = regs.edx;
    }
    
    // Get brand string if supported
    cpuid(0x80000000, &regs);
    if (regs.eax >= 0x80000004) {
        uint32_t brand[12];
        
        cpuid(0x80000002, &regs);
        brand[0] = regs.eax; brand[1] = regs.ebx;
        brand[2] = regs.ecx; brand[3] = regs.edx;
        
        cpuid(0x80000003, &regs);
        brand[4] = regs.eax; brand[5] = regs.ebx;
        brand[6] = regs.ecx; brand[7] = regs.edx;
        
        cpuid(0x80000004, &regs);
        brand[8] = regs.eax; brand[9] = regs.ebx;
        brand[10] = regs.ecx; brand[11] = regs.edx;
        
        memcpy(g_cpu_info.brand, brand, 48);
        g_cpu_info.brand[48] = 0;
        
        // Trim trailing spaces
        for (int i = 47; i >= 0; i--) {
            if (g_cpu_info.brand[i] == ' ') {
                g_cpu_info.brand[i] = 0;
            } else if (g_cpu_info.brand[i] != 0) {
                break;
            }
        }
    } else {
        strcpy(g_cpu_info.brand, g_cpu_info.vendor);
    }
}

/* ATA DMA driver init (registered here) */
void ata_dma_init(void);

int exit = 0;

static char g_cwd[256] = "/";

extern uint8_t _end[]; /* kernel end symbol from linker */

static inline uintptr_t align_up_uintptr(uintptr_t v, uintptr_t a) {
    return (v + (a - 1)) & ~(a - 1);
}

/* Multiboot2: find the maximum module end address. This is critical to place
   the kernel heap ABOVE modules; otherwise heap headers can overwrite initfs
   (this is exactly what happens on VMware in your log). */
static uintptr_t mb2_modules_max_end(uint32_t multiboot_magic, uint64_t multiboot_info) {
    if (multiboot_magic != 0x36d76289u || multiboot_info == 0) return 0;
    uint8_t *p = (uint8_t*)(uintptr_t)multiboot_info;
    uint32_t total_size = *(uint32_t*)p;
    if (total_size < 16 || total_size > (64u * 1024u * 1024u)) return 0;

    uint32_t off = 8;
    uintptr_t max_end = 0;
    while (off + 8 <= total_size) {
        uint32_t type = *(uint32_t*)(p + off);
        uint32_t size = *(uint32_t*)(p + off + 4);
        if (size < 8) break;
        if ((uint64_t)off + (uint64_t)size > (uint64_t)total_size) break;
        if (type == 0) break;
        if (type == 3 && size >= 16) { /* module */
            const uint8_t *fp = p + off + 8;
            uint32_t mod_end = *(uint32_t*)(fp + 4);
            if ((uintptr_t)mod_end > max_end) max_end = (uintptr_t)mod_end;
        }
        off += (size + 7) & ~7u;
    }
    return max_end;
}

static ssize_t sysfs_show_const(char *buf, size_t size, void *priv) {
    if (!buf || size == 0) return 0;
    const char *text = (const char*)priv;
    if (!text) text = "";
    size_t len = strlen(text);
    if (len > size) len = size;
    memcpy(buf, text, len);
    if (len < size) buf[len++] = '\n';
    return (ssize_t)len;
}

static ssize_t sysfs_show_cpu_name_attr(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    const char *name = sysinfo_cpu_name();
    size_t len = strlen(name);
    if (len > size) len = size;
    memcpy(buf, name, len);
    if (len < size) buf[len++] = '\n';
    return (ssize_t)len;
}

static size_t sysfs_write_int(char *buf, size_t size, int value) {
    if (!buf || size == 0) return 0;
    char tmp[32];
    size_t n = 0;
    unsigned int v;
    int neg = 0;
    if (value < 0) { neg = 1; v = (unsigned int)(-value); }
    else v = (unsigned int)value;
    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v && n < sizeof(tmp));
    if (neg && n < sizeof(tmp)) tmp[n++] = '-';
    size_t written = 0;
    while (n && written < size) {
        buf[written++] = tmp[--n];
    }
    return written;
}

static ssize_t sysfs_show_ram_mb_attr(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    int mb = sysinfo_ram_mb();
    if (mb < 0) {
        return sysfs_show_const(buf, size, (void*)"unknown");
    }
    size_t written = sysfs_write_int(buf, size, mb);
    if (written < size) buf[written++] = '\n';
    return (ssize_t)written;
}

void ring0_shell()  { osh_run(); }

/* ====== SYSFS ATTR FUNCTIONS ====== */

static ssize_t sysfs_show_cpu_vendor(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    size_t len = strlen(g_cpu_info.vendor);
    if (len > size) len = size;
    memcpy(buf, g_cpu_info.vendor, len);
    if (len < size) buf[len++] = '\n';
    return (ssize_t)len;
}

static ssize_t sysfs_show_cpu_brand(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    size_t len = strlen(g_cpu_info.brand);
    if (len > size) len = size;
    memcpy(buf, g_cpu_info.brand, len);
    if (len < size) buf[len++] = '\n';
    return (ssize_t)len;
}

static ssize_t sysfs_show_cpu_family(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    char tmp[32];
    size_t n = 0;
    uint32_t v = g_cpu_info.family;
    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v && n < sizeof(tmp));
    size_t written = 0;
    while (n && written < size) {
        buf[written++] = tmp[--n];
    }
    if (written < size) buf[written++] = '\n';
    return (ssize_t)written;
}

static ssize_t sysfs_show_cpu_model(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    char tmp[32];
    size_t n = 0;
    uint32_t v = g_cpu_info.model;
    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v && n < sizeof(tmp));
    size_t written = 0;
    while (n && written < size) {
        buf[written++] = tmp[--n];
    }
    if (written < size) buf[written++] = '\n';
    return (ssize_t)written;
}

static ssize_t sysfs_show_cpu_stepping(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    char tmp[32];
    size_t n = 0;
    uint32_t v = g_cpu_info.stepping;
    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v && n < sizeof(tmp));
    size_t written = 0;
    while (n && written < size) {
        buf[written++] = tmp[--n];
    }
    if (written < size) buf[written++] = '\n';
    return (ssize_t)written;
}

static ssize_t sysfs_show_firmware_type(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    const char *type;
    switch (g_firmware_type) {
        case FIRMWARE_BIOS: type = "BIOS"; break;
        case FIRMWARE_UEFI: type = "UEFI"; break;
        default: type = "Unknown"; break;
    }
    size_t len = strlen(type);
    if (len > size) len = size;
    memcpy(buf, type, len);
    if (len < size) buf[len++] = '\n';
    return (ssize_t)len;
}

static ssize_t sysfs_show_cpuinfo_full(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    
    char tmp[512];
    const char *fw_type;
    switch (g_firmware_type) {
        case FIRMWARE_BIOS: fw_type = "BIOS"; break;
        case FIRMWARE_UEFI: fw_type = "UEFI"; break;
        default: fw_type = "Unknown"; break;
    }
    
    int len = snprintf(tmp, sizeof(tmp),
        "processor\t: 0\n"
        "vendor_id\t: %s\n"
        "cpu family\t: %u\n"
        "model\t\t: %u\n"
        "stepping\t: %u\n"
        "apicid\t\t: %u\n"
        "firmware\t: %s\n"
        "flags\t\t: ",
        g_cpu_info.vendor,
        g_cpu_info.family,
        g_cpu_info.model,
        g_cpu_info.stepping,
        g_cpu_info.apic_id,
        fw_type);
    
    // Add CPU features
    if (g_cpu_info.features_edx & (1 << 23)) len += snprintf(tmp + len, sizeof(tmp) - len, "mmx ");
    if (g_cpu_info.features_edx & (1 << 25)) len += snprintf(tmp + len, sizeof(tmp) - len, "sse ");
    if (g_cpu_info.features_edx & (1 << 26)) len += snprintf(tmp + len, sizeof(tmp) - len, "sse2 ");
    if (g_cpu_info.features_edx & (1 << 28)) len += snprintf(tmp + len, sizeof(tmp) - len, "ht ");
    if (g_cpu_info.features_ecx & (1 << 0)) len += snprintf(tmp + len, sizeof(tmp) - len, "sse3 ");
    if (g_cpu_info.features_ecx & (1 << 9)) len += snprintf(tmp + len, sizeof(tmp) - len, "ssse3 ");
    if (g_cpu_info.features_ecx & (1 << 19)) len += snprintf(tmp + len, sizeof(tmp) - len, "sse4.1 ");
    if (g_cpu_info.features_ecx & (1 << 20)) len += snprintf(tmp + len, sizeof(tmp) - len, "sse4.2 ");
    if (g_cpu_info.features_ecx & (1 << 25)) len += snprintf(tmp + len, sizeof(tmp) - len, "aes ");
    
    len += snprintf(tmp + len, sizeof(tmp) - len, "\n\n");
    
    size_t to_copy = len;
    if (to_copy > size) to_copy = size;
    memcpy(buf, tmp, to_copy);
    return (ssize_t)to_copy;
}

void kernel_main(uint32_t multiboot_magic, uint64_t multiboot_info) {
    kclear();
    enable_cursor();
    kprint("Initializing kernel...\n");
    sysinfo_init(multiboot_magic, multiboot_info);
    /* ====== DETECT FIRMWARE AND CPU ====== */
    g_firmware_type = detect_firmware_type(multiboot_magic, multiboot_info);
    detect_cpu();
    
    // Print to console
    kprintf("firmware: %s\n", 
        g_firmware_type == FIRMWARE_BIOS ? "BIOS" : 
        g_firmware_type == FIRMWARE_UEFI ? "UEFI" : "Unknown");
    kprintf("CPU vendor: %s\n", g_cpu_info.vendor);
    kprintf("CPU: %s\n", g_cpu_info.brand);
    kprintf("CPU family: %u, model: %u, stepping: %u\n", 
           g_cpu_info.family, g_cpu_info.model, g_cpu_info.stepping);
    kprintf("APIC ID: %u\n", g_cpu_info.apic_id);
    /* ====== END DETECTION ====== */
    /* Initialize heap EARLY and place it above kernel + multiboot modules.
       Otherwise heap metadata can overwrite initfs module (seen on VMware). */
    {
        uintptr_t heap_start = align_up_uintptr((uintptr_t)_end, 0x1000);
        uintptr_t mods_end = mb2_modules_max_end(multiboot_magic, multiboot_info);
        if (mods_end) {
            uintptr_t mods_end_aligned = align_up_uintptr(mods_end, 0x1000);
            if (mods_end_aligned > heap_start) heap_start = mods_end_aligned;
        }
        /* 
           IMPORTANT:
           User ELF binaries are currently loaded by copying PT_LOAD segments into their p_vaddr
           in the identity-mapped region. Typical ELF64 ET_EXEC uses 0x00400000.. (4MiB+).
           If the kernel heap also lives in low memory, exec will literally overwrite heap blocks
           (we already observed this as a heap canary overflow during `exec /bin/busybox`).
           Keep heap above a safe floor to avoid collisions with user image mappings. 
        */
        const uintptr_t HEAP_MIN_START = (uintptr_t)(64u * 1024u * 1024u); /* 64 MiB */
        if (heap_start < HEAP_MIN_START) heap_start = HEAP_MIN_START;
        heap_init(heap_start, 0);
        kprintf("kernel: heap_start=%p kernel_end=%p mods_end=%p\n",
                (void*)heap_start, (void*)(uintptr_t)_end, (void*)mods_end);
    }

    gdt_init();
    /* allocate IST1 stack for Double Fault handler to avoid triple-faults */
    {
        void *df_stack = kmalloc(8192 + 16);
        if (df_stack) {
            uint64_t df_top = (uint64_t)df_stack + 8192 + 16;
            tss_set_ist(1, df_top);
            kprintf("kernel: set DF IST1 stack at %p\n", (void*)(uintptr_t)df_top);
        } else {
            kprintf("kernel: WARNING: failed to allocate DF IST stack\n");
        }
    }
    idt_init();
    pic_init();
    pit_init();
    
    mmio_init();
    
    ramfs_register();
    ext2_register();

    if (sysfs_register() == 0) {
        kprintf("sysfs: mounting sysfs in /sys\n");
        ramfs_mkdir("/sys");
        sysfs_mkdir("/sys");
        sysfs_mkdir("/sys/kernel");
        sysfs_mkdir("/sys/kernel/cpu");
        sysfs_mkdir("/sys/class");
        sysfs_mkdir("/sys/class/input");
        sysfs_mkdir("/sys/class/tty");
        sysfs_mkdir("/sys/class/block");
        sysfs_mkdir("/sys/class/net");
        sysfs_mkdir("/sys/bus");
        sysfs_mkdir("/sys/bus/pci");
        sysfs_mkdir("/sys/bus/pci/devices");
        sysfs_mkdir("/sys/class");
        sysfs_mkdir("/sys/class/input");
        sysfs_mkdir("/sys/class/tty");
        sysfs_mkdir("/sys/class/block");
        sysfs_mkdir("/sys/class/net");
        struct sysfs_attr attr_os_name = { sysfs_show_const, NULL, (void*)OS_NAME };
        struct sysfs_attr attr_os_version = { sysfs_show_const, NULL, (void*)OS_VERSION };
        struct sysfs_attr attr_cpu_name = { sysfs_show_cpu_name_attr, NULL, NULL };
        struct sysfs_attr attr_ram_mb = { sysfs_show_ram_mb_attr, NULL, NULL };
        sysfs_create_file("/sys/kernel/sysname", &attr_os_name);
        sysfs_create_file("/sys/kernel/sysver", &attr_os_version);
        sysfs_create_file("/sys/kernel/cpu/name", &attr_cpu_name);
        sysfs_create_file("/sys/kernel/ram", &attr_ram_mb);
        sysfs_mount("/sys");
        /* ====== CPU AND FIRMWARE INFO FILES ====== */
        struct sysfs_attr attr_cpu_vendor = { sysfs_show_cpu_vendor, NULL, NULL };
        struct sysfs_attr attr_cpu_brand = { sysfs_show_cpu_brand, NULL, NULL };
        struct sysfs_attr attr_cpu_family = { sysfs_show_cpu_family, NULL, NULL };
        struct sysfs_attr attr_cpu_model = { sysfs_show_cpu_model, NULL, NULL };
        struct sysfs_attr attr_cpu_stepping = { sysfs_show_cpu_stepping, NULL, NULL };
        struct sysfs_attr attr_firmware_type = { sysfs_show_firmware_type, NULL, NULL };
        struct sysfs_attr attr_cpuinfo_full = { sysfs_show_cpuinfo_full, NULL, NULL };
        
        sysfs_create_file("/sys/kernel/cpu/vendor", &attr_cpu_vendor);
        sysfs_create_file("/sys/kernel/cpu/brand", &attr_cpu_brand);
        sysfs_create_file("/sys/kernel/cpu/family", &attr_cpu_family);
        sysfs_create_file("/sys/kernel/cpu/model", &attr_cpu_model);
        sysfs_create_file("/sys/kernel/cpu/stepping", &attr_cpu_stepping);
        sysfs_create_file("/sys/kernel/firmware_type", &attr_firmware_type);
        sysfs_create_file("/sys/kernel/cpuinfo", &attr_cpuinfo_full);
        /* ====== END CPU INFO ====== */

        
        /* create /etc and write initial passwd/group files into ramfs */
        ramfs_mkdir("/etc");
        {
            char *buf = NULL; size_t bl = 0;
            if (user_export_passwd(&buf, &bl) == 0 && buf) {
                struct fs_file *f = fs_create_file("/etc/passwd");
                if (f) {
                    fs_write(f, buf, bl, 0);
                    fs_file_free(f);
                }
                kfree(buf);
            }
            /* simple /etc/group with only root group initially */
            const char *gline = "root:x:0:root\n";
            struct fs_file *g = fs_create_file("/etc/group");
            if (g) {
                fs_write(g, gline, strlen(gline), 0);
                fs_file_free(g);
            }
        }
    } else {
        kprintf("sysfs: failed to register\n");
    }
    klog_init();
    
    apic_init();
    apic_timer_init();
    idt_set_handler(APIC_TIMER_VECTOR, apic_timer_handler);
    /* syscall (int 0x80) initialization */
    syscall_init();
    
    paging_init();

    // Включаем прерывания
    asm volatile("sti");

    apic_timer_start(100);

    for (int i = 0; i < 50; i++) {
        pit_sleep_ms(10);
        if (apic_timer_ticks > 0) break;
    }
    if (apic_timer_ticks > 0) {
        apic_timer_stop();
        pit_disable();
        pic_mask_irq(0);
        apic_timer_start(1000);
    } else {
        kprintf("APIC: using PIT\n");
        apic_timer_stop();
    }

    /* Calibrate TSC for high-resolution timestamps now that APIC timer is running */
    klog_calibrate_tsc();

    pci_init();
    pci_dump_devices();
    pci_sysfs_init();
    intel_chipset_init();
    /* start threading and I/O subsystem, then initialize disk drivers from a kernel thread
       to avoid probing hardware too early during boot. */
    thread_init();
    iothread_init();
    /* create kernel thread to initialize ATA/SATA drivers after scheduler is ready */
    if (!thread_create(ata_dma_init, "ata_init")) {
        kprintf("ata: failed to create init thread\n");
    }
    
    /* user subsystem */
    user_init();
    fat32_register();

    
    /* If an initfs module was provided by the bootloader, unpack it into ramfs */
    {
        int r = initfs_process_multiboot_module(multiboot_magic, multiboot_info, "initfs");
        if (r == 0) klogprintf("initfs: unpacked successfully\n");
        else klogprintf("initfs: error: failed, code: %d\n", r);
    }
    /* register and mount devfs at /dev */
    if (devfs_register() == 0) {
        klogprintf("devfs: registering devfs\n");
        ramfs_mkdir("/dev");
        devfs_mount("/dev");
        /* initialize stdio fds for current thread (main) */
        struct fs_file *console = fs_open("/dev/console");
        if (console) {
            /* allocate fd slots for main thread using helper to manage refcounts */
            int fd0 = thread_fd_alloc(console);
            if (fd0 >= 0) {
                /* ensure we have fd 0..2 set; if not, duplicate */
                thread_t* t = thread_current();
                if (t) {
                    if (fd0 != 0) { /* move to 0 */
                        if (t->fds[0]) fs_file_free(t->fds[0]);
                        t->fds[0] = t->fds[fd0];
                        t->fds[fd0] = NULL;
                    }
                    if (!t->fds[1]) { t->fds[1] = t->fds[0]; if (t->fds[1]) t->fds[1]->refcount++; }
                    if (!t->fds[2]) { t->fds[2] = t->fds[0]; if (t->fds[2]) t->fds[2]->refcount++; }
                }
            } else {
                fs_file_free(console);
            }
        }
    } else {
        klogprintf("devfs: failed to register\n");
    }

    /* register and mount procfs at /proc */
    if (procfs_register() == 0) {
        klogprintf("procfs: mounting procfs in /proc\n");
        ramfs_mkdir("/proc");
        procfs_mount("/proc");
    } else {
        klogprintf("procfs: error: failed to register\n");
    }

    ps2_keyboard_init();
    rtc_init();
    
    //autostart: run /start script once if present
    // {
    //     struct fs_file *f = fs_open("/start");
    //     if (f) { fs_file_free(f); (void)exec_line("osh /start"); }
    //     else { kprintf("FATAL: /start file not found; fallback to osh\n"); exec_line("PS1=\"\\w # \""); exec_line("osh"); }
    // }

    {
        /* Try standard init paths in order. Use kernel_execve_from_path to directly
           transfer to user init; if it returns, the exec failed and we try next. */
        const char *inits[] = { "/sbin/init",  NULL };
        for (int i = 0; inits[i]; i++) {
            const char *path = inits[i];
            struct fs_file *f = fs_open(path);
            if (!f) continue;
            fs_file_free(f);
            if (strcmp(path, "/bin/busybox") == 0) {
                /* busybox invoked with 'init' arg */
                const char *kargv[] = { "/bin/busybox", "init", NULL };
                kprintf("execve: launching %s %s\n", kargv[0], kargv[1]);
                (void)kernel_execve_from_path(kargv[0], kargv, NULL);
            } else {
                const char *kargv[] = { path, NULL };
                kprintf("execve: launching %s\n", path);
                (void)kernel_execve_from_path(path, kargv, NULL);
            }
            /* If we get here, exec failed; try next candidate */
            kprintf("execve: %s failed, trying next\n", path);
        }
        kprintf("fatal: unable to run initial process; falling back to osh\n");
        exec_line("PS1=\"osh-2.0# \"");
        exec_line("osh");
    }
    
    for(;;) {
        asm volatile("hlt");
    }
}