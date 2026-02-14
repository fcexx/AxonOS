/*
 * core/entry/kernel.c
 * Kernel entry point implementation
 * Author: fcexx
*/

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
#include <ramfs.h>
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
#include <vbe.h>
void ata_dma_init(void);

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

    /* Allow larger multiboot info blocks (some bootloaders/VMs may pass large
       tag regions when modules are large). Increase cap to 256 MiB. */
    if (total_size < 16 || total_size > (256u * 1024u * 1024u)) return 0;

    uint32_t off = 8;
    uintptr_t max_end = 0;

    while (off + 8 <= total_size) {
        uint32_t type = *(uint32_t*)(p + off);
        uint32_t size = *(uint32_t*)(p + off + 4);

        if (size < 8) break;
        if ((uint64_t)off + (uint64_t)size > (uint64_t)total_size) break;
        if (type == 0) break;

        if (type == 3 && size >= 16) { /* its a module */
            const uint8_t *fp = p + off + 8;
            uint32_t mod_end = *(uint32_t*)(fp + 4);
            if ((uintptr_t)mod_end > max_end) max_end = (uintptr_t)mod_end;
        }
        off += (size + 7) & ~7u;
    }
    return max_end;
}

ssize_t sysfs_show_const(char *buf, size_t size, void *priv) {
    if (!buf || size == 0) return 0;

    const char *text = (const char*)priv;
    if (!text) text = "";
    size_t len = strlen(text);
    if (len > size) len = size;
    memcpy(buf, text, len);
    if (len < size) buf[len++] = '\n';

    return (ssize_t)len;
}

ssize_t sysfs_show_cpu_name_attr(char *buf, size_t size, void *priv) {
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

ssize_t sysfs_show_ram_mb_attr(char *buf, size_t size, void *priv) {
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

/* Populate default sysfs tree when userspace mounts sysfs via SYS_mount. */
void kernel_sysfs_populate_default(void) {
    sysfs_mkdir("/sys/kernel");
    sysfs_mkdir("/sys/class");
    sysfs_mkdir("/sys/bus");
    static const struct sysfs_attr attr_cpu = { sysfs_show_cpu_name_attr, NULL, NULL };
    static const struct sysfs_attr attr_ram = { sysfs_show_ram_mb_attr, NULL, NULL };
    sysfs_create_file("/sys/kernel/cpu_name", &attr_cpu);
    sysfs_create_file("/sys/kernel/ram_mb", &attr_ram);
}

static int boot_try_run_init(void) {
    /* initramfs-style init selection:
       prefer /linuxrc when present, then fall back to /init and classic paths. */
    static const char *candidates[] = {
        "/sbin/init",
        "/bin/init",
        NULL
    };
    for (int i = 0; candidates[i]; i++) {
        const char *p = candidates[i];
        struct stat st;
        if (vfs_stat(p, &st) != 0) continue;
        /* Accept regular files and symlinks (symlinks already resolved by exec). */
        if (!((st.st_mode & S_IFREG) == S_IFREG || (st.st_mode & S_IFLNK) == S_IFLNK)) continue;
        const char *argv0[2] = { p, NULL };
        klogprintf("boot: starting init candidate %s\n", p);
        int rc = kernel_execve_from_path(p, argv0, NULL);
        if (rc == 0) return 0;
        klogprintf("boot: init %s returned rc=%d\n", p, rc);

    }
    return -1;
}

void kernel_main(uint32_t multiboot_magic, uint64_t multiboot_info) {
    qemu_debug_printf("Kernel started\n");
    kclear();
    enable_cursor();
    sysinfo_init(multiboot_magic, multiboot_info);

    /* Initialize heap EARLY and place it above kernel + multiboot modules.
       Otherwise heap metadata can overwrite initfs module (seen on VMware). */
    {
        uintptr_t heap_start = align_up_uintptr((uintptr_t)_end, 0x1000);
        uintptr_t mods_end = mb2_modules_max_end(multiboot_magic, multiboot_info);
        if (mods_end) {
            uintptr_t mods_end_aligned = align_up_uintptr(mods_end, 0x1000);
            if (mods_end_aligned > heap_start) heap_start = mods_end_aligned;
        }
        
        // DO NOT TOUCH
        const uintptr_t HEAP_MIN_START = (uintptr_t)(64u * 1024u * 1024u); /* 64 MiB minimal heap start */
        if (heap_start < HEAP_MIN_START) heap_start = HEAP_MIN_START;
        /* Heap size must not exceed installed RAM. The heap implementation is a
           simple identity-mapped arena; if we size it past RAM we will scribble
           into non-existent memory and get "random" initfs extraction failures
           that change with kernel size/timing. */
        size_t heap_size = 0; /* 0 => heap.c default, but we'll clamp below */
        int ram_mb = sysinfo_ram_mb();
        if (ram_mb > 0) {
            uint64_t ram_bytes = (uint64_t)ram_mb * 1024ULL * 1024ULL;
            uint64_t start = (uint64_t)heap_start;
            const uint64_t guard = 16ULL * 1024ULL * 1024ULL; /* leave some slack */
            if (ram_bytes > start + guard + (32ULL * 1024ULL * 1024ULL)) {
                uint64_t max = ram_bytes - start - guard;
                /* keep heap reasonably bounded even on big-RAM machines */
                const uint64_t cap = 512ULL * 1024ULL * 1024ULL;
                if (max > cap) max = cap;
                heap_size = (size_t)max;
            }
        }
        heap_init(heap_start, heap_size);
        kprintf("Loading kernel without compression: heap_start: %p heap_size=%llu heap_total=%llu heap_base=%p ram_mb=%d kernel_end: %p mods_end: %p\n",
                (void*)heap_start,
                (unsigned long long)heap_size,
                (unsigned long long)heap_total_bytes(),
                (void*)heap_base_addr(),
                sysinfo_ram_mb(),
                (void*)(uintptr_t)_end, (void*)mods_end);
    }

    gdt_init();

    /* allocate IST1 stack for Double Fault handler to avoid triple-faults.
       Use a larger (16KiB) stack and ensure 16-byte alignment of the top. */
    {
        const size_t DF_STACK_SIZE = 16 * 1024;
        void *df_stack = kmalloc(DF_STACK_SIZE + 16);
        if (df_stack) {
            uintptr_t top = (uintptr_t)df_stack + DF_STACK_SIZE + 16;
            uintptr_t df_top = align_up_uintptr(top, 16);
            tss_set_ist(1, (uint64_t)df_top);
            kprintf("Set kernel DF IST1 stack at %p.\n", (void*)(uintptr_t)df_top);
        } else {
            kprintf("Failed to allocate DF IST stack (warning)\n");
        }
    }
    int vbe_init = 0;
    /* Initialize VBE framebuffer console after heap is available */
    if (multiboot_info != 0) {
        if (vbe_init_from_multiboot(multiboot_magic, multiboot_info)) {
            if (vbe_is_available()) {
                uint32_t w = vbe_get_width();
                uint32_t h = vbe_get_height();
                uint32_t p = vbe_get_pitch();
                uint32_t b = vbe_get_bpp();
                if (vbefb_init(w, h, p, b) == 0) {
                    kprintf("vbe: framebuffer initialized %ux%u@%u\n", (unsigned)w, (unsigned)h, (unsigned)b);
                    vbe_init = 1;
                } else {
                    kprintf("vbe: framebuffer init failed\n");
                    vbe_init = 0;
                }
            }
        } else {
            kprintf("vbe: init_from_multiboot returned error\n");
            vbe_init = 0;
        }
    }

    idt_init();
    pic_init();
    pit_init();

    mmio_init();
    ramfs_register();
    /* Create /dev in ramfs before initfs so it is always visible in ls / and before getty runs */
    ext2_register();

    /* sysfs, procfs, devfs mount — only via SYS_mount from userspace (e.g. init) */

    klog_init(); // for logging into /var/log/kernel file
    sysinfo_print_e820(multiboot_magic, multiboot_info);
    if (vbe_is_available() == 1) klogprintf("Set VBE framebuffer mode: %ux%u@%u.\n", vbe_get_width(), vbe_get_height(), vbe_get_bpp());
    else klogprintf("Set VGA default 80x25 mode.\n");
    
    apic_init();
    apic_timer_init();
    idt_set_handler(APIC_TIMER_VECTOR, apic_timer_handler);

    syscall_init();/* syscall (int 0x80) initialization */
    
    paging_init();

    // Enabling interrupts
    asm volatile("sti");
    /* Recalibrate after STI when PIT ticks are guaranteed to progress. */
    apic_timer_calibrate();

    /* Enable APIC timer if it behaves sanely; otherwise keep PIT.
       Real hardware can hang or run at wildly wrong rate with bad APIC calibration. */
    apic_timer_start(100);
    {
        uint64_t apic_start = apic_timer_ticks;
        uint64_t pit_start = pit_get_ticks();
        while ((pit_get_ticks() - pit_start) < 200) {
            asm volatile("pause");
        }
        uint64_t apic_delta = apic_timer_ticks - apic_start;
        /* At 100 Hz over ~200 ms we expect around 20 ticks; allow wide tolerance. */
        int apic_ok = (apic_delta >= 5 && apic_delta <= 80);
        if (apic_ok) {
            apic_timer_stop();
            pit_disable();
            pic_mask_irq(0);
            apic_timer_start(1000);
            /* Confirm APIC is actually ticking at the new rate; otherwise revert to PIT. */
            uint64_t t0 = apic_timer_ticks;
            for (int i = 0; i < 1000000; i++) {
                if (apic_timer_ticks != t0) break;
                asm volatile("pause");
            }
            if (apic_timer_ticks == t0) {
                kprintf("APIC: no ticks after 1000Hz start, falling back to PIT\n");
                apic_timer_stop();
                pic_unmask_irq(0);
                pit_init();
            }
        } else {
            kprintf("APIC: unstable (%llu ticks/200ms), using PIT\n", (unsigned long long)apic_delta);
            apic_timer_stop();
        }
    }

    // Calibrate TSC for high resolution timestamps now that APIC timer is running
    // Otherwise, for microseconds.
    klog_calibrate_tsc();

    pci_init();
    pci_dump_devices();
    pci_sysfs_init();
    intel_chipset_init();

    // Scheduler and I/O scheduler
    thread_init();
    iothread_init();

    ata_dma_init();
    
    // POSIX user subsystem
    user_init();

    // Registering all disk file systems
    fat32_register();

    
    /* If an initfs module was provided by the bootloader, unpack it into ramfs */
    int r = initfs_process_multiboot_module(multiboot_magic, multiboot_info, "initfs");
    if (r == 0) klogprintf("initfs: unpacked successfully\n");
    else klogprintf("initfs: error: failed, code: %d\n", r);

    /* register devfs and mount at /dev so /dev/tty0, /dev/console etc. exist before init/getty */
    if (devfs_register() == 0) {
        klogprintf("devfs: registering devfs\n");
        if (devfs_mount("/dev") == 0) {
            klogprintf("devfs: mounted at /dev\n");
        }
        /* initialize stdio fds for current thread (main) */
        struct fs_file *console = devfs_open_direct("/dev/console");
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

    ps2_keyboard_init();
    rtc_init();
    
    ramfs_mkdir("/dev");


    // Prefer linuxrc/init if present; fallback to kernel shell.
    if (boot_try_run_init() != 0) {
        kprintf("fatal: nothing to run.");
    }
    
    for(;;) {
        asm volatile("sti; hlt" ::: "memory");
    }
}