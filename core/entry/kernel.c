/*
 * core/entry/kernel.c
 * Kernel entry point implementation
 * Author: fcexx
*/

#include <axonos.h>
#include <keyboard.h>
#include <stdint.h>
#include <stdio.h>
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
#include <smp.h>
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
#include <usb.h>
#include <exec.h>
#include <klog.h>
#include <debug.h>
#include <vbe.h>
#include <cirrus.h>
#include <vmwgfx.h>
#include <cirrusfb.h>
#include <nvme.h>
#include <e1000.h>
void ata_dma_init(void);
void scsi_init(void);
int pvscsi_init(void);

static char g_cwd[256] = "/";

extern uint8_t _end[]; /* kernel end symbol from linker */

static inline uintptr_t align_up_uintptr(uintptr_t v, uintptr_t a) {
    return (v + (a - 1)) & ~(a - 1);
}

/* Multiboot2: find the maximum module end address. This is critical to place
   the kernel heap ABOVE modules; otherwise heap headers can overwrite initfs
   (this is exactly what happens on VMware when archive size changes).
   Uses the same parsing strategies as initfs (standard, alt layout, loose scan)
   so heap placement matches where initfs will find the module. */
static uintptr_t mb2_modules_max_end(uint32_t multiboot_magic, uint64_t multiboot_info) {
    if (multiboot_magic != 0x36d76289u || multiboot_info == 0) return 0;

    uint8_t *p = (uint8_t*)(uintptr_t)multiboot_info;
    uint32_t total_size = *(uint32_t*)p;
    uintptr_t max_end = 0;

    /* Standard layout: total_size at p+0, tags start at p+8 */
    if (total_size >= 16 && total_size <= (256u * 1024u * 1024u)) {
        uint32_t off = 8;
        while (off + 8 <= total_size) {
            uint32_t type = *(uint32_t*)(p + off);
            uint32_t size = *(uint32_t*)(p + off + 4);
            if (size < 8) break;
            if ((uint64_t)off + (uint64_t)size > (uint64_t)total_size) break;
            if (type == 0) break;
            if (type == 3 && size >= 16) {
                uint32_t mod_end = *(uint32_t*)(p + off + 12);
                if ((uintptr_t)mod_end > max_end) max_end = (uintptr_t)mod_end;
            }
            off += (size + 7) & ~7u;
        }
    }

    /* Alt layout (VMware etc.): p+0 is first tag, not header. Try fixed window. */
    if (max_end == 0) {
        const uint32_t alt_max = 65536u;
        uint32_t alt_off = 0;
        while (alt_off + 16 <= alt_max) {
            uint32_t tag_type = *(uint32_t*)(p + alt_off);
            uint32_t tag_size = *(uint32_t*)(p + alt_off + 4);
            if (tag_size < 8 || tag_size > alt_max) break;
            if (tag_type == 0) break;
            if (tag_type == 3 && tag_size >= 16) {
                uint32_t mod_end = *(uint32_t*)(p + alt_off + 12);
                if ((uintptr_t)mod_end > max_end) max_end = (uintptr_t)mod_end;
            }
            alt_off += (tag_size + 7) & ~7u;
        }
    }

    /* Loose scan: look for module tags in first 64 KiB */
    if (max_end == 0) {
        const uint32_t meta_scan = 65536u;
        for (uint32_t off = 0; off + 16u <= meta_scan; off += 4u) {
            if (*(uint32_t*)(p + off) != 3u) continue;
            uint32_t tag_size = *(uint32_t*)(p + off + 4);
            if (tag_size < 16u || tag_size > 4096u) continue;
            if (off + tag_size > meta_scan) continue;
            uint32_t ms32 = *(uint32_t*)(p + off + 8);
            uint32_t me32 = *(uint32_t*)(p + off + 12);
            if (me32 <= ms32) continue;
            if ((uintptr_t)me32 > max_end) max_end = (uintptr_t)me32;
        }
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

/* Linux /sys/devices/system/cpu/{online,possible,present} — musl/glibc sysconf(_SC_NPROCESSORS_*)
 * and some tools read these before /proc/stat; a missing or wrong file yields nproc==1 despite /proc/cpuinfo. */
static ssize_t sysfs_show_cpu_range_list(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    int n = smp_cpu_count();
    if (n < 1)
        n = 1;
    if (n > SMP_MAX_CPUS)
        n = SMP_MAX_CPUS;
    int w = (n <= 1) ? snprintf(buf, size, "0\n") : snprintf(buf, size, "0-%d\n", n - 1);
    if (w < 0)
        return 0;
    if ((size_t)w > size)
        return (ssize_t)size;
    return (ssize_t)w;
}

/* Populate default sysfs tree when userspace mounts sysfs via SYS_mount. */
void kernel_sysfs_populate_default(void) {
    sysfs_mkdir("/sys/kernel");
    sysfs_mkdir("/sys/class");
    sysfs_mkdir("/sys/bus");
    sysfs_mkdir("/sys/devices/system/cpu");
    static const struct sysfs_attr attr_cpu = { sysfs_show_cpu_name_attr, NULL, NULL };
    static const struct sysfs_attr attr_ram = { sysfs_show_ram_mb_attr, NULL, NULL };
    static const struct sysfs_attr attr_cpu_range = { sysfs_show_cpu_range_list, NULL, NULL };
    sysfs_create_file("/sys/kernel/cpu_name", &attr_cpu);
    sysfs_create_file("/sys/kernel/ram_mb", &attr_ram);
    sysfs_create_file("/sys/devices/system/cpu/online", &attr_cpu_range);
    sysfs_create_file("/sys/devices/system/cpu/possible", &attr_cpu_range);
    sysfs_create_file("/sys/devices/system/cpu/present", &attr_cpu_range);
    {
        int nc = smp_cpu_count();
        if (nc < 1)
            nc = 1;
        if (nc > SMP_MAX_CPUS)
            nc = SMP_MAX_CPUS;
        for (int i = 0; i < nc; i++) {
            char path[80];
            snprintf(path, sizeof path, "/sys/devices/system/cpu/cpu%d", i);
            sysfs_mkdir(path);
        }
    }
    usb_sysfs_populate_default();
    pci_sysfs_init();  /* /sys/bus/pci/devices для lspci */
}

static int boot_try_run_init(void) {
    /* initramfs-style init selection: linuxrc, init, then classic paths */
    static const char *candidates[] = {
        "/linuxrc",
        "/init",
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
        static const char *init_env[] = { "PS1=\\[\\033[1;31m\\]\\u\\033[0m@\\h \e[0;37m\\w\\033[0m\\$ ", NULL };
        klogprintf("boot: starting init candidate %s\n", p);
        int rc = kernel_execve_from_path(p, argv0, init_env);
        if (rc == 0) return 0;
        klogprintf("boot: init %s returned rc=%d\n", p, rc);

    }
    return -1;
}

void kernel_main(uint32_t multiboot_magic, uint64_t multiboot_info) {
    qemu_debug_printf("Kernel started\n");
    enable_cursor();
    sysinfo_init(multiboot_magic, multiboot_info);

    /* Initialize heap EARLY and place it above kernel + multiboot modules.
       Otherwise heap metadata can overwrite initfs module (seen on VMware). */
    {
        uintptr_t heap_start = align_up_uintptr((uintptr_t)_end, 0x1000);
        uintptr_t mods_end = mb2_modules_max_end(multiboot_magic, multiboot_info);
        uintptr_t mods_end_aligned = 0;
        if (mods_end) {
            mods_end_aligned = align_up_uintptr(mods_end, 0x1000);
            if (mods_end_aligned > heap_start) heap_start = mods_end_aligned;
        }
        /*
         * Avoid placing the heap below 64 MiB only when that does not re-enter the
         * multiboot module/initrd range. Forcing heap_start=64M while a ~160 MiB
         * module lives at 0x080b9000..0x1234xxxx overlaps the arena with the CPIO:
         * kmalloc returns addresses inside the module, unpack corrupts heap headers,
         * krealloc then fails with magic=0.
         */
        const uintptr_t HEAP_MIN_START = (uintptr_t)(64u * 1024u * 1024u);
        if (heap_start < HEAP_MIN_START) {
            uintptr_t want = HEAP_MIN_START;
            if (mods_end_aligned != 0 && want < mods_end_aligned)
                want = mods_end_aligned;
            if (heap_start < want)
                heap_start = want;
        }
        /* Heap size must not exceed installed RAM. The heap implementation is a
           simple identity-mapped arena; if we size it past RAM we will scribble
           into non-existent memory and get "random" initfs extraction failures. */
        size_t heap_size = 0;
        int ram_mb = sysinfo_ram_mb();
        if (ram_mb > 0) {
            uint64_t ram_bytes = (uint64_t)ram_mb * 1024ULL * 1024ULL;
            uint64_t start = (uint64_t)heap_start;
            const uint64_t guard = 4ULL * 1024ULL * 1024ULL; /* 4 MiB (was 8) — more heap for VMware/low-RAM */
            if (ram_bytes > start + guard + (16ULL * 1024ULL * 1024ULL)) {
                uint64_t max = ram_bytes - start - guard;
                const uint64_t cap = 512ULL * 1024ULL * 1024ULL;
                if (max > cap) max = cap;
                heap_size = (size_t)max;
            }
        }
        if (heap_size == 0 && ram_mb > 0) {
            uint64_t ram_bytes = (uint64_t)ram_mb * 1024ULL * 1024ULL;
            uint64_t start = (uint64_t)heap_start;
            if (ram_bytes > start + (4ULL * 1024ULL * 1024ULL))
                heap_size = (size_t)(ram_bytes - start - (4ULL * 1024ULL * 1024ULL));
        }
        if (heap_size == 0)
            heap_size = 64ULL * 1024ULL * 1024ULL; /* safe default when RAM unknown */
        heap_init(heap_start, heap_size);
        kprintf("Kernel starting... heap_start: %p heap_size=%llu heap_total=%llu heap_base=%p ram_mb=%d kernel_end: %p mods_end: %p\n",
                (void*)heap_start,
                (unsigned long long)heap_size,
                (unsigned long long)heap_total_bytes(),
                (void*)heap_base_addr(),
                sysinfo_ram_mb(),
                (void*)(uintptr_t)_end, (void*)mods_end);
    }

    gdt_init();
    smp_init(multiboot_magic, multiboot_info);

    /* Per-CPU IST1 stacks for Double Fault (avoids triple-fault when SMP is enabled). */
    {
        const size_t DF_STACK_SIZE = 16 * 1024;
        int ndf = smp_have_acpi_cpu_topology() ? smp_cpu_count() : SMP_MAX_CPUS;
        if (ndf < 1)
            ndf = 1;
        if (ndf > SMP_MAX_CPUS)
            ndf = SMP_MAX_CPUS;
        for (int i = 0; i < ndf; i++) {
            void *df_stack = kmalloc(DF_STACK_SIZE + 16);
            if (df_stack) {
                uintptr_t top = (uintptr_t)df_stack + DF_STACK_SIZE + 16;
                uintptr_t df_top = align_up_uintptr(top, 16);
                tss_set_ist_for_cpu(i, 1, (uint64_t)df_top);
                kprintf("Set kernel DF IST1 for cpu %d at %p.\n", i, (void*)(uintptr_t)df_top);
            } else {
                kprintf("Failed to allocate DF IST stack for cpu %d (warning)\n", i);
            }
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
    klogprintf(OS_NAME " v" OS_VERSION ".\n");
    sysinfo_print_e820(multiboot_magic, multiboot_info);
    if (vbe_is_available() == 1) klogprintf("screen: Set mode: %ux%u@%u.\n", vbe_get_width(), vbe_get_height(), vbe_get_bpp());
    else klogprintf("screen: Set VGA+ 80x25 16 colors\n");
    
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
            for (int i = 0; i < 100000; i++) {
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

    smp_finalize_topology(multiboot_magic, multiboot_info);

    pci_init();
    /* Fbcon before long PCI/disk logs: otherwise klog uses VGA 80x25 and lines wrap ~66 chars with timestamps. */
    if (vmwgfx_kernel_init() == 0) {
        klogprintf("video: vmwgfx fbcon enabled early (wide console)\n");
        devfs_tty_realloc_for_console();
    } else if (cirrus_kernel_init() == 0) {
        klogprintf("video: cirrus fbcon enabled early\n");
        devfs_tty_realloc_for_console();
    }
    pci_dump_devices();
    intel_chipset_init();
    usb_init();

    /* Keep NIC driver non-intrusive until full net stack is wired.
       This avoids affecting boot stability on machines where NIC init timing is sensitive. */
    thread_init();
    smp_boot_aps();
 
    iothread_init();

    // POSIX user subsystem
    user_init();

    // Registering all disk file systems
    fat32_register();

    if (e1000_init() != 0) {
        klogprintf("net: e1000 not found\n");
    } else {
        int nrc = syscall_net_preinit();
        klogprintf("net: preinit %s\n", (nrc == 0) ? "ok" : "failed");
    }

    
    /* If an initfs module was provided by the bootloader, unpack it into ramfs */
    int r = initfs_process_multiboot_module(multiboot_magic, multiboot_info, "initfs");
    if (r == 0) {
        klogprintf("initfs: unpacked successfully\n");
        initfs_debug_list_vfs();
        struct stat st;
        if (vfs_stat("/linuxrc", &st) == 0)
            klogprintf("initfs: /linuxrc present\n");
        else if (vfs_stat("/init", &st) == 0)
            klogprintf("initfs: /init present\n");
        else if (vfs_stat("/sbin/init", &st) == 0)
            klogprintf("initfs: /sbin/init present\n");
        else if (vfs_stat("/bin/init", &st) == 0)
            klogprintf("initfs: /bin/init present\n");
        else
            kprintf("initfs: warning: no init (/linuxrc,/init,/sbin/init,/bin/init) found\n");
    } else {
        klogprintf("initfs: error: failed, code: %d\n", r);
        for (;;);
    }

    /* register devfs and mount at /dev so /dev/tty0, /dev/console etc. exist before init/getty */
    if (devfs_register() == 0) {
        klogprintf("devfs: registering devfs\n");
        if (devfs_mount("/dev") == 0) {
            klogprintf("devfs: mounted at /dev\n");
            /* /console -> /dev/console for chvt and tools that open "console" */
            (void)ramfs_symlink("/console", "/dev/console");
            scsi_init();
            ata_dma_init();
            (void)pvscsi_init();
            (void)nvme_init();
            {
                int n = devfs_block_count();
                klogprintf("List of block devices: %d\n", n);
                for (int i = 0; i < n; i++) {
                    char name[64];
                    int did = -1;
                    uint32_t secs = 0;
                    if (devfs_block_get(i, name, sizeof(name), &did, &secs) == 0)
                        klogprintf("  /dev/%s disk_id=%d sectors=%u\n", name, did, (unsigned)secs);
                }
            }
            (void)usb_publish_devfs_nodes();
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

    /* /etc/passwd and /etc/group so whoami/id show root. Use static buffers to avoid heap overflow. */
    (void)ramfs_mkdir("/etc");
    static const char root_passwd_line[] = "root:x:0:0:root:/root:/bin/sh\n";
    const size_t root_passwd_len = sizeof(root_passwd_line) - 1;
    struct fs_file *pf = fs_create_file("/etc/passwd");
    if (!pf) pf = fs_open("/etc/passwd");
    if (pf) {
        fs_write(pf, root_passwd_line, root_passwd_len, 0);
        fs_file_free(pf);
    }
    static const char root_group_line[] = "root:x:0:\nusers:x:100:\n";
    const size_t root_group_len = sizeof(root_group_line) - 1;
    struct fs_file *gf = fs_create_file("/etc/group");
    if (!gf) gf = fs_open("/etc/group");
    if (gf) {
        fs_write(gf, root_group_line, root_group_len, 0);
        fs_file_free(gf);
    }
    /* adduser expects /etc/shadow to exist and appends entries with O_APPEND. */
    {
        /* root:: = no password (empty field allows login with Enter) */
        static const char root_shadow[] = "root::0:0:99999:7:::\n";
        struct fs_file *sf = fs_create_file("/etc/shadow");
        if (!sf) sf = fs_open("/etc/shadow");
        if (sf) {
            fs_write(sf, root_shadow, sizeof(root_shadow) - 1, 0);
            fs_file_free(sf);
        }
    }
    /* adduser/addgroup may readlink /etc/gshadow; create minimal file. */
    {
        static const char root_gshadow[] = "root::\nusers::\n";
        struct fs_file *gsf = fs_create_file("/etc/gshadow");
        if (!gsf) gsf = fs_open("/etc/gshadow");
        if (gsf) {
            fs_write(gsf, root_gshadow, sizeof(root_gshadow) - 1, 0);
            fs_file_free(gsf);
        }
    }
    (void)ramfs_mkdir("/var");
    (void)ramfs_mkdir("/var/run");
    (void)ramfs_mkdir("/var/log");  /* ensure exists for wtmp (klog also creates it) */
    (void)ramfs_mkdir("/tmp");  /* passwd uses mkstemp in /tmp for shadow update */
    /* /var/log/wtmp: login history for last(1). Empty at boot; login appends utmp records. */
    {
        struct fs_file *wf = fs_create_file("/var/log/wtmp");
        if (!wf) wf = fs_open("/var/log/wtmp");
        if (wf) fs_file_free(wf);
    }
    syscall_net_ensure_resolv();
    /* Programs (mount, sh) open /etc/localtime; create so open doesn't fail. */
    {
        struct fs_file *lt = fs_create_file("/etc/localtime");
        if (lt) fs_file_free(lt);
    }
    /* /etc/profile: sourced by login shells (getty->login->sh -l). Sets PS1 and TERM for vim. */
    {
        static const char profile[] =
            "export TERM=builtin_ansi\n"
            "export PS1='\\[\\033[1;31m\\]\\u\\033[0m@\\h \\033[1;37m\\w\\033[0m \\$ '\n";
        struct fs_file *pf = fs_create_file("/etc/profile");
        if (!pf) pf = fs_open("/etc/profile");
        if (pf) {
            fs_write(pf, profile, sizeof(profile) - 1, 0);
            fs_file_free(pf);
        }   
    }
    /* /etc/issue: getty prints this before login prompt. \l = tty name (tty1, tty2, ...) */
    {
        static const char issue[] = "AxonOS v" OS_VERSION " for servers (\\l)\n\n";
        struct fs_file *ifile = fs_create_file("/etc/issue");
        if (!ifile) ifile = fs_open("/etc/issue");
        if (ifile) {
            fs_write(ifile, issue, sizeof(issue) - 1, 0);
            fs_file_free(ifile);
        }
    }
    /* /etc/securetty: TTY devices from which root can log in */
    {
        static const char securetty[] = "console\ntty1\ntty2\ntty3\ntty4\ntty5\ntty6\nttyS0\nttyS1\n";
        struct fs_file *sf = fs_create_file("/etc/securetty");
        if (!sf) sf = fs_open("/etc/securetty");
        if (sf) {
            fs_write(sf, securetty, sizeof(securetty) - 1, 0);
            fs_file_free(sf);
        }
    }
    /* /etc/motd: message of the day, shown after successful login */
    {
        static const char motd[] = "Welcome to " OS_NAME " v" OS_VERSION "!\n"
                                   "Official site: https://axont.ru\n\n";
        struct fs_file *mf = fs_create_file("/etc/motd");
        if (!mf) mf = fs_open("/etc/motd");
        if (mf) {
            fs_write(mf, motd, sizeof(motd) - 1, 0);
            fs_file_free(mf);
        }
    }
    /* /etc/termcap: vt102/linux with arrow keys (ku/kd/kr/kl) so vim moves cursor correctly */
    {
        static const char termcap[] =
            "vt102|vt100|linux|linux-term:"
            /* 1280x800 / 8x16 fbcon ≈ 160×50; ioctl winsize overrides for other vmwgfx modes */
            "co#160:li#50:cl=\\E[2J\\E[H:cm=\\E[%i%d;%dH:nd=\\E[C:up=\\E[A:"
            "ce=\\E[K:cd=\\E[J:so=\\E[7m:se=\\E[0m:us=\\E[4m:ue=\\E[0m:"
            "ku=\\E[A:kd=\\E[B:kr=\\E[C:kl=\\E[D:"
            "ti=\\E[?1049h:te=\\E[?1049l:\n";
        struct fs_file *tc = fs_create_file("/etc/termcap");
        if (!tc) tc = fs_open("/etc/termcap");
        if (tc) {
            fs_write(tc, termcap, sizeof(termcap) - 1, 0);
            fs_file_free(tc);
        }
    }

    /* Compatibility: many distros' adduser scripts call /sbin/addgroup explicitly,
       while initfs may only provide /usr/sbin/addgroup. Create a tiny wrapper if needed. */
    {
        struct stat st;
        if (vfs_stat("/sbin/addgroup", &st) != 0 && vfs_stat("/usr/sbin/addgroup", &st) == 0) {
            (void)ramfs_mkdir("/sbin");
            /* Shebang runs with argv [interp, script_path, orig_argv[1], ...]; shift drops script path so $@ = real args for addgroup */
            static const char addgroup_wrapper[] = "#!/bin/sh\nshift\nexec /usr/sbin/addgroup \"$@\"\n";
            const size_t L = sizeof(addgroup_wrapper) - 1;
            struct fs_file *af = fs_create_file("/sbin/addgroup");
            if (!af) af = fs_open("/sbin/addgroup");
            if (af) {
                fs_write(af, addgroup_wrapper, L, 0);
                fs_file_free(af);
            }
        }
    }
    ps2_keyboard_init();
    rtc_init();
    kclear();
    // Prefer linuxrc/init if present; fallback to kernel shell.
    if (boot_try_run_init() != 0) {
        kprintf("fatal: nothing to run.");
    }
    
    for(;;) {
        asm volatile("sti; hlt" ::: "memory");
    }
}