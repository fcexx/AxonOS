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

#include <iothread.h>
#include <fs.h>
#include <ext2.h>
#include <ramfs.h>
#include <sysfs.h>
#include <initfs.h>
#include <editor.h>
#include <fat32.h>
#include <intel_chipset.h>s
#include <disk.h>

/* ATA DMA driver init (registered here) */
void ata_dma_init(void);

int exit = 0;

static char g_cwd[256] = "/";

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

static void resolve_path(const char *cwd, const char *arg, char *out, size_t outlen) {
    if (!arg || arg[0] == '\0') {
        /* return cwd */
        strncpy(out, cwd, outlen-1);
        out[outlen-1] = '\0';
        return;
    }
    if (arg[0] == '/') {
        strncpy(out, arg, outlen-1);
        out[outlen-1] = '\0';
        return;
    }
    /* remove leading ./ if present */
    const char *p = arg;
    if (p[0] == '.' && p[1] == '/') p += 2;
    /* build absolute path into tmp then normalize */
    char tmp[512];
    if (arg[0] == '\0') {
        strncpy(tmp, cwd, sizeof(tmp)-1);
        tmp[sizeof(tmp)-1] = '\0';
    } else if (arg[0] == '/') {
        strncpy(tmp, arg, sizeof(tmp)-1);
        tmp[sizeof(tmp)-1] = '\0';
    } else {
        if (strcmp(cwd, "/") == 0) {
            tmp[0] = '/';
            size_t n = strlen(p);
            if (n > sizeof(tmp) - 2) n = sizeof(tmp) - 2;
            if (n) memcpy(tmp + 1, p, n);
            tmp[1 + n] = '\0';
        } else {
            size_t a = strlen(cwd);
            if (a > sizeof(tmp) - 2) a = sizeof(tmp) - 2;
            memcpy(tmp, cwd, a);
            tmp[a] = '/';
            size_t n = strlen(p);
            if (n > sizeof(tmp) - a - 2) n = sizeof(tmp) - a - 2;
            if (n) memcpy(tmp + a + 1, p, n);
            tmp[a + 1 + n] = '\0';
        }
    }
    /* normalize tmp into out (handle "." and "..") */
    /* algorithm: split by '/', push segments, pop on '..' */
    char **parts = (char**)kmalloc(128);
    if (!parts) return;
    int pc = 0;
    char *s = tmp;
    /* ensure leading slash */
    if (*s != '/') {
        /* make absolute by prepending cwd */
        char t2[512]; strncpy(t2, tmp, sizeof(t2)-1); t2[sizeof(t2)-1] = '\0';
        if (strcmp(cwd, "/") == 0) {
            tmp[0] = '/';
            size_t n = strlen(t2);
            if (n > sizeof(tmp) - 2) n = sizeof(tmp) - 2;
            if (n) memcpy(tmp + 1, t2, n);
            tmp[1 + n] = '\0';
        } else {
            size_t a = strlen(cwd);
            if (a > sizeof(tmp) - 2) a = sizeof(tmp) - 2;
            memcpy(tmp, cwd, a);
            tmp[a] = '/';
            size_t n = strlen(t2);
            if (n > sizeof(tmp) - a - 2) n = sizeof(tmp) - a - 2;
            if (n) memcpy(tmp + a + 1, t2, n);
            tmp[a + 1 + n] = '\0';
        }
        s = tmp;
    }
    /* tokenize */
    s++; /* skip leading slash */
    while (*s) {
        char *seg = s;
        while (*s && *s != '/') s++;
        size_t len = (size_t)(s - seg);
        if (len == 0) { if (*s) s++; continue; }
        char save = seg[len];
        seg[len] = '\0';
        if (strcmp(seg, ".") == 0) {
            /* ignore */
        } else if (strcmp(seg, "..") == 0) {
            if (pc > 0) pc--; /* pop */
        } else {
            parts[pc++] = seg;
        }
        seg[len] = save;
        if (*s) s++;
    }
    /* build output */
    if (pc == 0) {
        strncpy(out, "/", outlen-1); out[outlen-1] = '\0';
    } else {
        size_t pos = 0;
        for (int i = 0; i < pc; i++) {
            size_t need = strlen(parts[i]) + 1; /* '/' + name */
            if (pos + need >= outlen) break;
            out[pos++] = '/';
            size_t n = strlen(parts[i]);
            memcpy(out + pos, parts[i], n);
            pos += n;
        }
        out[pos] = '\0';
    }
    kfree(parts);
}

static int is_dir_path(const char *path) {
    struct fs_file *f = fs_open(path);
    if (!f) return 0;
    /* If driver explicitly set type, use it */
    if (f->type == FS_TYPE_DIR) {
        fs_file_free(f);
        return 1;
    }
    if (f->type == FS_TYPE_REG) {
        fs_file_free(f);
        return 0;
    }
    /* Fallback: attempt to read directory entries */
    size_t want = f->size ? f->size : 512;
    if (want > 8192) want = 8192;
    void *buf = kmalloc(want + 1);
    int found = 0;
    if (buf) {
        ssize_t r = fs_read(f, buf, want, 0);
        if (r > 0) {
            uint32_t off = 0;
            while ((size_t)off + sizeof(struct ext2_dir_entry) < (size_t)r) {
                struct ext2_dir_entry *de = (struct ext2_dir_entry *)((uint8_t*)buf + off);
                if (de->inode != 0 && de->rec_len > 0 && de->name_len > 0 && de->name_len < 255) { found = 1; break; }
                if (de->rec_len == 0) break;
                off += de->rec_len;
            }
        }
        kfree(buf);
    }
    fs_file_free(f);
    return found;
}

void ring0_shell()  { osh_run(); }

void ascii_art() {
    kprintf("<(0f)> \xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0<(0b)> \xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0 \xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0\n");
    kprintf("<(0f)>\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1<(0b)>\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\n");
    kprintf("<(0f)>\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1<(0b)>\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\n");
    kprintf("<(0f)>\xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1<(0b)>\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0\n");
    kprintf("<(0f)>\xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1<(0b)>\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0\n");
    kprintf("<(0f)>\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1<(0b)>\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0      \xB0\xB1\xB2\xDB\xB2\xB1\xB0\n");
    kprintf("<(0f)>\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1<(0b)>\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0      \xB0\xB1\xB2\xDB\xB2\xB1\xB0\n");
    kprintf("<(0f)>\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xB2\xB1<(0b)>\xB0\xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0\xB0\xB1\xB2\xDB\xDB\xDB\xDB\xDB\xDB\xDB\xB2\xB1\xB0\n\n");
}

void kernel_main(uint32_t multiboot_magic, uint64_t multiboot_info) {
    kclear();
    kprint("Initializing kernel...\n");
    sysinfo_init(multiboot_magic, multiboot_info);

    gdt_init();
    idt_init();
    pic_init();
    pit_init();
    

    
    apic_init();
    apic_timer_init();
    idt_set_handler(APIC_TIMER_VECTOR, apic_timer_handler);
    
    paging_init();
    heap_init(0, 0);

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
        kprintf("Switched to APIC Timer\n");
    } else {
        kprintf("APIC: using PIT\n");
        apic_timer_stop();
    }

    pci_init();
    pci_dump_devices();
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
    ramfs_register();
    ext2_register();
    fat32_register();
    
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

        pci_sysfs_init();
        
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
    
    /* If an initfs module was provided by the bootloader, unpack it into ramfs */
    {
        int r = initfs_process_multiboot_module(multiboot_magic, multiboot_info, "initfs");
        if (r == 0) kprintf("initfs: unpacked successfully\n");
        else if (r == 1) kprintf("initfs: initfs module not found or not multiboot2\n");
        else if (r == -1) kprintf("initfs: success\n");
    }
    /* register and mount devfs at /dev */
    if (devfs_register() == 0) {
        kprintf("devfs: registering devfs\n");
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
        kprintf("devfs: failed to register\n");
    }

    ps2_keyboard_init();
    rtc_init();
    
    kprintf("kernel base: done\n");
    
    kprintf("\n%s v%s\n", OS_NAME, OS_VERSION);
    
    // autostart: run /start script once if present
    {
        struct fs_file *f = fs_open("/start");
        if (f) { fs_file_free(f); (void)exec_line("osh /start"); }
        else { kprintf("FATAL: /start file not found; fallback to osh\n"); exec_line("PS1=\"\\w # \""); exec_line("osh"); }
    }

    kprintf("\nWelcome to %s %s!\n", OS_NAME, OS_VERSION);

    // Завершение
    kprint("\nShutting down...");
    pit_sleep_ms(3000);
    shutdown_system();
    
    for(;;) {
        asm volatile("hlt");
    }
}