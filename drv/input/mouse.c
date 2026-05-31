#include <mouse.h>

#include <devfs.h>
#include <idt.h>
#include <keyboard.h>
#include <pic.h>
#include <stdio.h>
#include <serial.h>
#include <spinlock.h>
#include <sysfs.h>
#include <thread.h>

#define PS2_CMD_PORT 0x64
#define PS2_DATA_PORT 0x60

/* Byte ring exposed via /dev/input/mice */
static uint8_t g_mouse_rb[4096];
static int g_mouse_head = 0;
static int g_mouse_tail = 0;
static int g_mouse_count = 0;
static spinlock_t g_mouse_lock = { 0 };

/* Packet assembler for IRQ stream */
static uint8_t g_pkt[3];
static int g_pkt_idx = 0;

static int g_mouse_sysfs_registered = 0;

static int ps2_wait_input_empty(void) {
    for (int i = 0; i < 100000; i++) {
        if ((inb(PS2_CMD_PORT) & 0x02) == 0) return 1;
        asm volatile("pause");
    }
    return 0;
}

static int ps2_wait_output_full(void) {
    for (int i = 0; i < 100000; i++) {
        if (inb(PS2_CMD_PORT) & 0x01) return 1;
        asm volatile("pause");
    }
    return 0;
}

static void ps2_flush_output(void) {
    for (int i = 0; i < 64; i++) {
        if ((inb(PS2_CMD_PORT) & 0x01u) == 0) break;
        (void)inb(PS2_DATA_PORT);
    }
}

static void ps2_mouse_write(uint8_t v) {
    if (!ps2_wait_input_empty()) return;
    outb(PS2_CMD_PORT, 0xD4);
    if (!ps2_wait_input_empty()) return;
    outb(PS2_DATA_PORT, v);
}

static int ps2_mouse_read_ack(uint8_t *out) {
    if (!out) return -1;
    if (!ps2_wait_output_full()) return -1;
    *out = inb(PS2_DATA_PORT);
    return 0;
}

static void mouse_stream_push(uint8_t b) {
    unsigned long irqf;
    acquire_irqsave(&g_mouse_lock, &irqf);
    if (g_mouse_count < (int)sizeof(g_mouse_rb)) {
        g_mouse_rb[g_mouse_tail] = b;
        g_mouse_tail = (g_mouse_tail + 1) % (int)sizeof(g_mouse_rb);
        g_mouse_count++;
    }
    release_irqrestore(&g_mouse_lock, irqf);
}

void mouse_process_byte(uint8_t b) {
    if (g_pkt_idx == 0 && (b & 0x08u) == 0) {
        /* Out-of-sync: first byte always has bit3=1 for PS/2 packet. */
        return;
    }
    g_pkt[g_pkt_idx++] = b;
    if (g_pkt_idx >= 3) {
        mouse_stream_push(g_pkt[0]);
        mouse_stream_push(g_pkt[1]);
        mouse_stream_push(g_pkt[2]);
        g_pkt_idx = 0;
    }
}

static void mouse_irq_handler(cpu_registers_t *regs) {
    (void)regs;
    /* Drain all pending bytes to avoid partial-packet stalls. */
    for (int i = 0; i < 32; i++) {
        uint8_t st = inb(PS2_CMD_PORT);
        if ((st & 0x01u) == 0) break;
        uint8_t b = inb(PS2_DATA_PORT);
        if (st & 0x20u) mouse_process_byte(b);
        else keyboard_process_scancode(b);
    }
}

int mouse_stream_available(void) {
    int n;
    unsigned long irqf;
    acquire_irqsave(&g_mouse_lock, &irqf);
    n = g_mouse_count;
    release_irqrestore(&g_mouse_lock, irqf);
    return n;
}

ssize_t mouse_read_stream(void *buf, size_t size) {
    if (!buf) return -1;
    if (size == 0) return 0;
    uint8_t *out = (uint8_t*)buf;
    size_t got = 0;

    /* Block until at least one byte, then drain available bytes. */
    while (got == 0) {
        unsigned long irqf;
        acquire_irqsave(&g_mouse_lock, &irqf);
        while (got < size && g_mouse_count > 0) {
            out[got++] = g_mouse_rb[g_mouse_head];
            g_mouse_head = (g_mouse_head + 1) % (int)sizeof(g_mouse_rb);
            g_mouse_count--;
        }
        release_irqrestore(&g_mouse_lock, irqf);
        if (got > 0) break;
        thread_sleep(1);
    }
    return (ssize_t)got;
}

static ssize_t mouse_sysfs_show_text(char *buf, size_t size, void *priv) {
    const char *s = (const char*)priv;
    if (!buf || size == 0) return 0;
    if (!s) s = "";
    size_t n = 0;
    while (s[n] && n < size) { buf[n] = s[n]; n++; }
    if (n < size) buf[n++] = '\n';
    return (ssize_t)n;
}

static ssize_t mouse_sysfs_show_pending(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    return (ssize_t)snprintf(buf, size, "%d\n", mouse_stream_available());
}

static void mouse_register_sysfs(void) {
    if (g_mouse_sysfs_registered) return;
    if (sysfs_mkdir("/sys/class") != 0) return;
    if (sysfs_mkdir("/sys/class/input") != 0) return;
    if (sysfs_mkdir("/sys/class/input/mouse0") != 0) return;
    struct sysfs_attr attr_name = { mouse_sysfs_show_text, NULL, (void*)"PS/2 mouse" };
    struct sysfs_attr attr_driver = { mouse_sysfs_show_text, NULL, (void*)"ps2-mouse" };
    struct sysfs_attr attr_pending = { mouse_sysfs_show_pending, NULL, NULL };
    if (sysfs_create_file("/sys/class/input/mouse0/name", &attr_name) != 0) return;
    if (sysfs_create_file("/sys/class/input/mouse0/driver", &attr_driver) != 0) return;
    if (sysfs_create_file("/sys/class/input/mouse0/pending_bytes", &attr_pending) != 0) return;
    g_mouse_sysfs_registered = 1;
}

void mouse_publish_sysfs(void) {
    mouse_register_sysfs();
}

void ps2_mouse_init(void) {
    idt_set_handler(44, mouse_irq_handler); /* IRQ12 */
    /* Program shared PS/2 controller atomically to avoid losing IRQ1 enable bit. */
    pic_mask_irq(1);
    pic_mask_irq(12);

    /* Enable second PS/2 port and IRQ12 in controller command byte. */
    ps2_flush_output();
    if (ps2_wait_input_empty()) outb(PS2_CMD_PORT, 0xA8); /* enable aux port */
    if (ps2_wait_input_empty()) outb(PS2_CMD_PORT, 0x20); /* read command byte */
    uint8_t cmd = 0x47; /* sane default: IRQ1+IRQ12+translation */
    if (ps2_wait_output_full()) cmd = inb(PS2_DATA_PORT);
    cmd |= 0x03u;              /* force IRQ1 + IRQ12 enabled */
    cmd &= (uint8_t)~0x30u;    /* clear disable keyboard/mouse clocks */
    cmd |= 0x40u;              /* keep translation on for set1 keyboard path */
    if (ps2_wait_input_empty()) outb(PS2_CMD_PORT, 0x60);
    if (ps2_wait_input_empty()) outb(PS2_DATA_PORT, cmd);
    ps2_flush_output();

    /* Defaults + enable streaming packets. */
    uint8_t ack = 0;
    ps2_mouse_write(0xF6); (void)ps2_mouse_read_ack(&ack);
    ps2_mouse_write(0xF4); (void)ps2_mouse_read_ack(&ack);

    pic_unmask_irq(1);
    pic_unmask_irq(12);

    (void)devfs_create_char_node("/dev/input/mice", NULL);
    mouse_register_sysfs();
}
