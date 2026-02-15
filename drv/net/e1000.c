#include <e1000.h>
#include <axonos.h>
#include <pci.h>
#include <mmio.h>
#include <heap.h>
#include <string.h>
#include <klog.h>
#include <pit.h>
#include <stdint.h>

extern uint64_t virt_to_phys(uint64_t va);

#define E1000_VENDOR_ID               0x8086

/* Commonly used Intel PRO/1000 / e1000e IDs (includes QEMU 0x100E). */
#define E1000_DEV_82540EM             0x100E
#define E1000_DEV_82545EM             0x100F
#define E1000_DEV_82543GC             0x1004
#define E1000_DEV_82574L              0x10D3
#define E1000_DEV_82571EB             0x105E
#define E1000_DEV_82572EI             0x107D
#define E1000_DEV_82573E              0x108B
#define E1000_DEV_82567LM             0x10F5
#define E1000_DEV_82566DM             0x10BD

/* Registers */
#define E1000_REG_CTRL                0x0000
#define E1000_REG_STATUS              0x0008
#define E1000_REG_EERD                0x0014
#define E1000_REG_ICR                 0x00C0
#define E1000_REG_IMS                 0x00D0
#define E1000_REG_IMC                 0x00D8
#define E1000_REG_RCTL                0x0100
#define E1000_REG_TCTL                0x0400
#define E1000_REG_TIPG                0x0410

#define E1000_REG_RDBAL               0x2800
#define E1000_REG_RDBAH               0x2804
#define E1000_REG_RDLEN               0x2808
#define E1000_REG_RDH                 0x2810
#define E1000_REG_RDT                 0x2818

#define E1000_REG_TDBAL               0x3800
#define E1000_REG_TDBAH               0x3804
#define E1000_REG_TDLEN               0x3808
#define E1000_REG_TDH                 0x3810
#define E1000_REG_TDT                 0x3818

#define E1000_REG_RAL0                0x5400
#define E1000_REG_RAH0                0x5404
#define E1000_RAH_AV                  (1u << 31)

/* CTRL / STATUS bits */
#define E1000_CTRL_RST                (1u << 26)
#define E1000_CTRL_ASDE               (1u << 5)
#define E1000_CTRL_SLU                (1u << 6)
#define E1000_STATUS_LU               (1u << 1)

/* EERD bits (8254x style) */
#define E1000_EERD_START              (1u << 0)
#define E1000_EERD_DONE_LEGACY        (1u << 4)
#define E1000_EERD_DONE_ALT           (1u << 1)

/* RX control bits */
#define E1000_RCTL_EN                 (1u << 1)
#define E1000_RCTL_UPE                (1u << 3)
#define E1000_RCTL_MPE                (1u << 4)
#define E1000_RCTL_BAM                (1u << 15)
#define E1000_RCTL_SECRC              (1u << 26)

/* TX control bits */
#define E1000_TCTL_EN                 (1u << 1)
#define E1000_TCTL_PSP                (1u << 3)
#define E1000_TCTL_CT_SHIFT           4
#define E1000_TCTL_COLD_SHIFT         12

/* TX descriptor bits */
#define E1000_TX_CMD_EOP              (1u << 0)
#define E1000_TX_CMD_IFCS             (1u << 1)
#define E1000_TX_CMD_RS               (1u << 3)
#define E1000_TX_STATUS_DD            (1u << 0)

/* RX descriptor bits */
#define E1000_RX_STATUS_DD            (1u << 0)
#define E1000_RX_STATUS_EOP           (1u << 1)

#define E1000_TX_DESC_COUNT           64
#define E1000_RX_DESC_COUNT           64
#define E1000_RX_BUF_SIZE             2048
#define E1000_TX_BUF_SIZE             2048
#define E1000_ETH_MIN_FRAME           60

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint16_t length;
    uint8_t cso;
    uint8_t cmd;
    uint8_t status;
    uint8_t css;
    uint16_t special;
} e1000_tx_desc_t;

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint16_t length;
    uint16_t checksum;
    uint8_t status;
    uint8_t errors;
    uint16_t special;
} e1000_rx_desc_t;

typedef struct {
    int initialized;
    pci_device_t *pdev;
    volatile uint8_t *mmio;
    uint8_t mac[6];

    e1000_tx_desc_t *tx_desc;
    e1000_rx_desc_t *rx_desc;
    uint8_t *tx_buf[E1000_TX_DESC_COUNT];
    uint8_t *rx_buf[E1000_RX_DESC_COUNT];
    uint32_t rx_next;
    uint32_t rdt_sw;  /* программный RDT для возврата дескрипторов (8254x) */

    e1000_stats_t stats;
} e1000_state_t;

static e1000_state_t g_e1000;

static void *kmalloc_aligned_local(size_t size, size_t align) {
    uintptr_t raw = (uintptr_t)kmalloc(size + align);
    if (!raw) return NULL;
    uintptr_t aligned = (raw + (align - 1)) & ~(uintptr_t)(align - 1);
    memset((void *)aligned, 0, size);
    return (void *)aligned;
}

static inline uint32_t e1000_read32(size_t reg) {
    return mmio_read32((volatile void *)g_e1000.mmio, reg);
}

static inline void e1000_write32(size_t reg, uint32_t val) {
    mmio_write32((volatile void *)g_e1000.mmio, reg, val);
}

static int e1000_supported_device(uint16_t device_id) {
    switch (device_id) {
        case E1000_DEV_82540EM:
        case E1000_DEV_82545EM:
        case E1000_DEV_82543GC:
        case E1000_DEV_82574L:
        case E1000_DEV_82571EB:
        case E1000_DEV_82572EI:
        case E1000_DEV_82573E:
        case E1000_DEV_82567LM:
        case E1000_DEV_82566DM:
            return 1;
        default:
            return 0;
    }
}

static pci_device_t *e1000_find_pci_device(void) {
    pci_device_t *devs = pci_get_devices();
    int count = pci_get_device_count();
    for (int i = 0; i < count; i++) {
        pci_device_t *d = &devs[i];
        if (d->vendor_id != E1000_VENDOR_ID) continue;
        if (d->class_code != 0x02) continue; /* network controller */
        if (!e1000_supported_device(d->device_id)) continue;
        return d;
    }
    return NULL;
}

static int e1000_eeprom_read16(uint8_t addr, uint16_t *out_word) {
    if (!out_word) return -1;
    uint32_t cmd = E1000_EERD_START | ((uint32_t)addr << 8);
    e1000_write32(E1000_REG_EERD, cmd);
    for (int i = 0; i < 10000; i++) {
        uint32_t v = e1000_read32(E1000_REG_EERD);
        if (v & (E1000_EERD_DONE_LEGACY | E1000_EERD_DONE_ALT)) {
            *out_word = (uint16_t)((v >> 16) & 0xFFFFu);
            return 0;
        }
    }
    return -1;
}

static int e1000_read_mac(uint8_t out_mac[6]) {
    if (!out_mac) return -1;
    uint16_t w0 = 0, w1 = 0, w2 = 0;
    if (e1000_eeprom_read16(0, &w0) == 0 &&
        e1000_eeprom_read16(1, &w1) == 0 &&
        e1000_eeprom_read16(2, &w2) == 0) {
        out_mac[0] = (uint8_t)(w0 & 0xFF);
        out_mac[1] = (uint8_t)(w0 >> 8);
        out_mac[2] = (uint8_t)(w1 & 0xFF);
        out_mac[3] = (uint8_t)(w1 >> 8);
        out_mac[4] = (uint8_t)(w2 & 0xFF);
        out_mac[5] = (uint8_t)(w2 >> 8);
        return 0;
    }

    /* EEPROM path failed on some variants; fallback to RAL/RAH. */
    uint32_t ral = e1000_read32(E1000_REG_RAL0);
    uint32_t rah = e1000_read32(E1000_REG_RAH0);
    out_mac[0] = (uint8_t)(ral & 0xFF);
    out_mac[1] = (uint8_t)((ral >> 8) & 0xFF);
    out_mac[2] = (uint8_t)((ral >> 16) & 0xFF);
    out_mac[3] = (uint8_t)((ral >> 24) & 0xFF);
    out_mac[4] = (uint8_t)(rah & 0xFF);
    out_mac[5] = (uint8_t)((rah >> 8) & 0xFF);
    return (out_mac[0] | out_mac[1] | out_mac[2] | out_mac[3] | out_mac[4] | out_mac[5]) ? 0 : -1;
}

static int e1000_setup_tx(void) {
    g_e1000.tx_desc = (e1000_tx_desc_t *)kmalloc_aligned_local(sizeof(e1000_tx_desc_t) * E1000_TX_DESC_COUNT, 16);
    if (!g_e1000.tx_desc) return -1;

    for (uint32_t i = 0; i < E1000_TX_DESC_COUNT; i++) {
        g_e1000.tx_buf[i] = (uint8_t *)kmalloc_aligned_local(E1000_TX_BUF_SIZE, 16);
        if (!g_e1000.tx_buf[i]) return -1;
        uint64_t pa = virt_to_phys((uint64_t)(uintptr_t)g_e1000.tx_buf[i]);
        if (!pa) return -1;
        g_e1000.tx_desc[i].addr = pa;
        g_e1000.tx_desc[i].status = E1000_TX_STATUS_DD;
    }

    uint64_t tx_pa = virt_to_phys((uint64_t)(uintptr_t)g_e1000.tx_desc);
    if (!tx_pa) return -1;

    e1000_write32(E1000_REG_TDBAL, (uint32_t)(tx_pa & 0xFFFFFFFFu));
    e1000_write32(E1000_REG_TDBAH, (uint32_t)(tx_pa >> 32));
    e1000_write32(E1000_REG_TDLEN, (uint32_t)(sizeof(e1000_tx_desc_t) * E1000_TX_DESC_COUNT));
    e1000_write32(E1000_REG_TDH, 0);
    e1000_write32(E1000_REG_TDT, 0);

    /* Typical values used by Intel examples and hobby OS drivers. */
    uint32_t tctl = E1000_TCTL_EN | E1000_TCTL_PSP | (0x10u << E1000_TCTL_CT_SHIFT) | (0x40u << E1000_TCTL_COLD_SHIFT);
    e1000_write32(E1000_REG_TCTL, tctl);
    e1000_write32(E1000_REG_TIPG, 0x0060200A);
    return 0;
}

static int e1000_setup_rx(void) {
    g_e1000.rx_desc = (e1000_rx_desc_t *)kmalloc_aligned_local(sizeof(e1000_rx_desc_t) * E1000_RX_DESC_COUNT, 16);
    if (!g_e1000.rx_desc) return -1;

    for (uint32_t i = 0; i < E1000_RX_DESC_COUNT; i++) {
        g_e1000.rx_buf[i] = (uint8_t *)kmalloc_aligned_local(E1000_RX_BUF_SIZE, 16);
        if (!g_e1000.rx_buf[i]) return -1;
        uint64_t pa = virt_to_phys((uint64_t)(uintptr_t)g_e1000.rx_buf[i]);
        if (!pa) return -1;
        g_e1000.rx_desc[i].addr = pa;
        g_e1000.rx_desc[i].status = 0;
    }

    uint64_t rx_pa = virt_to_phys((uint64_t)(uintptr_t)g_e1000.rx_desc);
    if (!rx_pa) return -1;

    e1000_write32(E1000_REG_RDBAL, (uint32_t)(rx_pa & 0xFFFFFFFFu));
    e1000_write32(E1000_REG_RDBAH, (uint32_t)(rx_pa >> 32));
    e1000_write32(E1000_REG_RDLEN, (uint32_t)(sizeof(e1000_rx_desc_t) * E1000_RX_DESC_COUNT));
    e1000_write32(E1000_REG_RDH, 0);
    g_e1000.rdt_sw = E1000_RX_DESC_COUNT - 1;
    e1000_write32(E1000_REG_RDT, g_e1000.rdt_sw);
    g_e1000.rx_next = 0;

    /* Enable broad receive filters during early bring-up. */
    e1000_write32(E1000_REG_RCTL, E1000_RCTL_EN | E1000_RCTL_UPE | E1000_RCTL_MPE | E1000_RCTL_BAM | E1000_RCTL_SECRC);
    return 0;
}

int e1000_init(void) {
    if (g_e1000.initialized) return 0;
    memset(&g_e1000, 0, sizeof(g_e1000));

    pci_device_t *pdev = e1000_find_pci_device();
    if (!pdev) {
        klogprintf("e1000: no supported Intel NIC found\n");
        return -1;
    }
    g_e1000.pdev = pdev;

    /* Enable MEM + BUSMASTER. */
    uint32_t pci_cmd = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, 0x04);
    pci_cmd |= (1u << 1) | (1u << 2);
    pci_config_write_dword(pdev->bus, pdev->device, pdev->function, 0x04, pci_cmd);

    uint64_t bar0 = (uint64_t)(pdev->bar[0] & ~0xFULL);
    if (bar0 == 0 || (pdev->bar[0] & 0x1u)) {
        klogprintf("e1000: invalid MMIO BAR0=0x%08x\n", pdev->bar[0]);
        return -1;
    }

    g_e1000.mmio = (volatile uint8_t *)mmio_map_phys(bar0, 0x20000);
    if (!g_e1000.mmio) {
        klogprintf("e1000: failed to map MMIO at 0x%llx\n", (unsigned long long)bar0);
        return -1;
    }

    /* Hardware reset. Без pit_sleep_ms: в контексте первого ping (syscall) на VMware таймер может не тикать. */
    e1000_write32(E1000_REG_CTRL, e1000_read32(E1000_REG_CTRL) | E1000_CTRL_RST);
    for (int i = 0; i < 50000; i++) {
        if ((e1000_read32(E1000_REG_CTRL) & E1000_CTRL_RST) == 0) break;
        for (volatile int d = 0; d < 1000; d++) ;
    }

    /* On some VMware e1000 variants force link-up/autospeed enable helps LU bit transition. */
    {
        uint32_t ctrl = e1000_read32(E1000_REG_CTRL);
        ctrl |= (E1000_CTRL_SLU | E1000_CTRL_ASDE);
        e1000_write32(E1000_REG_CTRL, ctrl);
    }

    /* Disable and clear interrupts for polling-mode driver operation. */
    e1000_write32(E1000_REG_IMC, 0xFFFFFFFFu);
    (void)e1000_read32(E1000_REG_ICR);

    if (e1000_read_mac(g_e1000.mac) != 0) {
        klogprintf("e1000: failed to read MAC address\n");
        return -1;
    }

    /* Program receive MAC filter explicitly after reset. */
    {
        uint32_t ral = ((uint32_t)g_e1000.mac[0]) |
                       ((uint32_t)g_e1000.mac[1] << 8) |
                       ((uint32_t)g_e1000.mac[2] << 16) |
                       ((uint32_t)g_e1000.mac[3] << 24);
        uint32_t rah = ((uint32_t)g_e1000.mac[4]) |
                       ((uint32_t)g_e1000.mac[5] << 8) |
                       E1000_RAH_AV;
        e1000_write32(E1000_REG_RAL0, ral);
        e1000_write32(E1000_REG_RAH0, rah);
    }

    if (e1000_setup_tx() != 0 || e1000_setup_rx() != 0) {
        klogprintf("e1000: descriptor ring setup failed\n");
        return -1;
    }

    g_e1000.initialized = 1;
    /* Не ждём link здесь: pit_sleep_ms в контексте первого ping (syscall) на VMware может зависнуть. */
    {
        int link_up = (e1000_read32(E1000_REG_STATUS) & E1000_STATUS_LU) ? 1 : 0;
        klogprintf("e1000: initialized %02x:%02x.%x dev=%04x mac=%02x:%02x:%02x:%02x:%02x:%02x link=%s\n",
                   pdev->bus, pdev->device, pdev->function, pdev->device_id,
                   g_e1000.mac[0], g_e1000.mac[1], g_e1000.mac[2],
                   g_e1000.mac[3], g_e1000.mac[4], g_e1000.mac[5],
                   link_up ? "up" : "down");
    }
    return 0;
}

int e1000_is_ready(void) {
    if (!g_e1000.initialized) return 0;
    return (e1000_read32(E1000_REG_STATUS) & E1000_STATUS_LU) ? 1 : 0;
}

int e1000_get_mac(uint8_t out_mac[6]) {
    if (!g_e1000.initialized || !out_mac) return -1;
    memcpy(out_mac, g_e1000.mac, 6);
    return 0;
}

int e1000_send_frame(const void *data, size_t len) {
    if (!g_e1000.initialized || !data) return -1;
    if (len == 0 || len > E1000_TX_BUF_SIZE) return -1;

    uint32_t tail = e1000_read32(E1000_REG_TDT);
    if (tail >= E1000_TX_DESC_COUNT) tail = 0;
    e1000_tx_desc_t *d = &g_e1000.tx_desc[tail];

    if ((d->status & E1000_TX_STATUS_DD) == 0) {
        g_e1000.stats.tx_errors++;
        return -2; /* ring full/busy */
    }

    size_t wire_len = (len < E1000_ETH_MIN_FRAME) ? E1000_ETH_MIN_FRAME : len;
    memcpy(g_e1000.tx_buf[tail], data, len);
    if (wire_len > len) memset(g_e1000.tx_buf[tail] + len, 0, wire_len - len);

    d->length = (uint16_t)wire_len;
    d->cso = 0;
    d->cmd = E1000_TX_CMD_EOP | E1000_TX_CMD_IFCS | E1000_TX_CMD_RS;
    d->status = 0;
    d->css = 0;
    d->special = 0;

    e1000_write32(E1000_REG_TDT, (tail + 1) % E1000_TX_DESC_COUNT);

    /* Ограниченный спин без pit_sleep_ms: в syscall pit_sleep_ms может зависнуть (timer_ticks не тикает). */
    for (int i = 0; i < 100000; i++) {
        if (d->status & E1000_TX_STATUS_DD) {
            g_e1000.stats.tx_packets++;
            return (int)len;
        }
    }

    g_e1000.stats.tx_errors++;
    return -3; /* timeout */
}

int e1000_recv_frame(void *buf, size_t cap) {
    if (!g_e1000.initialized || !buf || cap == 0) return -1;

    uint32_t rdh = e1000_read32(E1000_REG_RDH);
    /* 8254x: пусто, когда голова совпадает с отданным хвостом (нет нового заполненного дескриптора). */
    if (rdh == g_e1000.rdt_sw) return 0;

    /* Пакет в дескрипторе (RDH - 1), т.к. железо уже сдвинуло RDH вперёд. */
    uint32_t idx = (rdh == 0) ? (E1000_RX_DESC_COUNT - 1) : (rdh - 1);
    e1000_rx_desc_t *d = &g_e1000.rx_desc[idx];
    if ((d->status & E1000_RX_STATUS_DD) == 0) return 0;

    if ((d->status & E1000_RX_STATUS_EOP) == 0) {
        d->status = 0;
        g_e1000.rdt_sw = idx;
        e1000_write32(E1000_REG_RDT, idx);
        g_e1000.stats.rx_errors++;
        return -2;
    }

    size_t frame_len = d->length;
    size_t copy_len = (frame_len > cap) ? cap : frame_len;
    memcpy(buf, g_e1000.rx_buf[idx], copy_len);

    d->status = 0;
    g_e1000.rdt_sw = idx;
    e1000_write32(E1000_REG_RDT, idx);

    g_e1000.stats.rx_packets++;
    return (int)copy_len;
}

void e1000_poll(void) {
    if (!g_e1000.initialized) return;
    (void)e1000_read32(E1000_REG_ICR);
}

int e1000_get_stats(e1000_stats_t *out_stats) {
    if (!g_e1000.initialized || !out_stats) return -1;
    *out_stats = g_e1000.stats;
    return 0;
}