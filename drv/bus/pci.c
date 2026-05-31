#include <pci.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <apic.h>
#include <apic_timer.h>
#include <sysfs.h>
#include <serial.h>
#include <vga.h>
#include <klog.h>

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

static pci_device_t pci_devices[256];
static int pci_device_count = 0;
static int pci_sysfs_initialized = 0;

static inline uint32_t pci_make_address(uint8_t bus, uint8_t device,
                                       uint8_t function, uint8_t offset)
{
    return (uint32_t)((1U << 31) |
                      ((uint32_t)bus << 16) |
                      ((uint32_t)device << 11) |
                      ((uint32_t)function << 8) |
                      (offset & 0xFC));
}

uint32_t pci_config_read_dword(uint8_t bus, uint8_t device,
                               uint8_t function, uint8_t offset)
{
    uint32_t addr = pci_make_address(bus, device, function, offset);
    outportl(PCI_CONFIG_ADDRESS, addr);
    return inportl(PCI_CONFIG_DATA);
}

void pci_config_write_dword(uint8_t bus, uint8_t device,
                           uint8_t function, uint8_t offset, uint32_t value)
{
    uint32_t addr = pci_make_address(bus, device, function, offset);
    outportl(PCI_CONFIG_ADDRESS, addr);
    outportl(PCI_CONFIG_DATA, value);
}

void pci_init(void)
{
    pci_device_count = 0;

    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t device = 0; device < 32; device++) {
            uint32_t id = pci_config_read_dword((uint8_t)bus, device, 0, 0x00);
            uint16_t vendor = (uint16_t)(id & 0xFFFF);
            if (vendor == 0xFFFF)
                continue;

            uint8_t header_type = (uint8_t)((pci_config_read_dword((uint8_t)bus, device, 0, 0x0C) >> 16) & 0xFF);
            int multifunction = (header_type & 0x80) != 0;
            uint8_t max_functions = multifunction ? 8 : 1;

            for (uint8_t function = 0; function < max_functions; function++) {
                uint32_t dword0 = pci_config_read_dword((uint8_t)bus, device, function, 0x00);
                uint16_t vend = (uint16_t)(dword0 & 0xFFFF);
                if (vend == 0xFFFF)
                    continue;

                pci_device_t *pdev = &pci_devices[pci_device_count];
                pdev->bus = (uint8_t)bus;
                pdev->device = device;
                pdev->function = function;
                pdev->vendor_id = vend;
                pdev->device_id = (uint16_t)((dword0 >> 16) & 0xFFFF);

                uint32_t dword2 = pci_config_read_dword((uint8_t)bus, device, function, 0x08);
                pdev->class_code = (uint8_t)((dword2 >> 24) & 0xFF);
                pdev->subclass = (uint8_t)((dword2 >> 16) & 0xFF);
                pdev->prog_if = (uint8_t)((dword2 >> 8) & 0xFF);

                uint32_t dword3 = pci_config_read_dword((uint8_t)bus, device, function, 0x0C);
                pdev->header_type = (uint8_t)((dword3 >> 16) & 0xFF);

                uint32_t irq_dword = pci_config_read_dword((uint8_t)bus, device, function, 0x3C);
                pdev->irq = (uint8_t)(irq_dword & 0xFF);
                pdev->revision = (uint8_t)(dword2 & 0xFF);

                for (int i = 0; i < 6; i++)
                    pdev->bar[i] = pci_config_read_dword((uint8_t)bus, device, function, 0x10 + i * 4);

                pci_device_count++;
                if (pci_device_count >= (int)(sizeof(pci_devices) / sizeof(pci_devices[0])))
                    return;
            }
        }
    }
}

int pci_get_device_count(void)
{
    return pci_device_count;
}

pci_device_t *pci_get_devices(void)
{
    return pci_devices;
}

pci_device_t *pci_find_device_by_id(uint16_t vendor_id, uint16_t device_id)
{
    for (int i = 0; i < pci_device_count; i++) {
        if (pci_devices[i].vendor_id == vendor_id && pci_devices[i].device_id == device_id)
            return &pci_devices[i];
    }
    return NULL;
}

static void pci_format_slot(const pci_device_t *d, char *slot, size_t slot_sz)
{
    snprintf(slot, slot_sz, "0000:%02x:%02x.%x", d->bus, d->device, d->function);
}

static const char *pci_class_desc(const pci_device_t *d)
{
    uint8_t b = d->class_code;
    uint8_t s = d->subclass;
    if (b == 0x00)
        return "Unclassified device";
    if (b == 0x01) {
        if (s == 0x01) return "IDE interface";
        if (s == 0x06) return "SATA controller";
        if (s == 0x08) return "Non-Volatile memory controller";
        return "Mass storage controller";
    }
    if (b == 0x02 && s == 0x00)
        return "Ethernet controller";
    if (b == 0x03) {
        if (s == 0x00) return "VGA compatible controller";
        if (s == 0x02) return "3D controller";
        return "Display controller";
    }
    if (b == 0x06) {
        if (s == 0x00) return "Host bridge";
        if (s == 0x01) return "ISA bridge";
        if (s == 0x04) return "PCI bridge";
        if (s == 0x09) return "PCI Express bridge";
        return "Bridge";
    }
    if (b == 0x0c && s == 0x03)
        return "USB controller";
    if (b == 0x0c && s == 0x05)
        return "SMBus controller";
    return "PCI device";
}

static int pci_is_pci_bridge(const pci_device_t *d)
{
    uint8_t ht = d->header_type & 0x7f;
    return ht == 1 || (d->class_code == 0x06 &&
                       (d->subclass == 0x04 || d->subclass == 0x09));
}

static uint64_t pci_resource_start_val(uint32_t bar)
{
    if (bar == 0 || bar == 0xFFFFFFFFu)
        return 0;
    if (bar & 1u)
        return (uint64_t)(bar & ~3u);
    return (uint64_t)(bar & ~0xFULL);
}

static void pci_log_bridge_windows(const pci_device_t *d, const char *slot)
{
    for (int i = 0; i < 2; i++) {
        uint32_t bar = d->bar[i];
        if (bar == 0 || bar == 0xFFFFFFFFu)
            continue;
        uint64_t start = pci_resource_start_val(bar);
        uint64_t end = start;
        if (bar & 1u)
            klogprintf("pci %s:   bridge window [io  0x%llx-0x%llx]\n",
                       slot, (unsigned long long)start, (unsigned long long)end);
        else
            klogprintf("pci %s:   bridge window [mem 0x%llx-0x%llx]\n",
                       slot, (unsigned long long)start, (unsigned long long)end);
    }
}

static void pci_log_bridge(const pci_device_t *d)
{
    char slot[20];
    pci_format_slot(d, slot, sizeof(slot));
    uint32_t buses = pci_config_read_dword(d->bus, d->device, d->function, 0x18);
    uint8_t secondary = (uint8_t)((buses >> 8) & 0xFF);
    klogprintf("pci %s: PCI bridge to [bus %02x]\n", slot, secondary);
    pci_log_bridge_windows(d, slot);
}

static void pci_log_irq_routing(const pci_device_t *d)
{
    uint32_t cfg = pci_config_read_dword(d->bus, d->device, d->function, 0x3C);
    uint8_t pin = (uint8_t)((cfg >> 8) & 0xFF);
    if (pin < 1 || pin > 4)
        return;
    if (d->irq != 0 && d->irq != 0xFF)
        return;
    char slot[20];
    pci_format_slot(d, slot, sizeof(slot));
    char intc = (char)('A' + (pin - 1));
    klogprintf("pci %s: can't derive routing for PCI INT %c\n", slot, intc);
    klogprintf("pci %s: PCI INT %c: no GSI\n", slot, intc);
}

static void pci_log_device(const pci_device_t *d)
{
    char slot[20];
    pci_format_slot(d, slot, sizeof(slot));

    if (pci_is_pci_bridge(d)) {
        pci_log_bridge(d);
        return;
    }

    if (d->class_code == 0x03 && d->subclass == 0x00) {
        klogprintf("pci %s: Video device with shadowed ROM at [mem 0x000c0000-0x000dffff]\n",
                   slot);
        pci_log_irq_routing(d);
        return;
    }

    klogprintf("pci %s: [%04x:%04x] %s (rev %02x)\n",
               slot, d->vendor_id, d->device_id,
               pci_class_desc(d), d->revision);
    pci_log_irq_routing(d);
}

ssize_t pci_format_lspci_n_line(char *buf, size_t size, const pci_device_t *d)
{
    if (!buf || size == 0 || !d)
        return 0;
    uint16_t cls = (uint16_t)(((uint16_t)d->class_code << 8) | d->subclass);
    return (ssize_t)snprintf(buf, size,
        "%02x:%02x.%x %04x: %04x:%04x (rev %02x)\n",
        d->bus, d->device, d->function, cls,
        d->vendor_id, d->device_id, d->revision);
}

static uint64_t pci_resource_flags_val(uint32_t bar)
{
    if (bar == 0 || bar == 0xFFFFFFFFu)
        return 0;
    if (bar & 1u)
        return 0x0000000100000001ULL;
    return 0x0000000000000200ULL;
}

ssize_t pci_format_proc_line(char *buf, size_t size, const pci_device_t *d)
{
    if (!buf || size == 0 || !d)
        return 0;
    int devfn = ((int)d->device << 3) | (int)d->function;
    unsigned irq = (d->irq == 0 || d->irq == 0xFF) ? 255u : (unsigned)d->irq;
    int n = snprintf(buf, size, "%02x%02x\t%04x%04x\t%x",
                     d->bus, devfn, d->vendor_id, d->device_id, irq);
    if (n < 0 || (size_t)n >= size)
        return (ssize_t)((n < 0) ? n : (ssize_t)size);
    for (int i = 0; i < 7; i++) {
        uint32_t bar = (i < 6) ? d->bar[i] : 0;
        uint64_t val = pci_resource_start_val(bar) | (pci_resource_flags_val(bar) & 0xFFu);
        int wr = snprintf(buf + n, size - (size_t)n, "\t%016llx",
                          (unsigned long long)val);
        if (wr < 0)
            return wr;
        n += wr;
        if ((size_t)n >= size)
            return (ssize_t)size;
    }
    for (int i = 0; i < 7; i++) {
        int wr = snprintf(buf + n, size - (size_t)n, "\t%016llx", 0ULL);
        if (wr < 0)
            return wr;
        n += wr;
        if ((size_t)n >= size)
            return (ssize_t)size;
    }
    if ((size_t)n + 2 < size) {
        buf[n++] = '\t';
        buf[n++] = '\n';
    }
    return (ssize_t)n;
}

ssize_t pci_show_proc_devices(char *buf, size_t size)
{
    if (!buf || size == 0)
        return 0;
    size_t w = 0;
    pci_device_t *devs = pci_get_devices();
    int count = pci_get_device_count();
    for (int i = 0; i < count && w < size; i++) {
        ssize_t n = pci_format_proc_line(buf + w, size - w, &devs[i]);
        if (n <= 0)
            break;
        w += (size_t)n;
    }
    return (ssize_t)w;
}

void pci_dump_devices(void)
{
    pci_device_t *devs = pci_get_devices();
    int count = pci_get_device_count();
    for (int i = 0; i < count; i++)
        pci_log_device(&devs[i]);
}

static ssize_t sysfs_show_pci_vendor(char *buf, size_t size, void *priv) {
    if (!buf || size == 0 || !priv) return 0;
    pci_device_t *dev = (pci_device_t*)priv;
    return (ssize_t)snprintf(buf, size, "0x%04x\n", dev->vendor_id);
}

static ssize_t sysfs_show_pci_device(char *buf, size_t size, void *priv) {
    if (!buf || size == 0 || !priv) return 0;
    pci_device_t *dev = (pci_device_t*)priv;
    return (ssize_t)snprintf(buf, size, "0x%04x\n", dev->device_id);
}

static ssize_t sysfs_show_pci_class(char *buf, size_t size, void *priv) {
    if (!buf || size == 0 || !priv) return 0;
    pci_device_t *dev = (pci_device_t*)priv;
    uint32_t val = ((uint32_t)dev->class_code << 16) |
                   ((uint32_t)dev->subclass << 8) |
                   ((uint32_t)dev->prog_if);
    return (ssize_t)snprintf(buf, size, "0x%06x\n", val);
}

static ssize_t sysfs_show_pci_irq(char *buf, size_t size, void *priv) {
    if (!buf || size == 0 || !priv) return 0;
    pci_device_t *dev = (pci_device_t*)priv;
    unsigned irq = (dev->irq == 0 || dev->irq == 0xFF) ? 255u : (unsigned)dev->irq;
    return (ssize_t)snprintf(buf, size, "%u\n", irq);
}

struct pci_resource_ctx {
    pci_device_t *dev;
    int index;
};

static ssize_t sysfs_show_pci_resource_one(char *buf, size_t size, void *priv) {
    struct pci_resource_ctx *ctx = (struct pci_resource_ctx*)priv;
    if (!buf || size == 0 || !ctx || !ctx->dev)
        return 0;
    uint32_t bar = (ctx->index >= 0 && ctx->index < 6) ? ctx->dev->bar[ctx->index] : 0;
    uint64_t start = pci_resource_start_val(bar);
    uint64_t flags = pci_resource_flags_val(bar);
    uint64_t end = start;
    return (ssize_t)snprintf(buf, size,
        "0x%016llx 0x%016llx 0x%016llx\n",
        (unsigned long long)start,
        (unsigned long long)end,
        (unsigned long long)flags);
}

static ssize_t sysfs_show_pci_resource(char *buf, size_t size, void *priv) {
    pci_device_t *dev = (pci_device_t*)priv;
    if (!buf || size == 0 || !dev)
        return 0;
    size_t pos = 0;
    for (int i = 0; i < 7; i++) {
        struct pci_resource_ctx ctx = { dev, i < 6 ? i : -1 };
        char line[80];
        ssize_t n = sysfs_show_pci_resource_one(line, sizeof(line), &ctx);
        if (n <= 0)
            break;
        if (pos + (size_t)n > size)
            break;
        memcpy(buf + pos, line, (size_t)n);
        pos += (size_t)n;
    }
    return (ssize_t)pos;
}

static void create_attr_file(const char *base, const char *name, const struct sysfs_attr *attr) {
    char path[96];
    size_t base_len = strlen(base);
    size_t name_len = strlen(name);
    if (base_len + 1 + name_len + 1 > sizeof(path)) return;
    memcpy(path, base, base_len);
    path[base_len] = '/';
    memcpy(path + base_len + 1, name, name_len + 1);
    sysfs_create_file(path, attr);
}

void pci_sysfs_init(void) {
    if (pci_sysfs_initialized) return;
    
    sysfs_mkdir("/sys/bus");
    sysfs_mkdir("/sys/bus/pci");
    sysfs_mkdir("/sys/bus/pci/devices");
    pci_device_t *devs = pci_get_devices();
    int count = pci_get_device_count();
    
    for (int i = 0; i < count; i++) {
        pci_device_t *dev = &devs[i];
        char dir_path[64];
        snprintf(dir_path, sizeof(dir_path), "/sys/bus/pci/devices/0000:%02x:%02x.%x",
                dev->bus, dev->device, dev->function);
        sysfs_mkdir(dir_path);
        struct sysfs_attr vendor = { sysfs_show_pci_vendor, NULL, dev };
        struct sysfs_attr device_attr = { sysfs_show_pci_device, NULL, dev };
        struct sysfs_attr class_attr = { sysfs_show_pci_class, NULL, dev };
        struct sysfs_attr irq_attr = { sysfs_show_pci_irq, NULL, dev };
        struct sysfs_attr resource_attr = { sysfs_show_pci_resource, NULL, dev };
        create_attr_file(dir_path, "vendor", &vendor);
        create_attr_file(dir_path, "device", &device_attr);
        create_attr_file(dir_path, "class", &class_attr);
        create_attr_file(dir_path, "irq", &irq_attr);
        create_attr_file(dir_path, "resource", &resource_attr);
        static struct pci_resource_ctx res_ctx[256][6];
        for (int bar = 0; bar < 6; bar++) {
            if (i >= (int)(sizeof(res_ctx) / sizeof(res_ctx[0])))
                break;
            res_ctx[i][bar].dev = dev;
            res_ctx[i][bar].index = bar;
            char res_name[16];
            snprintf(res_name, sizeof(res_name), "resource%d", bar);
            struct sysfs_attr res_n = { sysfs_show_pci_resource_one, NULL, &res_ctx[i][bar] };
            create_attr_file(dir_path, res_name, &res_n);
        }
    }
    pci_sysfs_initialized = 1;
}