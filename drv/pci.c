#include "../inc/pci.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <apic.h>
#include <apic_timer.h>
#include "../inc/sysfs.h"
#include "../inc/serial.h"
extern void kprintf(const char *fmt, ...);

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

// ==================== Чтение конфигурационного пространства PCI ====================

uint32_t pci_config_read_dword(uint8_t bus, uint8_t device,
                               uint8_t function, uint8_t offset)
{
    uint32_t addr = pci_make_address(bus, device, function, offset);
    outportl(PCI_CONFIG_ADDRESS, addr);
    return inportl(PCI_CONFIG_DATA);
}

// ДОБАВЛЕНО: Чтение 16-битного слова из конфигурационного пространства PCI
uint16_t pci_config_read_word(uint8_t bus, uint8_t device,
                              uint8_t function, uint8_t offset)
{
    // Читаем полное 32-битное значение
    uint32_t dword = pci_config_read_dword(bus, device, function, offset & 0xFC);
    
    // Извлекаем нужное 16-битное слово
    if (offset & 0x02) {
        // Верхнее слово (биты 16-31)
        return (uint16_t)(dword >> 16);
    } else {
        // Нижнее слово (биты 0-15)
        return (uint16_t)dword;
    }
}

// ДОБАВЛЕНО: Чтение 8-битного байта из конфигурационного пространства PCI
uint8_t pci_config_read_byte(uint8_t bus, uint8_t device,
                             uint8_t function, uint8_t offset)
{
    // Читаем полное 32-битное значение
    uint32_t dword = pci_config_read_dword(bus, device, function, offset & 0xFC);
    
    // Извлекаем нужный байт
    switch (offset & 0x03) {
        case 0: return (uint8_t)(dword & 0xFF);
        case 1: return (uint8_t)((dword >> 8) & 0xFF);
        case 2: return (uint8_t)((dword >> 16) & 0xFF);
        case 3: return (uint8_t)((dword >> 24) & 0xFF);
    }
    return 0;
}

void pci_config_write_dword(uint8_t bus, uint8_t device,
                           uint8_t function, uint8_t offset, uint32_t value)
{
    uint32_t addr = pci_make_address(bus, device, function, offset);
    outportl(PCI_CONFIG_ADDRESS, addr);
    outportl(PCI_CONFIG_DATA, value);
}

// ==================== Инициализация PCI ====================

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

// ==================== Утилиты PCI ====================

// ДОБАВЛЕНО: Получение типа BAR (IO или MMIO)
int pci_bar_is_io(uint32_t bar) {
    return (bar & 0x1) != 0;
}

// ДОБАВЛЕНО: Получение адреса из BAR
uintptr_t pci_bar_get_address(uint32_t bar) {
    if (bar & 0x1) {
        // IO порт
        return bar & ~0x3;
    } else {
        // MMIO
        return bar & ~0xF;
    }
}

// ДОБАВЛЕНО: Получение размера BAR
uint32_t pci_bar_get_size(uint8_t bus, uint8_t device, uint8_t function, int bar_num) {
    uint32_t bar = pci_config_read_dword(bus, device, function, 0x10 + bar_num * 4);
    if (bar == 0 || bar == 0xFFFFFFFF) {
        return 0;
    }
    
    // Сохраняем оригинальное значение
    pci_config_write_dword(bus, device, function, 0x10 + bar_num * 4, 0xFFFFFFFF);
    
    // Читаем размер
    uint32_t size_mask = pci_config_read_dword(bus, device, function, 0x10 + bar_num * 4);
    
    // Восстанавливаем оригинальное значение
    pci_config_write_dword(bus, device, function, 0x10 + bar_num * 4, bar);
    
    // Обрабатываем IO порты
    if (bar & 0x1) {
        size_mask &= ~0x3;
        size_mask = ~size_mask + 1;
        return size_mask & 0xFFFF;
    }
    
    // Обрабатываем MMIO
    size_mask &= ~0xF;
    size_mask = ~size_mask + 1;
    return size_mask;
}

// ДОБАВЛЕНО: Поиск всех устройств по vendor ID
int pci_find_devices_by_vendor(uint16_t vendor_id, pci_device_t** result, int max_results) {
    int found = 0;
    for (int i = 0; i < pci_device_count && found < max_results; i++) {
        if (pci_devices[i].vendor_id == vendor_id) {
            result[found++] = &pci_devices[i];
        }
    }
    return found;
}

// ДОБАВЛЕНО: Поиск устройств по классу
int pci_find_devices_by_class(uint8_t class_code, uint8_t subclass, pci_device_t** result, int max_results) {
    int found = 0;
    for (int i = 0; i < pci_device_count && found < max_results; i++) {
        if (pci_devices[i].class_code == class_code && pci_devices[i].subclass == subclass) {
            result[found++] = &pci_devices[i];
        }
    }
    return found;
}

// ДОБАВЬТЕ в pci.c после функции pci_config_read_byte:

// Запись 16-битного слова в конфигурационное пространство PCI
void pci_config_write_word(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset, uint16_t value) {
    // Читаем текущее 32-битное значение
    uint32_t dword = pci_config_read_dword(bus, device, function, offset & 0xFC);
    
    // Изменяем нужное 16-битное слово
    if (offset & 0x02) {
        // Верхнее слово (биты 16-31)
        dword = (dword & 0x0000FFFF) | ((uint32_t)value << 16);
    } else {
        // Нижнее слово (биты 0-15)
        dword = (dword & 0xFFFF0000) | (uint32_t)value;
    }
    
    // Записываем обратно
    pci_config_write_dword(bus, device, function, offset & 0xFC, dword);
}

// Запись 8-битного байта в конфигурационное пространство PCI
void pci_config_write_byte(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset, uint8_t value) {
    // Читаем текущее 32-битное значение
    uint32_t dword = pci_config_read_dword(bus, device, function, offset & 0xFC);
    
    // Изменяем нужный байт
    switch (offset & 0x03) {
        case 0:
            dword = (dword & 0xFFFFFF00) | (uint32_t)value;
            break;
        case 1:
            dword = (dword & 0xFFFF00FF) | ((uint32_t)value << 8);
            break;
        case 2:
            dword = (dword & 0xFF00FFFF) | ((uint32_t)value << 16);
            break;
        case 3:
            dword = (dword & 0x00FFFFFF) | ((uint32_t)value << 24);
            break;
    }
    
    // Записываем обратно
    pci_config_write_dword(bus, device, function, offset & 0xFC, dword);
}

void pci_dump_devices(void)
{
    pci_device_t *devs = pci_get_devices();
    for (int i = 0; i < pci_get_device_count(); i++) {
        pci_device_t *d = &devs[i];
        if (d->irq == 0)
            kprintf("PCI %u.%u.%u: vendor=%04x device=%04x class=%02x/%02x prog_if=%02x hdr=%02x irq=N/A\n",
                    d->bus, d->device, d->function,
                    d->vendor_id, d->device_id,
                    d->class_code, d->subclass, d->prog_if,
                    d->header_type);
        else
            kprintf("PCI %u.%u.%u: vendor=%04x device=%04x class=%02x/%02x prog_if=%02x hdr=%02x irq=%u\n",
                    d->bus, d->device, d->function,
                    d->vendor_id, d->device_id,
                    d->class_code, d->subclass, d->prog_if,
                    d->header_type, d->irq);
        
        // ДОБАВЛЕНО: Вывод BAR информации
        for (int bar = 0; bar < 6; bar++) {
            if (d->bar[bar] != 0 && d->bar[bar] != 0xFFFFFFFF) {
                if (d->bar[bar] & 0x1) {
                    kprintf("    BAR%d: IO port 0x%04x\n", bar, d->bar[bar] & ~0x3);
                } else {
                    kprintf("    BAR%d: MMIO 0x%08x", bar, d->bar[bar] & ~0xF);
                    if (d->bar[bar] & 0x4) kprintf(" (64-bit)");
                    if (d->bar[bar] & 0x2) kprintf(" (prefetchable)");
                    kprintf("\n");
                }
            }
        }
    }
}

// ==================== SysFS поддержка ====================

static char hex_digit(uint8_t v) {
    return (v < 10) ? ('0' + v) : ('a' + (v - 10));
}

static size_t write_hex_prefixed(char *buf, size_t size, uint32_t value, int digits) {
    if (!buf || size < 3) return 0;
    if (digits > (int)(size - 2)) digits = (int)size - 2;
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < digits; i++) {
        int shift = (digits - 1 - i) * 4;
        buf[2 + i] = hex_digit((value >> shift) & 0xF);
    }
    return (size_t)(digits + 2);
}

static ssize_t sysfs_show_pci_vendor(char *buf, size_t size, void *priv) {
    if (!buf || size == 0 || !priv) return 0;
    pci_device_t *dev = (pci_device_t*)priv;
    size_t n = write_hex_prefixed(buf, size, dev->vendor_id, 4);
    if (n < size) buf[n++] = '\n';
    return (ssize_t)n;
}

static ssize_t sysfs_show_pci_device(char *buf, size_t size, void *priv) {
    if (!buf || size == 0 || !priv) return 0;
    pci_device_t *dev = (pci_device_t*)priv;
    size_t n = write_hex_prefixed(buf, size, dev->device_id, 4);
    if (n < size) buf[n++] = '\n';
    return (ssize_t)n;
}

static ssize_t sysfs_show_pci_class(char *buf, size_t size, void *priv) {
    if (!buf || size == 0 || !priv) return 0;
    pci_device_t *dev = (pci_device_t*)priv;
    uint32_t val = ((uint32_t)dev->class_code << 16) |
                   ((uint32_t)dev->subclass << 8) |
                   ((uint32_t)dev->prog_if);
    size_t n = write_hex_prefixed(buf, size, val, 6);
    if (n < size) buf[n++] = '\n';
    return (ssize_t)n;
}

static ssize_t sysfs_show_pci_irq(char *buf, size_t size, void *priv) {
    if (!buf || size == 0 || !priv) return 0;
    pci_device_t *dev = (pci_device_t*)priv;
    if (dev->irq == 0xFF || dev->irq == 0) {
        const char *txt = "N/A\n";
        size_t len = strlen(txt);
        if (len > size) len = size;
        memcpy(buf, txt, len);
        return (ssize_t)len;
    }
    unsigned int irq = dev->irq;
    char tmp[4];
    size_t n = 0;
    do {
        tmp[n++] = (char)('0' + (irq % 10));
        irq /= 10;
    } while (irq && n < sizeof(tmp));
    size_t written = 0;
    while (n && written < size) buf[written++] = tmp[--n];
    if (written < size) buf[written++] = '\n';
    return (ssize_t)written;
}

static ssize_t sysfs_show_pci_bars(char *buf, size_t size, void *priv) {
    if (!buf || size == 0 || !priv) return 0;
    pci_device_t *dev = (pci_device_t*)priv;
    size_t pos = 0;
    for (int i = 0; i < 6; i++) {
        if (pos + 5 >= size) break;
        buf[pos++] = 'b';
        buf[pos++] = 'a';
        buf[pos++] = 'r';
        buf[pos++] = '0' + i;
        buf[pos++] = '=';
        size_t n = write_hex_prefixed(buf + pos, size - pos, dev->bar[i], 8);
        pos += n;
        if (pos < size) buf[pos++] = (i == 5) ? '\n' : ' ';
    }
    if (pos > 0 && buf[pos-1] != '\n' && pos < size) buf[pos++] = '\n';
    return (ssize_t)pos;
}

static void format_pci_device_dir(char *buf, size_t size, const pci_device_t *dev) {
    const char prefix[] = "/sys/bus/pci/devices/";
    size_t len = strlen(prefix);
    if (size <= len + 8) {
        if (size) buf[0] = '\0';
        return;
    }
    memcpy(buf, prefix, len);
    char *p = buf + len;
    *p++ = hex_digit(dev->bus >> 4);
    *p++ = hex_digit(dev->bus & 0xF);
    *p++ = ':';
    *p++ = hex_digit(dev->device >> 4);
    *p++ = hex_digit(dev->device & 0xF);
    *p++ = '.';
    *p++ = (char)('0' + (dev->function % 10));
    *p = '\0';
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
        snprintf(dir_path, sizeof(dir_path), "/sys/bus/pci/devices/%02x:%02x.%x", 
                dev->bus, dev->device, dev->function);        
        sysfs_mkdir(dir_path);
        struct sysfs_attr vendor = { sysfs_show_pci_vendor, NULL, dev };
        struct sysfs_attr device_attr = { sysfs_show_pci_device, NULL, dev };
        struct sysfs_attr class_attr = { sysfs_show_pci_class, NULL, dev };
        struct sysfs_attr irq_attr = { sysfs_show_pci_irq, NULL, dev };
        struct sysfs_attr bars_attr = { sysfs_show_pci_bars, NULL, dev };
        create_attr_file(dir_path, "vendor", &vendor);
        create_attr_file(dir_path, "device", &device_attr);
        create_attr_file(dir_path, "class", &class_attr);
        create_attr_file(dir_path, "irq", &irq_attr);
        create_attr_file(dir_path, "bars", &bars_attr);
    }
    pci_sysfs_initialized = 1;
}