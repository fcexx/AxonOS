#include "rtl8139.h"
#include "pci.h"
#include "heap.h"
#include "string.h"

struct rtl8139_device rtl8139 = {0};

static inline uint8_t inportb(uint16_t port) {
    uint8_t ret;
    asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline uint16_t inportw(uint16_t port) {
    uint16_t ret;
    asm volatile("inw %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline uint32_t inportl(uint16_t port) {
    uint32_t ret;
    asm volatile("inl %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline void outportb(uint16_t port, uint8_t val) {
    asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline void outportw(uint16_t port, uint16_t val) {
    asm volatile("outw %0, %1" : : "a"(val), "Nd"(port));
}

static inline void outportl(uint16_t port, uint32_t val) {
    asm volatile("outl %0, %1" : : "a"(val), "Nd"(port));
}

static uint8_t read_reg8(uint16_t base, uint32_t reg) {
    return inportb(base + reg);
}

static uint16_t read_reg16(uint16_t base, uint32_t reg) {
    return inportw(base + reg);
}

static uint32_t read_reg32(uint16_t base, uint32_t reg) {
    return inportl(base + reg);
}

static void write_reg8(uint16_t base, uint32_t reg, uint8_t value) {
    outportb(base + reg, value);
}

static void write_reg16(uint16_t base, uint32_t reg, uint16_t value) {
    outportw(base + reg, value);
}

static void write_reg32(uint16_t base, uint32_t reg, uint32_t value) {
    outportl(base + reg, value);
}

static void rtl8139_reset(uint16_t base) {
    kprintf("RTL8139: Resetting...\n");
    write_reg8(base, RTL8139_CMD, CMD_RST);
    for(int i = 0; i < 1000000; i++) {
        if(!(read_reg8(base, RTL8139_CMD) & CMD_RST)) {
            break;
        }
    }
    
    kprintf("RTL8139: Reset complete\n");
}

static int rtl8139_init_device(uint16_t base) {
    kprintf("RTL8139: Initializing at I/O base 0x%04x\n", base);
    rtl8139_reset(base);
    rtl8139.rx_buffer = kmalloc(RX_BUFFER_SIZE + 16);
    if(!rtl8139.rx_buffer) {
        kprintf("RTL8139: Failed to allocate RX buffer\n");
        return -1;
    }

    memset(rtl8139.rx_buffer, 0, RX_BUFFER_SIZE + 16);
    rtl8139.rx_buffer_phys = (uint32_t)rtl8139.rx_buffer;
    write_reg32(base, RTL8139_RBSTART, rtl8139.rx_buffer_phys);
    uint32_t rcr = RCR_AAP | RCR_APM | RCR_AM | RCR_AB | RCR_MAX_DMA_UNLIMITED;
    write_reg32(base, RTL8139_RCR, rcr);
    uint32_t tcr = 0x03000000;
    write_reg32(base, RTL8139_TCR, tcr);
    write_reg16(base, RTL8139_IMR, ISR_RX_OK | ISR_TX_OK);
    write_reg16(base, RTL8139_ISR, 0xFFFF);
    write_reg8(base, RTL8139_CMD, CMD_RX_ENABLE | CMD_TX_ENABLE);
    for(int i = 0; i < 6; i++) {
        rtl8139.mac[i] = read_reg8(base, RTL8139_MAC0 + i);
    }
    
    kprintf("RTL8139: MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           rtl8139.mac[0], rtl8139.mac[1], rtl8139.mac[2],
           rtl8139.mac[3], rtl8139.mac[4], rtl8139.mac[5]);
    
    return 0;
}


int rtl8139_init(uint8_t bus, uint8_t slot, uint8_t function) {
    kprintf("RTL8139: Initializing driver at %02x:%02x.%x...\n", bus, slot, function);

    memset(&rtl8139, 0, sizeof(rtl8139));

    uint32_t pci_data = pci_config_read_dword(bus, slot, function, 0);
    uint16_t vendor = pci_data & 0xFFFF;
    uint16_t device = (pci_data >> 16) & 0xFFFF;
    
    kprintf("RTL8139: Vendor: 0x%04x, Device: 0x%04x\n", vendor, device);
    
    if(vendor != 0x10EC || device != 0x8139) {
        kprintf("RTL8139: Not a valid RTL8139 device\n");
        return -1;
    }

    uint16_t command = pci_config_read_word(bus, slot, function, 0x04);
    command |= 0x0007;  // Bus mastering + I/O space + Memory space
    pci_config_write_word(bus, slot, function, 0x04, command);

    uint32_t bar0 = pci_config_read_dword(bus, slot, function, 0x10);
    uint16_t io_base = bar0 & ~0x3;
    
    rtl8139.io_base = io_base;
    rtl8139.bus = bus;
    rtl8139.slot = slot;
    rtl8139.function = function;
    rtl8139.rx_current = 0;
    
    if(rtl8139_init_device(io_base) == 0) {
        rtl8139.initialized = true;
        kprintf("RTL8139: Initialization successful\n");
        return 0;
    }
    
    return -1;
}

void rtl8139_get_mac(uint8_t mac[6]) {
    if(!rtl8139.initialized) {
        memset(mac, 0, 6);
        return;
    }
    memcpy(mac, rtl8139.mac, 6);
}

void rtl8139_send_packet(const uint8_t* data, uint32_t length) {
    if(!rtl8139.initialized || length > TX_BUFFER_SIZE || length == 0) {
        return;
    }
    
    uint16_t base = rtl8139.io_base;

    uint8_t* tx_buffer = kmalloc(length);
    if(!tx_buffer) {
        return;
    }

    memcpy(tx_buffer, data, length);
    uint32_t tx_phys = (uint32_t)tx_buffer;

    write_reg32(base, RTL8139_TSAD0, tx_phys);

    uint32_t tsd = length & 0x1FFF;
    tsd |= (1 << 13);  // OWN бит
    tsd |= (1 << 15);  // EOR (End Of Ring)
    
    write_reg32(base, RTL8139_TSD0, tsd);
    int timeout = 1000000;
    while(timeout-- > 0) {
        uint32_t status = read_reg32(base, RTL8139_TSD0);
        if(!(status & (1 << 13))) {
            break;
        }
    }

    kfree(tx_buffer);
}

uint32_t rtl8139_receive_packet(uint8_t* buffer, uint32_t max_len) {
    if(!rtl8139.initialized) {
        return 0;
    }
    
    uint16_t base = rtl8139.io_base;

    uint16_t isr = read_reg16(base, RTL8139_ISR);
    
    if(isr & ISR_RX_OK) {
        // Очищаем флаг
        write_reg16(base, RTL8139_ISR, ISR_RX_OK);
    } else {
        return 0;
    }
    
    // Получаем текущее положение в буфере
    uint8_t* rx_ptr = (uint8_t*)rtl8139.rx_buffer + rtl8139.rx_current;
    
    // Проверяем наличие пакета
    uint16_t status = *(uint16_t*)rx_ptr;
    uint16_t length = *(uint16_t*)(rx_ptr + 2);
    
    // Проверяем корректность пакета
    if((status & 0x01) && (length <= max_len) && (length > 0)) {
        // Копируем данные
        memcpy(buffer, rx_ptr + 4, length);
        
        // Обновляем указатель
        rtl8139.rx_current = (rtl8139.rx_current + length + 4 + 3) & ~3;
        if(rtl8139.rx_current >= RX_BUFFER_SIZE) {
            rtl8139.rx_current -= RX_BUFFER_SIZE;
        }
        
        return length;
    }
    
    return 0;
}

void rtl8139_dump_registers(void) {
    if(!rtl8139.initialized) {
        kprintf("RTL8139: Not initialized\n");
        return;
    }
    
    uint16_t base = rtl8139.io_base;
    
    kprintf("\nRTL8139 Registers at I/O 0x%04x:\n", base);
    
    kprintf("  MAC:     ");
    for(int i = 0; i < 6; i++) {
        kprintf("%02x ", read_reg8(base, i));
    }
    kprintf("\n");
    
    kprintf("  CMD:     0x%02x\n", read_reg8(base, RTL8139_CMD));
    kprintf("  ISR:     0x%04x\n", read_reg16(base, RTL8139_ISR));
    kprintf("  IMR:     0x%04x\n", read_reg16(base, RTL8139_IMR));
    kprintf("  RCR:     0x%08x\n", read_reg32(base, RTL8139_RCR));
    kprintf("  TCR:     0x%08x\n", read_reg32(base, RTL8139_TCR));
    kprintf("  RBSTART: 0x%08x\n", read_reg32(base, RTL8139_RBSTART));
    kprintf("  TSAD0:   0x%08x\n", read_reg32(base, RTL8139_TSAD0));
    kprintf("  TSD0:    0x%08x\n", read_reg32(base, RTL8139_TSD0));
}

void rtl8139_test(void) {
    kprintf("\nRTL8139 Test\n");
    kprintf("============\n");
    
    if(!rtl8139.initialized) {
        kprintf("RTL8139 not initialized\n");
        return;
    }
    
    // Тест 1: Dump регистров
    kprintf("\n1. Register dump:\n");
    rtl8139_dump_registers();
    
    // Тест 2: MAC адрес
    uint8_t mac[6];
    rtl8139_get_mac(mac);
    kprintf("\n2. MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    // Тест 3: Отправка тестового пакета
    kprintf("\n3. Sending test packet...\n");
    uint8_t test_packet[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        rtl8139.mac[0], rtl8139.mac[1], rtl8139.mac[2],
        rtl8139.mac[3], rtl8139.mac[4], rtl8139.mac[5],
        0x08, 0x06
    };
    
    rtl8139_send_packet(test_packet, sizeof(test_packet));
    kprintf("   Packet sent (%u bytes)\n", sizeof(test_packet));
    
    // Тест 4: Проверка приема
    kprintf("\n4. Checking for received packets...\n");
    uint8_t rx_buffer[1520];
    uint32_t rx_len = rtl8139_receive_packet(rx_buffer, sizeof(rx_buffer));
    if(rx_len > 0) {
        kprintf("   Received packet: %u bytes\n", rx_len);
    } else {
        kprintf("   No packets received\n");
    }
    
    kprintf("\nRTL8139 Test: Complete\n");
}

int rtl8139_command(int argc, char** argv) {
    if(argc < 2) {
        kprint("\nRTL8139 Commands\n");
        kprint("================\n");
        kprint("rtl8139 test    - Run tests\n");
        kprint("rtl8139 dump    - Dump registers\n");
        kprint("rtl8139 mac     - Show MAC address\n");
        kprint("rtl8139 send    - Send test packet\n");
        return 0;
    }
    
    const char* cmd = argv[1];
    
    if(strcmp(cmd, "test") == 0) {
        rtl8139_test();
    }
    else if(strcmp(cmd, "dump") == 0) {
        rtl8139_dump_registers();
    }
    else if(strcmp(cmd, "mac") == 0) {
        if(rtl8139.initialized) {
            uint8_t mac[6];
            rtl8139_get_mac(mac);
            kprintf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        } else {
            kprintf("RTL8139 not initialized\n");
        }
    }
    else if(strcmp(cmd, "send") == 0) {
        if(!rtl8139.initialized) {
            kprintf("RTL8139 not initialized\n");
            return -1;
        }
        
        uint8_t packet[] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            rtl8139.mac[0], rtl8139.mac[1], rtl8139.mac[2],
            rtl8139.mac[3], rtl8139.mac[4], rtl8139.mac[5],
            0x08, 0x00
        };
        
        rtl8139_send_packet(packet, sizeof(packet));
        kprintf("Sent test packet (%u bytes)\n", sizeof(packet));
    }
    else {
        kprintf("Unknown command: %s\n", cmd);
        return -1;
    }
    
    return 0;
}