#include "mmio.h"
#include "string.h"

void mmio_init(void) {}

static uint32_t parse_hex(const char* str) {
    if (!str) return 0;
    
    while (*str == ' ' || *str == '\t') str++;
    
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        str += 2;
    }
    
    uint32_t result = 0;
    while (*str) {
        char c = *str;
        uint8_t digit;
        
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else break;
        
        result = (result << 4) | digit;
        str++;
    }
    
    return result;
}

int mmio_command(int argc, char** argv) {
    if (argc < 2) {
        kprint("\nMMIO Commands (simplified for RTL8139 driver)\n");
        kprint("===========================================\n");
        kprint("mmio read <addr>    - Read 32-bit value\n");
        kprint("mmio read16 <addr>  - Read 16-bit value\n");
        kprint("mmio read8 <addr>   - Read 8-bit value\n");
        kprint("mmio write <addr> <value>  - Write 32-bit value\n");
        kprint("mmio write16 <addr> <value> - Write 16-bit value\n");
        kprint("mmio write8 <addr> <value> - Write 8-bit value\n");
        kprint("\nExamples:\n");
        kprint("  mmio read 0xB8000\n");
        kprint("  mmio write16 0xB8000 0x1F41\n");
        kprint("\n");
        return 0;
    }
    
    const char* cmd = argv[1];
    
    if (strcmp(cmd, "read") == 0 && argc >= 3) {
        uintptr_t addr = parse_hex(argv[2]);
        uint32_t value = mmio_read32(addr);
        kprintf("0x%08x: 0x%08x\n", addr, value);
    }
    else if (strcmp(cmd, "read16") == 0 && argc >= 3) {
        uintptr_t addr = parse_hex(argv[2]);
        uint16_t value = mmio_read16(addr);
        kprintf("0x%08x: 0x%04x\n", addr, value);
    }
    else if (strcmp(cmd, "read8") == 0 && argc >= 3) {
        uintptr_t addr = parse_hex(argv[2]);
        uint8_t value = mmio_read8(addr);
        kprintf("0x%08x: 0x%02x\n", addr, value);
    }
    else if (strcmp(cmd, "write") == 0 && argc >= 4) {
        uintptr_t addr = parse_hex(argv[2]);
        uint32_t value = parse_hex(argv[3]);
        mmio_write32(addr, value);
        kprintf("Wrote 0x%08x to 0x%08x\n", value, addr);
    }
    else if (strcmp(cmd, "write16") == 0 && argc >= 4) {
        uintptr_t addr = parse_hex(argv[2]);
        uint32_t value = parse_hex(argv[3]);
        mmio_write16(addr, value & 0xFFFF);
        kprintf("Wrote 0x%04x to 0x%08x\n", value & 0xFFFF, addr);
    }
    else if (strcmp(cmd, "write8") == 0 && argc >= 4) {
        uintptr_t addr = parse_hex(argv[2]);
        uint32_t value = parse_hex(argv[3]);
        mmio_write8(addr, value & 0xFF);
        kprintf("Wrote 0x%02x to 0x%08x\n", value & 0xFF, addr);
    }
    else {
        kprintf("Unknown command: %s\n", cmd);
        return -1;
    }
    
    return 0;
}