#include <stdint.h>
#include <serial.h>

unsigned char   inb(unsigned short port)
{
    unsigned char result;
	__asm__("in %%dx, %%al" : "=a" (result) : "d" (port));
    return (result);
}


void    outb(unsigned short port, unsigned char data)
{
	__asm__("out %%al, %%dx" : : "a" (data), "d" (port));
}


unsigned char   inw(unsigned short port)
{
    unsigned short result;
    __asm__("in %%dx, %%ax" : "=a" (result) : "d" (port));
    return (result);
}


void outw(unsigned short port, unsigned short data)
{
    __asm__("out %%ax, %%dx" : : "a" (data), "d" (port));
}

void insw(uint16_t port, void *addr, unsigned long count)
{
    asm volatile ("cld; rep insw"
                  : "+D" (addr), "+c" (count)
                  : "d" (port)
                  : "memory");
}

void outsw(uint16_t port, const void *addr, unsigned long count)
{
    asm volatile ("cld; rep outsw"
                  : "+S" (addr), "+c" (count)
                  : "d" (port)
                  : "memory");
}

void insb(uint16_t port, void *addr, unsigned long count) {
    // Use assembler to perform the input operation
    asm volatile (
        "cld; rep insb"  // cld - sets the reading direction in memory
        : "+D" (addr), "+c" (count)  // Specify that addr and count will be changed
        : "d" (port)  // Specify the port from which we will read
        : "memory"  // Specify that the memory can be changed
    );
}

void reboot_system() {
    uint8_t good = 0x02;
    while (good & 0x02)
        good = inb(0x64);
    outb(0x64, 0xFE);
    __asm__ volatile ("hlt");
}

void shutdown_system() {
    // ACPI method
    outw(0xB004, 0x2000);

    // APM method
    outw(0x604, 0x2000);

    // If the previous methods did not work, try the Bochs/QEMU method
    outw(0x4004, 0x3400);

    // If nothing worked, just loop
    while(1) {
        __asm__ volatile ("hlt");
    }
}
uint32_t inportl(uint16_t _port) {
    uint32_t rv;
    asm volatile ("inl %%dx, %%eax" : "=a" (rv) : "dN" (_port));
    return rv;
}
/*
 * Read 2 bytes
 * */
uint16_t inports(uint16_t _port) {
    uint16_t rv;
    asm volatile ("inw %1, %0" : "=a" (rv) : "dN" (_port));
    return rv;
}

void outports(uint16_t _port, uint16_t _data) {
    asm volatile ("outw %1, %0" : : "dN" (_port), "a" (_data));
}

/*
 * Write 4 bytes
 * */
void outportl(uint16_t _port, uint32_t _data) {
    asm volatile ("outl %%eax, %%dx" : : "dN" (_port), "a" (_data));
}