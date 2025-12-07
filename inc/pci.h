#pragma once

#include <stdint.h>

/**
 * struct pci_device - simple PCI device descriptor
 * @bus: PCI bus number
 * @device: PCI device number
 * @function: PCI function number
 * @vendor_id: PCI vendor ID
 * @device_id: PCI device ID
 * @class_code: device class code
 * @subclass: device subclass code
 * @prog_if: programming interface
 * @header_type: header type from config space
 * @irq: interrupt line (INTx)
 * @bar: Base Address Registers (raw values)
 *
 * Minimal descriptor filled by pci_init().
 */
typedef struct pci_device {
    uint8_t bus;
    uint8_t device;
    uint8_t function;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t class_code;
    uint8_t subclass;
    uint8_t prog_if;
    uint8_t header_type;
    uint8_t irq;
    uint32_t bar[6];
} pci_device_t;

/*
 * pci_init - enumerate PCI buses and populate internal device list
 */
void pci_init(void);
void pci_sysfs_init(void);

/*
 * pci_config_read_dword/pci_config_write_dword - access PCI config space
 * @bus/@device/@function: address of the device
 * @offset: dword-aligned offset within config space
 */
uint32_t pci_config_read_dword(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset);
void pci_config_write_dword(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset, uint32_t value);

/*
 * pci_get_device_count/pci_get_devices - access enumerated device list
 */
int pci_get_device_count(void);
pci_device_t *pci_get_devices(void);

/*
 * pci_find_device_by_id - find first device matching vendor/device id
 */
pci_device_t *pci_find_device_by_id(uint16_t vendor_id, uint16_t device_id);

uint16_t pci_config_read_word(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset);
void pci_config_write_word(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset, uint16_t value);
uint8_t pci_config_read_byte(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset);