#include <intel_chipset.h>
#include <pci.h>
#include <axonos.h>
#include <stdint.h>
#include <serial.h>
#include <heap.h>
#include <stddef.h>


static intel_chipset_t intel_chipset;
static int intel_detected = 0;


static const struct {
    uint16_t device_id;
    const char* name;
    uint16_t features;
    uint8_t usb_ports;
    uint8_t sata_ports;
} intel_chipsets[] = {
    {0x7000, "Intel 82371SB PIIX3", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB, 2, 2},
    {0x2410, "Intel 82801AA (ICH)", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB, 2, 2},
    {0x2420, "Intel 82801AB (ICH0)", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB, 2, 2},
    {0x2440, "Intel 82801BA (ICH2)", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB, 4, 2},
    {0x2480, "Intel 82801CA (ICH3)", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB, 4, 2},
    {0x24C0, "Intel 82801DB (ICH4)", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB, 6, 2},
    {0x24D0, "Intel 82801EB (ICH5)", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB | INTEL_FEATURE_SATA, 8, 2},
    {0x2660, "Intel 82801FB (ICH6)", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB | INTEL_FEATURE_SATA | INTEL_FEATURE_HD_AUDIO, 8, 4},
    {0x27B0, "Intel 82801GB (ICH7)", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB | INTEL_FEATURE_SATA | INTEL_FEATURE_POWER_MGMT | INTEL_FEATURE_HD_AUDIO, 8, 4},
    {0x2810, "Intel 82801HB (ICH8)", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB | INTEL_FEATURE_SATA | INTEL_FEATURE_POWER_MGMT | INTEL_FEATURE_HD_AUDIO, 10, 6},
    {0x2910, "Intel 82801IB (ICH9)", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB | INTEL_FEATURE_SATA | INTEL_FEATURE_POWER_MGMT | INTEL_FEATURE_HD_AUDIO, 12, 6},
    {0x3A10, "Intel 82801JI (ICH10)", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB | INTEL_FEATURE_SATA | INTEL_FEATURE_POWER_MGMT | INTEL_FEATURE_SMBUS | INTEL_FEATURE_HD_AUDIO, 12, 6},
    {0x3B00, "Intel PCH", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB | INTEL_FEATURE_SATA | INTEL_FEATURE_POWER_MGMT | INTEL_FEATURE_SMBUS | INTEL_FEATURE_HD_AUDIO, 14, 6},
    {0x8C00, "Intel Z97", INTEL_FEATURE_ACPI | INTEL_FEATURE_USB | INTEL_FEATURE_SATA | INTEL_FEATURE_POWER_MGMT | INTEL_FEATURE_SMBUS | INTEL_FEATURE_HD_AUDIO, 14, 6},
    {0, NULL, 0, 0, 0}
};


static const char* intel_get_chipset_name(uint16_t device_id) {
    for (int i = 0; intel_chipsets[i].device_id != 0; i++) {
        if (intel_chipsets[i].device_id == device_id) {
            return intel_chipsets[i].name;
        }
    }
    return "Unknown Intel Chipset";
}


uint32_t intel_pci_read_config(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset) {
    return pci_config_read_dword(bus, dev, func, offset);
}


void intel_pci_write_config(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset, uint32_t value) {
    pci_config_write_dword(bus, dev, func, offset, value);
}


static void intel_enable_device(intel_device_t* dev) {
    if (!dev) return;


    uint32_t command = intel_pci_read_config(dev->bus, dev->device, dev->function, 0x04);
    command |= 0x0007;
    intel_pci_write_config(dev->bus, dev->device, dev->function, 0x04, command);
}


static intel_device_t* intel_create_device(pci_device_t* pci_dev, const char* name) {
    intel_device_t* dev = (intel_device_t*)kmalloc(sizeof(intel_device_t));
    if (!dev) return NULL;


    memset(dev, 0, sizeof(intel_device_t));
    dev->bus = pci_dev->bus;
    dev->device = pci_dev->device;
    dev->function = pci_dev->function;
    dev->vendor_id = pci_dev->vendor_id;
    dev->device_id = pci_dev->device_id;
    dev->class_code = pci_dev->class_code;
    dev->subclass = pci_dev->subclass;
    dev->prog_if = pci_dev->prog_if;
    dev->header_type = pci_dev->header_type;
    dev->irq = pci_dev->irq;
    dev->name = name;


    for (int i = 0; i < 6; i++) {
        dev->bar[i] = pci_dev->bar[i];
    }


    return dev;
}


int intel_detect_chipset(void) {
    if (intel_detected) return 1;


    memset(&intel_chipset, 0, sizeof(intel_chipset_t));


    int device_count = pci_get_device_count();
    pci_device_t* devices = pci_get_devices();


    kprintf("Intel: Scanning for Intel chipsets...\n");


    int intel_devices = 0;
    for (int i = 0; i < device_count; i++) {
        pci_device_t* pci_dev = &devices[i];


        if (pci_dev->vendor_id != INTEL_VENDOR_ID) continue;


        intel_devices++;


        switch (pci_dev->class_code) {
            case 0x06:
                if (pci_dev->subclass == 0x01 && !intel_chipset.lpc_controller) {
                    intel_chipset.lpc_controller = intel_create_device(pci_dev, "Intel LPC");
                    if (intel_chipset.lpc_controller) {
                        for (int j = 0; intel_chipsets[j].device_id != 0; j++) {
                            if (intel_chipsets[j].device_id == pci_dev->device_id) {
                                intel_chipset.supported_features = intel_chipsets[j].features;
                                intel_chipset.usb_ports = intel_chipsets[j].usb_ports;
                                intel_chipset.sata_ports = intel_chipsets[j].sata_ports;
                                intel_chipset.chipset_name = intel_chipsets[j].name;
                                kprintf("Intel: Found %s chipset\n", intel_chipset.chipset_name);
                                break;
                            }
                        }
                    }
                }
                break;


            case 0x0C:
                if (pci_dev->subclass == 0x03 && !intel_chipset.usb_controller) {
                    intel_chipset.usb_controller = intel_create_device(pci_dev, "Intel USB");
                }
                break;


            case 0x01:
                if (pci_dev->subclass == 0x06 && !intel_chipset.sata_controller) {
                    intel_chipset.sata_controller = intel_create_device(pci_dev, "Intel SATA");
                }
                break;


            case 0x02:
                if (!intel_chipset.ethernet_controller) {
                    intel_chipset.ethernet_controller = intel_create_device(pci_dev, "Intel Ethernet");
                }
                break;


            case 0x03:
                if (!intel_chipset.graphics_controller) {
                    intel_chipset.graphics_controller = intel_create_device(pci_dev, "Intel Graphics");
                }
                break;


            case 0x04:
                if (pci_dev->subclass == 0x03 && !intel_chipset.audio_controller) {
                    intel_chipset.audio_controller = intel_create_device(pci_dev, "Intel Audio");
                }
                break;
        }
    }


    intel_detected = (intel_chipset.lpc_controller != NULL);


    if (intel_detected) {
        kprintf("Intel: Chipset initialized (%d Intel devices found)\n", intel_devices);
    } else {
        kprintf("Intel: No Intel chipset found\n");
    }


    return intel_detected;
}


static void intel_enable_acpi(void) {
    if (!intel_chipset.lpc_controller) return;


    uint32_t acpi_cntl = intel_pci_read_config(
        intel_chipset.lpc_controller->bus,
        intel_chipset.lpc_controller->device,
        intel_chipset.lpc_controller->function,
        INTEL_LPC_ACPI_CNTL
    );


    acpi_cntl |= INTEL_PM_ACPI_ENABLE;


    intel_pci_write_config(
        intel_chipset.lpc_controller->bus,
        intel_chipset.lpc_controller->device,
        intel_chipset.lpc_controller->function,
        INTEL_LPC_ACPI_CNTL,
        acpi_cntl
    );
}


static void intel_enable_power_management(void) {
    if (!intel_chipset.lpc_controller) return;


    uint32_t pm_cntl = intel_pci_read_config(
        intel_chipset.lpc_controller->bus,
        intel_chipset.lpc_controller->device,
        intel_chipset.lpc_controller->function,
        INTEL_LPC_PM1_CNT
    );


    pm_cntl |= INTEL_PM_SUSPEND_ENABLE;


    intel_pci_write_config(
        intel_chipset.lpc_controller->bus,
        intel_chipset.lpc_controller->device,
        intel_chipset.lpc_controller->function,
        INTEL_LPC_PM1_CNT,
        pm_cntl
    );
}


static void intel_setup_usb_controllers(void) {
    if (intel_chipset.usb_controller) {
        intel_enable_device(intel_chipset.usb_controller);
    }
}


static void intel_setup_sata_controllers(void) {
    if (intel_chipset.sata_controller) {
        intel_enable_device(intel_chipset.sata_controller);
    }
}


static void intel_setup_audio_controller(void) {
    if (intel_chipset.audio_controller) {
        intel_enable_device(intel_chipset.audio_controller);
    }
}


static void intel_setup_smbus(void) {
    if (!intel_chipset.lpc_controller) return;


    if (intel_chipset.supported_features & INTEL_FEATURE_SMBUS) {
        uint32_t smb_base = intel_pci_read_config(
            intel_chipset.lpc_controller->bus,
            intel_chipset.lpc_controller->device,
            intel_chipset.lpc_controller->function,
            INTEL_LPC_SMB_BASE
        );


        if (!(smb_base & 0x01)) {
            smb_base = 0xEFA0 | 0x01;
            intel_pci_write_config(
                intel_chipset.lpc_controller->bus,
                intel_chipset.lpc_controller->device,
                intel_chipset.lpc_controller->function,
                INTEL_LPC_SMB_BASE,
                smb_base
            );
        }
    }
}


void intel_chipset_reset(void) {
    outb(0xCF9, 0x0E);


    asm volatile ("cli");
    while ((inb(0x64) & 0x02) != 0);
    outb(0x64, 0xFE);
    asm volatile ("hlt");
}


void intel_print_chipset_info(void) {
    if (!intel_detected) {
        kprintf("Intel chipset not detected\n");
        return;
    }


    if (intel_chipset.chipset_name) {
        kprintf("Chipset: %s\n", intel_chipset.chipset_name);
    }


    if (intel_chipset.lpc_controller) {
        kprintf("LPC: %04X:%04X\n", 
               intel_chipset.lpc_controller->vendor_id,
               intel_chipset.lpc_controller->device_id);
    }


    if (intel_chipset.usb_controller) {
        kprintf("USB: %d ports\n", intel_chipset.usb_ports);
    }


    if (intel_chipset.sata_controller) {
        kprintf("SATA: %d ports\n", intel_chipset.sata_ports);
    }


    if (intel_chipset.ethernet_controller) {
        kprintf("Ethernet: Present\n");
    }


    if (intel_chipset.graphics_controller) {
        kprintf("Graphics: Present\n");
    }


    if (intel_chipset.audio_controller) {
        kprintf("Audio: Present\n");
    }


    kprintf("Features: ");
    if (intel_chipset.supported_features & INTEL_FEATURE_ACPI) kprintf("ACPI ");
    if (intel_chipset.supported_features & INTEL_FEATURE_USB) kprintf("USB ");
    if (intel_chipset.supported_features & INTEL_FEATURE_SATA) kprintf("SATA ");
    if (intel_chipset.supported_features & INTEL_FEATURE_ETHERNET) kprintf("ETH ");
    if (intel_chipset.supported_features & INTEL_FEATURE_POWER_MGMT) kprintf("PM ");
    if (intel_chipset.supported_features & INTEL_FEATURE_SMBUS) kprintf("SMBus ");
    if (intel_chipset.supported_features & INTEL_FEATURE_HD_AUDIO) kprintf("HDA");
    kprintf("\n");
}


void intel_chipset_init(void) {
    if (intel_detected) return;


    if (!intel_detect_chipset()) {
        return;
    }


    if (intel_chipset.supported_features & INTEL_FEATURE_ACPI) {
        intel_enable_acpi();
    }


    if (intel_chipset.supported_features & INTEL_FEATURE_POWER_MGMT) {
        intel_enable_power_management();
    }


    if (intel_chipset.supported_features & INTEL_FEATURE_USB) {
        intel_setup_usb_controllers();
    }


    if (intel_chipset.supported_features & INTEL_FEATURE_SATA) {
        intel_setup_sata_controllers();
    }


    if (intel_chipset.supported_features & INTEL_FEATURE_SMBUS) {
        intel_setup_smbus();
    }


    if (intel_chipset.supported_features & INTEL_FEATURE_HD_AUDIO) {
        intel_setup_audio_controller();
    }


}


int intel_is_detected(void) {
    return intel_detected;
}


intel_chipset_t* intel_get_chipset(void) {
    return intel_detected ? &intel_chipset : NULL;
}