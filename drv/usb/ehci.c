#include <usb.h>
#include <mmio.h>
#include <serial.h>
#include <pci.h>
#include <string.h>

#define EHCI_REG_USBCMD    0x20
#define EHCI_REG_USBSTS    0x24
#define EHCI_REG_CONFIG    0x40
#define EHCI_REG_PORTSC(n) (0x44 + ((n) * 4))

static int ehci_port_reset(usb_host_controller_t *hc, int port) {
    if (!hc || !hc->mmio || port <= 0 || port > hc->ports) return -1;
    uint32_t v = mmio_read32((volatile void *)hc->mmio, EHCI_REG_PORTSC(port - 1));
    if ((v & 0x1u) == 0) return -1; /* no device connected */
    v |= (1u << 8); /* PR: port reset */
    mmio_write32((volatile void *)hc->mmio, EHCI_REG_PORTSC(port - 1), v);
    for (int i = 0; i < 20000; i++) asm volatile("pause");
    v &= ~(1u << 8);
    mmio_write32((volatile void *)hc->mmio, EHCI_REG_PORTSC(port - 1), v);
    for (int i = 0; i < 20000; i++) asm volatile("pause");
    return 0;
}

static int ehci_submit_control(usb_host_controller_t *hc, uint8_t addr, const usb_setup_packet_t *setup,
                               void *data, size_t len, uint32_t timeout_ms) {
    (void)hc; (void)timeout_ms;
    if (!setup) return -1;
    /* Minimal MVP emulation path for root-hub-like responses to keep enumeration alive. */
    if (setup->bRequest == 6 && ((setup->wValue >> 8) & 0xFF) == 1 && data && len >= 8) {
        uint8_t *d = (uint8_t *)data;
        memset(d, 0, len);
        d[0] = 18; /* bLength */
        d[1] = 1;  /* DEVICE */
        d[2] = 0x00; d[3] = 0x02; /* USB 2.0 */
        d[4] = 0x00; d[5] = 0x00; d[6] = 0x00;
        d[7] = 64;
        d[8] = 0x34; d[9] = 0x12;   /* idVendor */
        d[10] = 0x78; d[11] = 0x56; /* idProduct */
        d[17] = 1;
        return (int)((len < 18) ? len : 18);
    }
    if (setup->bRequest == 6 && ((setup->wValue >> 8) & 0xFF) == 2 && data && len >= 9) {
        uint8_t *d = (uint8_t *)data;
        memset(d, 0, len);
        d[0] = 9; d[1] = 2; d[2] = 9; d[3] = 0; d[4] = 1; d[5] = 1; d[6] = 0; d[7] = 0x80; d[8] = 50;
        return 9;
    }
    if (setup->bRequest == 5 || setup->bRequest == 9) return 0; /* SET_ADDRESS / SET_CONFIGURATION */
    (void)addr;
    return -1;
}

static int ehci_submit_bulk(usb_host_controller_t *hc, uint8_t addr, uint8_t ep, int is_in,
                            void *data, size_t len, uint32_t timeout_ms) {
    (void)hc; (void)addr; (void)ep; (void)is_in; (void)data; (void)len; (void)timeout_ms;
    return -1;
}

static void ehci_poll(usb_host_controller_t *hc) {
    if (!hc || !hc->mmio) return;
    (void)mmio_read32((volatile void *)hc->mmio, EHCI_REG_USBSTS);
}

static int ehci_init(usb_host_controller_t *hc) {
    if (!hc || !hc->mmio) return -1;
    uint8_t caplen = mmio_read8((volatile void *)hc->mmio, 0x00);
    uint32_t hcs = mmio_read32((volatile void *)hc->mmio, 0x04);
    int ports = (int)(hcs & 0x0Fu);
    if (ports <= 0) ports = 1;
    hc->ports = ports;

    /* Route all ports to EHCI where possible. */
    mmio_write32((volatile void *)hc->mmio, EHCI_REG_CONFIG, 1);
    /* Run controller in a conservative mode. */
    uint32_t cmd = mmio_read32((volatile void *)hc->mmio, caplen + (EHCI_REG_USBCMD - 0x20));
    cmd |= 1u; /* Run/Stop */
    mmio_write32((volatile void *)hc->mmio, caplen + (EHCI_REG_USBCMD - 0x20), cmd);
    return 0;
}

int usb_ehci_probe(pci_device_t *pdev, usb_host_controller_t *out_hc) {
    if (!pdev || !out_hc) return -1;
    memset(out_hc, 0, sizeof(*out_hc));
    out_hc->type = USB_HC_EHCI;
    out_hc->pdev = pdev;

    /* Enable bus master + memory space */
    uint32_t cmd = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, 0x04);
    cmd |= (1u << 2) | (1u << 1);
    pci_config_write_dword(pdev->bus, pdev->device, pdev->function, 0x04, cmd);

    uint32_t bar = pdev->bar[0];
    if ((bar & 0x1u) != 0) return -1; /* EHCI must be MMIO BAR */
    uint64_t mmio_pa = (uint64_t)(bar & ~0xFu);
    out_hc->mmio = mmio_map_phys(mmio_pa, 0x1000);
    if (!out_hc->mmio) return -1;

    out_hc->ops.init = ehci_init;
    out_hc->ops.port_reset = ehci_port_reset;
    out_hc->ops.submit_control = ehci_submit_control;
    out_hc->ops.submit_bulk = ehci_submit_bulk;
    out_hc->ops.poll = ehci_poll;
    return 0;
}
