#include <usb.h>
#include <serial.h>
#include <pci.h>
#include <string.h>

#define UHCI_USBCMD   0x00
#define UHCI_USBSTS   0x02
#define UHCI_PORTSC1  0x10
#define UHCI_PORTSC2  0x12

static int uhci_init(usb_host_controller_t *hc) {
    if (!hc || hc->io_base == 0) return -1;
    hc->ports = 2;
    /* Global reset and run (minimal safe sequence). */
    outw((unsigned short)(hc->io_base + UHCI_USBCMD), 0x0002);
    for (int i = 0; i < 20000; i++) asm volatile("pause");
    outw((unsigned short)(hc->io_base + UHCI_USBCMD), 0x0001);
    return 0;
}

static int uhci_port_reset(usb_host_controller_t *hc, int port) {
    if (!hc || hc->io_base == 0 || port < 1 || port > 2) return -1;
    uint16_t reg = (port == 1) ? UHCI_PORTSC1 : UHCI_PORTSC2;
    uint16_t v = inw((unsigned short)(hc->io_base + reg));
    if ((v & 0x1u) == 0) return -1; /* no connect */
    v |= (1u << 9); /* PR */
    outw((unsigned short)(hc->io_base + reg), v);
    for (int i = 0; i < 20000; i++) asm volatile("pause");
    v &= (uint16_t)~(1u << 9);
    outw((unsigned short)(hc->io_base + reg), v);
    for (int i = 0; i < 20000; i++) asm volatile("pause");
    return 0;
}

static int uhci_submit_control(usb_host_controller_t *hc, uint8_t addr, const usb_setup_packet_t *setup,
                               void *data, size_t len, uint32_t timeout_ms) {
    (void)hc; (void)addr; (void)timeout_ms;
    if (!setup) return -1;
    /* MVP emulation (same as EHCI fallback): enough for enumeration state machine. */
    if (setup->bRequest == 6 && ((setup->wValue >> 8) & 0xFF) == 1 && data && len >= 8) {
        uint8_t *d = (uint8_t *)data;
        memset(d, 0, len);
        d[0] = 18; d[1] = 1; d[2] = 0x10; d[3] = 0x01; d[7] = 8;
        d[8] = 0x86; d[9] = 0x80; d[10] = 0x01; d[11] = 0x00; d[17] = 1;
        return (int)((len < 18) ? len : 18);
    }
    if (setup->bRequest == 6 && ((setup->wValue >> 8) & 0xFF) == 2 && data && len >= 9) {
        uint8_t *d = (uint8_t *)data;
        memset(d, 0, len);
        d[0] = 9; d[1] = 2; d[2] = 9; d[3] = 0; d[4] = 1; d[5] = 1; d[6] = 0; d[7] = 0x80; d[8] = 50;
        return 9;
    }
    if (setup->bRequest == 5 || setup->bRequest == 9) return 0;
    return -1;
}

static int uhci_submit_bulk(usb_host_controller_t *hc, uint8_t addr, uint8_t ep, int is_in,
                            void *data, size_t len, uint32_t timeout_ms) {
    (void)hc; (void)addr; (void)ep; (void)is_in; (void)data; (void)len; (void)timeout_ms;
    return -1;
}

static void uhci_poll(usb_host_controller_t *hc) {
    if (!hc || hc->io_base == 0) return;
    (void)inw((unsigned short)(hc->io_base + UHCI_USBSTS));
}

int usb_uhci_probe(pci_device_t *pdev, usb_host_controller_t *out_hc) {
    if (!pdev || !out_hc) return -1;
    memset(out_hc, 0, sizeof(*out_hc));
    out_hc->type = USB_HC_UHCI;
    out_hc->pdev = pdev;

    /* Enable bus master + I/O space */
    uint32_t cmd = pci_config_read_dword(pdev->bus, pdev->device, pdev->function, 0x04);
    cmd |= (1u << 2) | (1u << 0);
    pci_config_write_dword(pdev->bus, pdev->device, pdev->function, 0x04, cmd);

    uint32_t bar4 = pdev->bar[4];
    uint32_t bar0 = pdev->bar[0];
    uint16_t iobase = 0;
    if (bar4 & 0x1u) iobase = (uint16_t)(bar4 & ~0x3u);
    else if (bar0 & 0x1u) iobase = (uint16_t)(bar0 & ~0x3u);
    if (iobase == 0) return -1;
    out_hc->io_base = iobase;

    out_hc->ops.init = uhci_init;
    out_hc->ops.port_reset = uhci_port_reset;
    out_hc->ops.submit_control = uhci_submit_control;
    out_hc->ops.submit_bulk = uhci_submit_bulk;
    out_hc->ops.poll = uhci_poll;
    return 0;
}
