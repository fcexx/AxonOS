#pragma once

#include <stdint.h>
#include <stddef.h>
#include <fs.h>
#include <pci.h>
#include <sysfs.h>

#define USB_MAX_HC      8
#define USB_MAX_DEVICES 64

typedef enum usb_hc_type {
    USB_HC_UHCI = 1,
    USB_HC_EHCI = 2
} usb_hc_type_t;

typedef enum usb_speed {
    USB_SPEED_LOW = 1,
    USB_SPEED_FULL = 2,
    USB_SPEED_HIGH = 3
} usb_speed_t;

typedef struct usb_setup_packet {
    uint8_t bmRequestType;
    uint8_t bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
} __attribute__((packed)) usb_setup_packet_t;

struct usb_host_controller;

typedef struct usb_hcd_ops {
    int (*init)(struct usb_host_controller *hc);
    int (*port_reset)(struct usb_host_controller *hc, int port);
    int (*submit_control)(struct usb_host_controller *hc, uint8_t addr, const usb_setup_packet_t *setup,
                          void *data, size_t len, uint32_t timeout_ms);
    int (*submit_bulk)(struct usb_host_controller *hc, uint8_t addr, uint8_t ep, int is_in,
                       void *data, size_t len, uint32_t timeout_ms);
    void (*poll)(struct usb_host_controller *hc);
} usb_hcd_ops_t;

typedef struct usb_host_controller {
    int id;
    usb_hc_type_t type;
    pci_device_t *pdev;
    void *mmio;
    uint16_t io_base;
    int ports;
    usb_hcd_ops_t ops;
    uint64_t submitted;
    uint64_t completed;
    uint64_t timeouts;
    uint64_t errors;
} usb_host_controller_t;

typedef struct usb_device {
    int id;
    int present;
    int is_root_hub;
    int bus_num;
    int dev_num;
    usb_speed_t speed;
    uint8_t address;
    uint8_t port;
    uint8_t configured;
    uint8_t claimed_mask[8];
    uint16_t vendor_id;
    uint16_t product_id;
    uint8_t dev_class;
    uint8_t dev_subclass;
    uint8_t dev_proto;
    char manufacturer[64];
    char product[64];
    usb_host_controller_t *hc;
} usb_device_t;

typedef struct usb_char_node {
    uint32_t magic;
    int dev_id;
} usb_char_node_t;

/* Core init/probe + background poll */
int usb_init(void);
void usb_poll(void);

/* Publishers for virtual filesystems */
int usb_publish_devfs_nodes(void);
int usb_publish_sysfs_nodes(void);
int usb_publish_procfs_nodes(void); /* kept for symmetry, currently no-op */

/* Called from kernel default sysfs population hook */
void usb_sysfs_populate_default(void);

/* Query helpers */
int usb_device_count(void);
const usb_device_t *usb_device_get(int idx);
const usb_device_t *usb_device_from_file(const struct fs_file *f);
int usb_is_devfs_file(const struct fs_file *f);
int usb_is_devfs_path(const char *path);

/* Data providers for /proc and /sys */
ssize_t usb_proc_bus_devices_show(char *buf, size_t size, void *priv);
ssize_t usb_sysfs_attr_show_hex16(char *buf, size_t size, void *priv);
ssize_t usb_sysfs_attr_show_u8(char *buf, size_t size, void *priv);
ssize_t usb_sysfs_attr_show_str(char *buf, size_t size, void *priv);
ssize_t usb_sysfs_attr_show_speed(char *buf, size_t size, void *priv);

/* Character-device read/write (minimal stub for now). */
ssize_t usb_devfs_read(struct fs_file *file, void *buf, size_t size, size_t offset);
ssize_t usb_devfs_write(struct fs_file *file, const void *buf, size_t size, size_t offset);

/* usbdevfs operations */
int usb_claim_interface(usb_device_t *dev, int ifnum);
int usb_release_interface(usb_device_t *dev, int ifnum);
int usb_reset_device(usb_device_t *dev);
int usb_control_transfer(usb_device_t *dev, const usb_setup_packet_t *setup, void *data, size_t len, uint32_t timeout_ms);
int usb_bulk_transfer(usb_device_t *dev, uint8_t ep, int is_in, void *data, size_t len, uint32_t timeout_ms);

/* HCD-specific probes */
int usb_ehci_probe(pci_device_t *pdev, usb_host_controller_t *out_hc);
int usb_uhci_probe(pci_device_t *pdev, usb_host_controller_t *out_hc);
