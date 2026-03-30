#include <usb.h>
#include <usbdevfs.h>
#include <axonos.h>
#include <heap.h>
#include <string.h>
#include <devfs.h>
#include <sysfs.h>
#include <pci.h>

static usb_host_controller_t g_hc[USB_MAX_HC];
static int g_hc_count = 0;
static usb_device_t g_dev[USB_MAX_DEVICES];
static int g_dev_count = 0;
static int g_usb_inited = 0;
static int g_devfs_published = 0;
static int g_sysfs_published = 0;

static usb_host_controller_t *usb_pick_companion(const usb_device_t *dev) {
    if (!dev || !dev->hc) return NULL;
    if (dev->speed == USB_SPEED_HIGH) return dev->hc;
    if (dev->hc->type != USB_HC_EHCI) return dev->hc;
    for (int i = 0; i < g_hc_count; i++) {
        if (g_hc[i].type == USB_HC_UHCI) return &g_hc[i];
    }
    return dev->hc;
}

static int usb_add_device(usb_host_controller_t *hc, int is_root, uint8_t port, uint8_t addr,
                          usb_speed_t speed, uint16_t vid, uint16_t pid,
                          uint8_t cls, uint8_t subcls, uint8_t proto,
                          const char *mfg, const char *prod) {
    if (!hc || g_dev_count >= USB_MAX_DEVICES) return -1;
    usb_device_t *d = &g_dev[g_dev_count];
    memset(d, 0, sizeof(*d));
    d->id = g_dev_count;
    d->present = 1;
    d->is_root_hub = is_root ? 1 : 0;
    d->bus_num = hc->id + 1;
    d->dev_num = g_dev_count + 1;
    d->speed = speed;
    d->address = addr;
    d->port = port;
    d->vendor_id = vid;
    d->product_id = pid;
    d->dev_class = cls;
    d->dev_subclass = subcls;
    d->dev_proto = proto;
    d->hc = hc;
    if (mfg) strncpy(d->manufacturer, mfg, sizeof(d->manufacturer) - 1);
    if (prod) strncpy(d->product, prod, sizeof(d->product) - 1);
    g_dev_count++;
    return d->id;
}

static usb_speed_t usb_hc_default_speed(usb_hc_type_t t) {
    if (t == USB_HC_EHCI) return USB_SPEED_HIGH;
    return USB_SPEED_FULL;
}

/* Minimal enumeration pipeline over root ports; safe timeouts and no unbounded loops. */
static void usb_enumerate_hc(usb_host_controller_t *hc) {
    if (!hc) return;

    /* Always add root hub pseudo device so /dev and /sys have stable bus anchor. */
    (void)usb_add_device(
        hc, 1, 0, 1, usb_hc_default_speed(hc->type),
        0x1d6b, (hc->type == USB_HC_EHCI) ? 0x0002 : 0x0001,
        0x09, 0x00, 0x00,
        "AxonOS", (hc->type == USB_HC_EHCI) ? "EHCI Root Hub" : "UHCI Root Hub"
    );

    if (!hc->ops.port_reset || !hc->ops.submit_control) return;
    for (int port = 1; port <= hc->ports; port++) {
        if (hc->ops.port_reset(hc, port) != 0) continue;

        /* 1) GET_DESCRIPTOR(Device) first 8 bytes */
        uint8_t dev_desc8[8];
        memset(dev_desc8, 0, sizeof(dev_desc8));
        usb_setup_packet_t s = {0};
        s.bmRequestType = 0x80;
        s.bRequest = 6;     /* GET_DESCRIPTOR */
        s.wValue = (1u << 8); /* DEVICE descriptor */
        s.wIndex = 0;
        s.wLength = 8;
        int rc = hc->ops.submit_control(hc, 0, &s, dev_desc8, sizeof(dev_desc8), 500);
        hc->submitted++;
        if (rc < 0) { hc->errors++; continue; }
        hc->completed++;

        /* 2) SET_ADDRESS (very small stack, static address map) */
        uint8_t addr = (uint8_t)((g_dev_count + 2) & 0x7F);
        if (addr == 0) addr = 2;
        usb_setup_packet_t set_addr = {0};
        set_addr.bmRequestType = 0x00;
        set_addr.bRequest = 5; /* SET_ADDRESS */
        set_addr.wValue = addr;
        set_addr.wIndex = 0;
        set_addr.wLength = 0;
        rc = hc->ops.submit_control(hc, 0, &set_addr, NULL, 0, 500);
        hc->submitted++;
        if (rc < 0) { hc->errors++; continue; }
        hc->completed++;

        /* 3) Full GET_DESCRIPTOR(Device) */
        uint8_t dev_desc[18];
        memset(dev_desc, 0, sizeof(dev_desc));
        s.wLength = sizeof(dev_desc);
        rc = hc->ops.submit_control(hc, addr, &s, dev_desc, sizeof(dev_desc), 1000);
        hc->submitted++;
        if (rc < 0) { hc->errors++; continue; }
        hc->completed++;

        /* 4) GET_DESCRIPTOR(Configuration) */
        uint8_t cfg_hdr[9];
        memset(cfg_hdr, 0, sizeof(cfg_hdr));
        usb_setup_packet_t get_cfg = {0};
        get_cfg.bmRequestType = 0x80;
        get_cfg.bRequest = 6;
        get_cfg.wValue = (2u << 8); /* CONFIG */
        get_cfg.wIndex = 0;
        get_cfg.wLength = sizeof(cfg_hdr);
        rc = hc->ops.submit_control(hc, addr, &get_cfg, cfg_hdr, sizeof(cfg_hdr), 1000);
        hc->submitted++;
        if (rc < 0) { hc->errors++; continue; }
        hc->completed++;

        /* 5) SET_CONFIGURATION #1 */
        usb_setup_packet_t set_cfg = {0};
        set_cfg.bmRequestType = 0x00;
        set_cfg.bRequest = 9;  /* SET_CONFIGURATION */
        set_cfg.wValue = 1;
        set_cfg.wIndex = 0;
        set_cfg.wLength = 0;
        rc = hc->ops.submit_control(hc, addr, &set_cfg, NULL, 0, 1000);
        hc->submitted++;
        if (rc < 0) { hc->errors++; continue; }
        hc->completed++;

        uint16_t vid = (uint16_t)(dev_desc[8] | ((uint16_t)dev_desc[9] << 8));
        uint16_t pid = (uint16_t)(dev_desc[10] | ((uint16_t)dev_desc[11] << 8));
        uint8_t cls = dev_desc[4];
        uint8_t sub = dev_desc[5];
        uint8_t pr = dev_desc[6];

        int id = usb_add_device(hc, 0, (uint8_t)port, addr, usb_hc_default_speed(hc->type),
                                vid, pid, cls, sub, pr, "USB", "USB Device");
        if (id >= 0) g_dev[id].configured = 1;
    }
}

int usb_publish_devfs_nodes(void) {
    if (g_devfs_published) return 0;
    for (int i = 0; i < g_dev_count; i++) {
        usb_device_t *d = &g_dev[i];
        if (!d->present) continue;
        usb_char_node_t *node = (usb_char_node_t *)kmalloc(sizeof(*node));
        if (!node) return -1;
        node->magic = 0x55534244u; /* 'USBD' */
        node->dev_id = d->id;
        char path[64];
        snprintf(path, sizeof(path), "/dev/bus/usb/%03d/%03d", d->bus_num, d->dev_num);
        if (devfs_create_char_node(path, node) != 0) {
            kfree(node);
            continue;
        }
    }
    g_devfs_published = 1;
    return 0;
}

static ssize_t usb_show_vendor(char *buf, size_t size, void *priv) {
    usb_device_t *d = (usb_device_t *)priv;
    if (!buf || size == 0 || !d) return 0;
    int n = snprintf(buf, size, "0x%04x\n", d->vendor_id);
    if (n < 0) return 0;
    if ((size_t)n > size) n = (int)size;
    return (ssize_t)n;
}

static ssize_t usb_show_product(char *buf, size_t size, void *priv) {
    usb_device_t *d = (usb_device_t *)priv;
    if (!buf || size == 0 || !d) return 0;
    int n = snprintf(buf, size, "0x%04x\n", d->product_id);
    if (n < 0) return 0;
    if ((size_t)n > size) n = (int)size;
    return (ssize_t)n;
}

static ssize_t usb_show_u8_class(char *buf, size_t size, void *priv) {
    usb_device_t *d = (usb_device_t *)priv;
    if (!buf || size == 0 || !d) return 0;
    int n = snprintf(buf, size, "0x%02x\n", d->dev_class);
    if (n < 0) return 0;
    if ((size_t)n > size) n = (int)size;
    return (ssize_t)n;
}

static ssize_t usb_show_speed(char *buf, size_t size, void *priv) {
    usb_device_t *d = (usb_device_t *)priv;
    if (!buf || size == 0 || !d) return 0;
    const char *s = "unknown\n";
    if (d->speed == USB_SPEED_LOW) s = "low\n";
    else if (d->speed == USB_SPEED_FULL) s = "full\n";
    else if (d->speed == USB_SPEED_HIGH) s = "high\n";
    size_t n = strlen(s);
    if (n > size) n = size;
    memcpy(buf, s, n);
    return (ssize_t)n;
}

static ssize_t usb_show_mfg(char *buf, size_t size, void *priv) {
    usb_device_t *d = (usb_device_t *)priv;
    if (!buf || size == 0 || !d) return 0;
    int n = snprintf(buf, size, "%s\n", d->manufacturer[0] ? d->manufacturer : "unknown");
    if (n < 0) return 0;
    if ((size_t)n > size) n = (int)size;
    return (ssize_t)n;
}

static ssize_t usb_show_prod_str(char *buf, size_t size, void *priv) {
    usb_device_t *d = (usb_device_t *)priv;
    if (!buf || size == 0 || !d) return 0;
    int n = snprintf(buf, size, "%s\n", d->product[0] ? d->product : "unknown");
    if (n < 0) return 0;
    if ((size_t)n > size) n = (int)size;
    return (ssize_t)n;
}

int usb_publish_sysfs_nodes(void) {
    if (g_sysfs_published) return 0;
    if (sysfs_mkdir("/sys/bus/usb") != 0) return -1;
    (void)sysfs_mkdir("/sys/bus/usb/devices");
    for (int i = 0; i < g_dev_count; i++) {
        usb_device_t *d = &g_dev[i];
        if (!d->present) continue;
        char dir[128];
        snprintf(dir, sizeof(dir), "/sys/bus/usb/devices/usb%d-%d", d->bus_num, d->dev_num);
        (void)sysfs_mkdir(dir);

        struct sysfs_attr a;
        char p[160];

        a.store = NULL; a.priv = d;
        a.show = usb_show_vendor;
        snprintf(p, sizeof(p), "%s/idVendor", dir);
        (void)sysfs_create_file(p, &a);

        a.show = usb_show_product;
        snprintf(p, sizeof(p), "%s/idProduct", dir);
        (void)sysfs_create_file(p, &a);

        a.show = usb_show_u8_class;
        snprintf(p, sizeof(p), "%s/bDeviceClass", dir);
        (void)sysfs_create_file(p, &a);

        a.show = usb_show_speed;
        snprintf(p, sizeof(p), "%s/speed", dir);
        (void)sysfs_create_file(p, &a);

        a.show = usb_show_mfg;
        snprintf(p, sizeof(p), "%s/manufacturer", dir);
        (void)sysfs_create_file(p, &a);

        a.show = usb_show_prod_str;
        snprintf(p, sizeof(p), "%s/product", dir);
        (void)sysfs_create_file(p, &a);
    }
    g_sysfs_published = 1;
    return 0;
}

int usb_publish_procfs_nodes(void) {
    return 0;
}

void usb_sysfs_populate_default(void) {
    (void)usb_publish_sysfs_nodes();
}

int usb_init(void) {
    if (g_usb_inited) return 0;
    memset(g_hc, 0, sizeof(g_hc));
    memset(g_dev, 0, sizeof(g_dev));
    g_hc_count = 0;
    g_dev_count = 0;

    pci_device_t *devs = pci_get_devices();
    int count = pci_get_device_count();
    for (int i = 0; i < count && g_hc_count < USB_MAX_HC; i++) {
        pci_device_t *pdev = &devs[i];
        if (pdev->class_code != 0x0C || pdev->subclass != 0x03) continue;

        usb_host_controller_t hc_tmp;
        memset(&hc_tmp, 0, sizeof(hc_tmp));
        int rc = -1;
        if (pdev->prog_if == 0x20) rc = usb_ehci_probe(pdev, &hc_tmp);
        else if (pdev->prog_if == 0x00) rc = usb_uhci_probe(pdev, &hc_tmp);
        else continue;
        if (rc != 0) continue;

        hc_tmp.id = g_hc_count;
        g_hc[g_hc_count] = hc_tmp;
        g_hc_count++;
    }

    for (int i = 0; i < g_hc_count; i++) {
        if (g_hc[i].ops.init) (void)g_hc[i].ops.init(&g_hc[i]);
        usb_enumerate_hc(&g_hc[i]);
        /* Smoke self-check: polling + bounded control request path on root address. */
        if (g_hc[i].ops.poll) g_hc[i].ops.poll(&g_hc[i]);
        if (g_hc[i].ops.submit_control) {
            uint8_t tmp[8];
            usb_setup_packet_t s;
            memset(&s, 0, sizeof(s));
            s.bmRequestType = 0x80;
            s.bRequest = 6;
            s.wValue = (1u << 8);
            s.wLength = sizeof(tmp);
            int tr = g_hc[i].ops.submit_control(&g_hc[i], 0, &s, tmp, sizeof(tmp), 200);
            if (tr < 0) g_hc[i].timeouts++;
        }
        klogprintf("usb: hc=%d type=%d ports=%d submitted=%llu completed=%llu errors=%llu timeouts=%llu\n",
                   g_hc[i].id, (int)g_hc[i].type, g_hc[i].ports,
                   (unsigned long long)g_hc[i].submitted,
                   (unsigned long long)g_hc[i].completed,
                   (unsigned long long)g_hc[i].errors,
                   (unsigned long long)g_hc[i].timeouts);
    }

    g_usb_inited = 1;
    klogprintf("usb: initialized hc=%d devices=%d\n", g_hc_count, g_dev_count);
    return 0;
}

void usb_poll(void) {
    for (int i = 0; i < g_hc_count; i++) {
        if (g_hc[i].ops.poll) g_hc[i].ops.poll(&g_hc[i]);
    }
}

int usb_device_count(void) { return g_dev_count; }

const usb_device_t *usb_device_get(int idx) {
    if (idx < 0 || idx >= g_dev_count) return NULL;
    return &g_dev[idx];
}

int usb_is_devfs_path(const char *path) {
    if (!path) return 0;
    return strncmp(path, "/dev/bus/usb/", 13) == 0;
}

int usb_is_devfs_file(const struct fs_file *f) {
    if (!f || !f->path || !f->driver_private) return 0;
    if (!usb_is_devfs_path(f->path)) return 0;
    usb_char_node_t *n = (usb_char_node_t *)f->driver_private;
    return n->magic == 0x55534244u;
}

const usb_device_t *usb_device_from_file(const struct fs_file *f) {
    if (!usb_is_devfs_file(f)) return NULL;
    usb_char_node_t *n = (usb_char_node_t *)f->driver_private;
    if (n->dev_id < 0 || n->dev_id >= g_dev_count) return NULL;
    return &g_dev[n->dev_id];
}

ssize_t usb_devfs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    (void)offset;
    if (!usb_is_devfs_file(file) || !buf) return -1;
    /* No streaming endpoint binding in MVP; behave as no data. */
    (void)size;
    return 0;
}

ssize_t usb_devfs_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
    (void)offset;
    if (!usb_is_devfs_file(file) || !buf) return -1;
    /* No implicit bulk endpoint in MVP. */
    (void)size;
    return -1;
}

int usb_claim_interface(usb_device_t *dev, int ifnum) {
    if (!dev || ifnum < 0 || ifnum >= 64) return -1;
    dev->claimed_mask[ifnum / 8] |= (uint8_t)(1u << (ifnum % 8));
    return 0;
}

int usb_release_interface(usb_device_t *dev, int ifnum) {
    if (!dev || ifnum < 0 || ifnum >= 64) return -1;
    dev->claimed_mask[ifnum / 8] &= (uint8_t)~(1u << (ifnum % 8));
    return 0;
}

int usb_reset_device(usb_device_t *dev) {
    if (!dev || !dev->hc || !dev->hc->ops.port_reset) return -1;
    if (dev->is_root_hub) return 0;
    return dev->hc->ops.port_reset(dev->hc, dev->port);
}

int usb_control_transfer(usb_device_t *dev, const usb_setup_packet_t *setup, void *data, size_t len, uint32_t timeout_ms) {
    if (!dev || !setup) return -1;
    usb_host_controller_t *hc = usb_pick_companion(dev);
    if (!hc || !hc->ops.submit_control) return -1;
    hc->submitted++;
    int rc = hc->ops.submit_control(hc, dev->address, setup, data, len, timeout_ms);
    if (rc < 0) hc->errors++; else hc->completed++;
    return rc;
}

int usb_bulk_transfer(usb_device_t *dev, uint8_t ep, int is_in, void *data, size_t len, uint32_t timeout_ms) {
    if (!dev) return -1;
    usb_host_controller_t *hc = usb_pick_companion(dev);
    if (!hc || !hc->ops.submit_bulk) return -1;
    hc->submitted++;
    int rc = hc->ops.submit_bulk(hc, dev->address, ep, is_in, data, len, timeout_ms);
    if (rc < 0) hc->errors++; else hc->completed++;
    return rc;
}

ssize_t usb_proc_bus_devices_show(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    size_t w = 0;
    int n = snprintf(buf + w, (w < size) ? (size - w) : 0,
                     "T:  Bus Lev Prnt Port Cnt Dev# Spd\n");
    if (n > 0) w += (size_t)n;
    for (int i = 0; i < g_dev_count; i++) {
        const usb_device_t *d = &g_dev[i];
        if (!d->present) continue;
        const char *spd = (d->speed == USB_SPEED_HIGH) ? "480" :
                          (d->speed == USB_SPEED_FULL) ? "12" : "1.5";
        n = snprintf(buf + w, (w < size) ? (size - w) : 0,
                     "T:  Bus=%03d Dev#=%03d Port=%u Spd=%s Vendor=%04x ProdID=%04x Class=%02x\n",
                     d->bus_num, d->dev_num, d->port, spd,
                     d->vendor_id, d->product_id, d->dev_class);
        if (n <= 0) break;
        w += (size_t)n;
        if (w >= size) { w = size; break; }
    }
    return (ssize_t)w;
}

/* Generic wrappers kept exported in header for reuse in sysfs.c if needed. */
ssize_t usb_sysfs_attr_show_hex16(char *buf, size_t size, void *priv) { return usb_show_vendor(buf, size, priv); }
ssize_t usb_sysfs_attr_show_u8(char *buf, size_t size, void *priv) { return usb_show_u8_class(buf, size, priv); }
ssize_t usb_sysfs_attr_show_str(char *buf, size_t size, void *priv) { return usb_show_mfg(buf, size, priv); }
ssize_t usb_sysfs_attr_show_speed(char *buf, size_t size, void *priv) { return usb_show_speed(buf, size, priv); }
