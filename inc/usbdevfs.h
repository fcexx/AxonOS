#pragma once

#include <stdint.h>

/* Linux-compatible usbdevfs subset ioctls (x86_64 values). */
#define USBDEVFS_CONTROL          0xC0105500u
#define USBDEVFS_BULK             0xC0105502u
#define USBDEVFS_RESETEP          0x40045503u
#define USBDEVFS_SETINTERFACE     0x80085504u
#define USBDEVFS_SETCONFIGURATION 0x80045505u
#define USBDEVFS_CLAIMINTERFACE   0x8004550Fu
#define USBDEVFS_RELEASEINTERFACE 0x80045510u
#define USBDEVFS_RESET            0x5514u

typedef struct usbdevfs_ctrltransfer {
    uint8_t bRequestType;
    uint8_t bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
    uint32_t timeout; /* ms */
    void *data;       /* userspace pointer */
} usbdevfs_ctrltransfer_t;

typedef struct usbdevfs_bulktransfer {
    uint32_t ep;
    uint32_t len;
    uint32_t timeout; /* ms */
    void *data;       /* userspace pointer */
} usbdevfs_bulktransfer_t;
