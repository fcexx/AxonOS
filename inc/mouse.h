#pragma once

#include <stddef.h>
#include <stdint.h>
#include <fs.h>

/* Initialize PS/2 mouse (IRQ12), register /dev/input/mice and sysfs nodes. */
void ps2_mouse_init(void);
/* Publish mouse nodes to /sys/class/input/* (safe to call multiple times). */
void mouse_publish_sysfs(void);

/* Read raw bytes from /dev/input/mice stream (PS/2 3-byte packets). */
ssize_t mouse_read_stream(void *buf, size_t size);

/* Number of pending bytes in mouse stream buffer. */
int mouse_stream_available(void);
/* Feed one raw AUX byte into mouse packet parser. */
void mouse_process_byte(uint8_t b);
