#pragma once

#include <stddef.h>
#include <stdint.h>

/* Intel PRO/1000 driver public API (raw Ethernet frames). */

typedef struct {
    uint64_t tx_packets;
    uint64_t tx_errors;
    uint64_t rx_packets;
    uint64_t rx_errors;
} e1000_stats_t;

/* Initialize Intel PRO/1000 NIC.
   Returns 0 on success, -1 if no supported device or init failed. */
int e1000_init(void);

/* Returns 1 when NIC is initialized and link is usable, 0 otherwise. */
int e1000_is_ready(void);

/* Copy NIC MAC address into out_mac[6]. Returns 0 on success. */
int e1000_get_mac(uint8_t out_mac[6]);

/* Send one raw Ethernet frame.
   Returns number of bytes queued/sent, or negative error code. */
int e1000_send_frame(const void *data, size_t len);

/* Receive one raw Ethernet frame (non-blocking).
   Returns frame length (>0), 0 if no packet, negative on error. */
int e1000_recv_frame(void *buf, size_t cap);

/* Optional driver polling hook (for setups without NIC IRQ path). */
void e1000_poll(void);

/* Snapshot driver counters. */
int e1000_get_stats(e1000_stats_t *out_stats);
