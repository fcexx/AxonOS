#pragma once

#include <stddef.h>
#include <stdint.h>

typedef int (*net_tcp_send_l4_fn)(uint32_t dst_ip_be, uint8_t proto, const void *l4, size_t l4_len);
typedef int (*net_tcp_recv_frame_fn)(void *buf, size_t cap);
typedef uint64_t (*net_tcp_time_ms_fn)(void);
typedef void (*net_tcp_yield_fn)(void);
/* Shared RX queue: put back a frame that does not belong to this TCP connection (Linux: other sockets still see it). */
typedef void (*net_tcp_return_frame_fn)(const void *frame, size_t n);

typedef struct {
    uint32_t local_ip_be;
    net_tcp_send_l4_fn send_l4;
    net_tcp_recv_frame_fn recv_frame;
    net_tcp_time_ms_fn time_ms;
    net_tcp_yield_fn yield;
    net_tcp_return_frame_fn return_frame;
} net_tcp_ops_t;

typedef struct {
    int used;
    int established;
    int peer_fin;
    uint32_t dst_ip_be;
    uint16_t dst_port;
    uint16_t src_port;
    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;
    uint8_t rx_buf[8192];
    size_t rx_len;
} net_tcp_conn_t;

int net_tcp_connect(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t dst_ip_be, uint16_t dst_port, uint16_t src_port, uint32_t timeout_ms);
int net_tcp_send(net_tcp_conn_t *c, const net_tcp_ops_t *ops, const uint8_t *data, size_t len, uint32_t timeout_ms);
int net_tcp_recv(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint8_t *out, size_t cap, uint32_t timeout_ms);
int net_tcp_close(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t timeout_ms);
int net_tcp_service(net_tcp_conn_t *c, const net_tcp_ops_t *ops, int budget);
