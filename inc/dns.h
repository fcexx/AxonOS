#pragma once

#include <stddef.h>
#include <stdint.h>

/* DNS resolver - RFC 1035 compliant. Resolves hostname to IPv4 (A record). */

/* Callback: send UDP to dst_ip:dst_port from src_port. Returns 0 on success. */
typedef int (*net_dns_send_udp_fn)(uint32_t dst_ip_be, uint16_t src_port, uint16_t dst_port,
                                   const void *data, size_t len, void *ctx);

/* Callback: receive UDP on local_port from peer_ip:peer_port. Returns bytes received, 0 on timeout, <0 on error. */
typedef int (*net_dns_recv_udp_fn)(uint16_t local_port, uint32_t peer_ip_be, uint16_t peer_port,
                                   void *out, size_t cap, uint32_t timeout_ms, void *ctx);

/*
 * Resolve hostname via DNS. Sends A query to dns_ip_be:53.
 * On success: returns 0, *out_ip_be contains IPv4 in network byte order.
 * On failure: returns -1.
 */
int net_dns_resolve(const char *hostname, uint32_t dns_ip_be,
                    net_dns_send_udp_fn send_udp, net_dns_recv_udp_fn recv_udp,
                    void *ctx, uint32_t *out_ip_be);
