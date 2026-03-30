#ifndef DHCP_H
#define DHCP_H

#include <stdint.h>

/* DHCP lease result */
typedef struct {
    uint32_t ip_be;      /* assigned IP (big-endian) */
    uint32_t mask_be;    /* subnet mask (big-endian) */
    uint32_t gw_be;      /* gateway/router (big-endian) */
    uint32_t dns_be;     /* DNS server (big-endian) */
    uint32_t server_be;  /* DHCP server (big-endian) */
} dhcp_lease_t;

/*
 * Perform DHCP discovery and obtain a lease.
 * 
 * @param mac       MAC address of the interface (6 bytes)
 * @param out_lease Output lease information
 * @return 0 on success, -1 on failure
 */
int dhcp_acquire(const uint8_t mac[6], dhcp_lease_t *out_lease);

#endif /* DHCP_H */
