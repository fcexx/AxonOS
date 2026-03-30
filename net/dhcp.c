/*
 * DHCP Client Implementation for AxonOS
 * Implements RFC 2131 DHCP protocol
 */

#include <dhcp.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <heap.h>
#include <e1000.h>
#include <pit.h>
#include <thread.h>

extern void klogprintf(const char *fmt, ...);

/* Ethernet/IP/UDP constants */
#define ETH_TYPE_IPV4         0x0800
#define DHCP_FRAME_BUF        2048
#define UDP_PORT_DHCP_SERVER  67
#define UDP_PORT_DHCP_CLIENT  68

/* Packet structures */
typedef struct __attribute__((packed)) {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
} eth_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t csum;
    uint32_t src;
    uint32_t dst;
} ipv4_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t csum;
} udp_hdr_t;

/* Byte order helpers */
static inline uint16_t be16(uint16_t x) {
    return (uint16_t)((x >> 8) | (x << 8));
}

/* IP checksum */
static uint16_t ip_checksum16(const void *data, size_t len) {
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* DHCP option parser */
static const uint8_t *dhcp_find_opt(const uint8_t *opts, size_t opts_len, uint8_t code, uint8_t *out_len) {
    size_t i = 0;
    while (i < opts_len) {
        uint8_t c = opts[i++];
        if (c == 0) continue;
        if (c == 255) break;
        if (i >= opts_len) break;
        uint8_t l = opts[i++];
        if (i + l > opts_len) break;
        if (c == code) {
            if (out_len) *out_len = l;
            return &opts[i];
        }
        i += l;
    }
    return NULL;
}

/* Global IP ID counter for packet identification */
static uint16_t g_ip_id = 1;
static dhcp_lease_t g_cached_lease;
static uint8_t g_cached_mac[6];
static int g_cached_lease_valid = 0;

/* Send DHCP packet */
static int dhcp_send_packet(const uint8_t mac[6], uint8_t msg_type, uint32_t xid, 
                            uint32_t req_ip_be, uint32_t server_id_be) {
    uint8_t pkt[548];
    memset(pkt, 0, sizeof(pkt));
    
    /* BOOTP fixed header */
    pkt[0] = 1;  /* op: request */
    pkt[1] = 1;  /* htype: ethernet */
    pkt[2] = 6;  /* hlen */
    pkt[3] = 0;  /* hops */
    pkt[4] = (uint8_t)(xid >> 24);
    pkt[5] = (uint8_t)(xid >> 16);
    pkt[6] = (uint8_t)(xid >> 8);
    pkt[7] = (uint8_t)xid;
    pkt[10] = 0x80; pkt[11] = 0x00; /* flags: broadcast */
    memcpy(&pkt[28], mac, 6); /* chaddr */
    
    /* DHCP magic cookie */
    pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99;
    
    /* DHCP options */
    size_t o = 240;
    pkt[o++] = 53; pkt[o++] = 1; pkt[o++] = msg_type; /* message type */
    pkt[o++] = 61; pkt[o++] = 7; pkt[o++] = 1; /* client id */
    memcpy(&pkt[o], mac, 6); o += 6;
    
    if (msg_type == 1) { /* DISCOVER */
        pkt[o++] = 55; pkt[o++] = 4; /* parameter request list */
        pkt[o++] = 1;  /* subnet mask */
        pkt[o++] = 3;  /* router */
        pkt[o++] = 6;  /* DNS */
        pkt[o++] = 15; /* domain name */
    } else if (msg_type == 3) { /* REQUEST */
        pkt[o++] = 50; pkt[o++] = 4; /* requested IP */
        pkt[o++] = (uint8_t)(req_ip_be >> 24);
        pkt[o++] = (uint8_t)(req_ip_be >> 16);
        pkt[o++] = (uint8_t)(req_ip_be >> 8);
        pkt[o++] = (uint8_t)(req_ip_be);
        pkt[o++] = 54; pkt[o++] = 4; /* server identifier */
        pkt[o++] = (uint8_t)(server_id_be >> 24);
        pkt[o++] = (uint8_t)(server_id_be >> 16);
        pkt[o++] = (uint8_t)(server_id_be >> 8);
        pkt[o++] = (uint8_t)(server_id_be);
    }
    pkt[o++] = 255; /* end */
    
    /* Build Ethernet + IP + UDP frame */
    size_t ip_len = sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t) + o;
    size_t frm_len = sizeof(eth_hdr_t) + ip_len;
    uint8_t *frm = (uint8_t *)kmalloc(frm_len);
    if (!frm) return -1;
    
    /* Ethernet header */
    eth_hdr_t *eth = (eth_hdr_t *)frm;
    memset(eth->dst, 0xFF, 6); /* broadcast */
    memcpy(eth->src, mac, 6);
    eth->ethertype = be16(ETH_TYPE_IPV4);
    
    /* IP header */
    ipv4_hdr_t *ip = (ipv4_hdr_t *)(frm + sizeof(eth_hdr_t));
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = 0x45;
    ip->total_len = be16((uint16_t)ip_len);
    ip->id = be16(++g_ip_id);
    ip->ttl = 64;
    ip->proto = 17; /* UDP */
    ip->src = 0;
    ip->dst = 0xFFFFFFFFu;
    ip->csum = be16(ip_checksum16(ip, sizeof(*ip)));
    
    /* UDP header */
    udp_hdr_t *udp = (udp_hdr_t *)(frm + sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t));
    udp->src_port = be16(UDP_PORT_DHCP_CLIENT);
    udp->dst_port = be16(UDP_PORT_DHCP_SERVER);
    udp->len = be16((uint16_t)(sizeof(udp_hdr_t) + o));
    udp->csum = 0;
    memcpy((uint8_t *)udp + sizeof(udp_hdr_t), pkt, o);
    
    int sr = e1000_send_frame(frm, frm_len);
    klogprintf("dhcp: e1000_send_frame(%u) = %d\n", (unsigned)frm_len, sr);
    kfree(frm);
    return (sr < 0) ? -1 : 0;
}

int dhcp_acquire(const uint8_t mac[6], dhcp_lease_t *out_lease) {
    if (!mac || !out_lease) return -1;
    
    memset(out_lease, 0, sizeof(*out_lease));

    /* Reuse the latest successful lease for repeated callers (e.g. second `ip a`). */
    if (g_cached_lease_valid && memcmp(g_cached_mac, mac, 6) == 0) {
        *out_lease = g_cached_lease;
        klogprintf("dhcp: reuse cached lease ip=%u.%u.%u.%u\n",
            (g_cached_lease.ip_be >> 24) & 0xFF, (g_cached_lease.ip_be >> 16) & 0xFF,
            (g_cached_lease.ip_be >> 8) & 0xFF, g_cached_lease.ip_be & 0xFF);
        return 0;
    }
    
    /* Wait for link (VMware NAT can be slow to bring link up) */
    uint64_t link_wait = pit_get_time_ms();
    while (!e1000_is_ready() && (pit_get_time_ms() - link_wait) < 5000)
        thread_yield();
    if (!e1000_is_ready())
        klogprintf("dhcp: link not up after 5s, proceeding anyway\n");

    /* VMware virtual switch needs time to be ready after link up */
    uint64_t settle = pit_get_time_ms();
    while ((pit_get_time_ms() - settle) < 1500) thread_yield();

    /* Drain stale frames (limit 64 to avoid blocking on broadcast flood) */
    uint8_t drain[512];
    int drained = 0;
    for (int d = 0; d < 64; d++) {
        e1000_poll();
        if (e1000_recv_frame(drain, sizeof(drain)) <= 0) break;
        drained++;
    }
    if (drained) klogprintf("dhcp: drained %d stale frames\n", drained);

    /* Let NIC stabilize (especially QEMU) */
    for (int i = 0; i < 3000; i++) thread_yield();
    
    uint32_t xid = (uint32_t)(pit_get_ticks() ^ 0xA5F0C31Du);
    uint32_t offered_ip = 0, server_id = 0, netmask = 0, router = 0, dns = 0;
    uint8_t *frame = kmalloc(DHCP_FRAME_BUF);
    if (!frame) return -1;
    
    /* PHASE 1: DISCOVER -> OFFER (with retries) */
    for (int disc_try = 0; disc_try < 3 && !offered_ip; disc_try++) {
        klogprintf("dhcp: DISCOVER (xid=0x%08x, try=%d)\n", xid, disc_try + 1);
        int send_rc = dhcp_send_packet(mac, 1, xid, 0, 0);
        klogprintf("dhcp: send_rc=%d\n", send_rc);
        if (send_rc != 0) {
            klogprintf("dhcp: DISCOVER send failed\n");
            for (int w = 0; w < 500; w++) thread_yield();
            continue;
        }
        
        /* Give QEMU/network time to process and respond */
        for (int w = 0; w < 100; w++) thread_yield();
        
        e1000_debug_rx();
        
        uint64_t start = pit_get_time_ms();
        int rx_count = 0;
        while ((pit_get_time_ms() - start) < 4000) {
            e1000_poll();
            int n = e1000_recv_frame(frame, DHCP_FRAME_BUF);
            if (n <= 0) { thread_yield(); continue; }
            rx_count++;
            if ((size_t)n < sizeof(eth_hdr_t) + 20 + 8 + 240) continue;
            
            const eth_hdr_t *eth = (const eth_hdr_t *)frame;
            if (be16(eth->ethertype) != ETH_TYPE_IPV4) continue;
            
            const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
            size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
            if (ip->proto != 17 || ihl < 20) continue;
            
            const udp_hdr_t *udp = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
            if (be16(udp->dst_port) != UDP_PORT_DHCP_CLIENT) continue;
            
            const uint8_t *d = (const uint8_t *)udp + sizeof(udp_hdr_t);
            /* Check DHCP magic cookie */
            if (!(d[236] == 99 && d[237] == 130 && d[238] == 83 && d[239] == 99)) continue;
            
            uint32_t rx_xid = ((uint32_t)d[4] << 24) | ((uint32_t)d[5] << 16) | 
                              ((uint32_t)d[6] << 8) | d[7];
            uint32_t yiaddr = ((uint32_t)d[16] << 24) | ((uint32_t)d[17] << 16) | 
                              ((uint32_t)d[18] << 8) | d[19];
            
            uint8_t l = 0;
            const uint8_t *t = dhcp_find_opt(d + 240, (size_t)n - (sizeof(eth_hdr_t) + ihl + 8 + 240), 53, &l);
            uint8_t msg_type = (t && l == 1) ? t[0] : 0;
            
            klogprintf("dhcp: rx type=%u xid=0x%08x ip=%u.%u.%u.%u\n", msg_type, rx_xid,
                (yiaddr >> 24) & 0xFF, (yiaddr >> 16) & 0xFF, 
                (yiaddr >> 8) & 0xFF, yiaddr & 0xFF);
            
            if (rx_xid != xid) continue;
            
            if (msg_type == 2) { /* OFFER */
                const uint8_t *sid = dhcp_find_opt(d + 240, (size_t)n - (sizeof(eth_hdr_t) + ihl + 8 + 240), 54, &l);
                if (sid && l == 4) server_id = ((uint32_t)sid[0] << 24) | ((uint32_t)sid[1] << 16) | 
                                                ((uint32_t)sid[2] << 8) | sid[3];
                const uint8_t *msk = dhcp_find_opt(d + 240, (size_t)n - (sizeof(eth_hdr_t) + ihl + 8 + 240), 1, &l);
                if (msk && l == 4) netmask = ((uint32_t)msk[0] << 24) | ((uint32_t)msk[1] << 16) | 
                                              ((uint32_t)msk[2] << 8) | msk[3];
                const uint8_t *rtr = dhcp_find_opt(d + 240, (size_t)n - (sizeof(eth_hdr_t) + ihl + 8 + 240), 3, &l);
                if (rtr && l >= 4) router = ((uint32_t)rtr[0] << 24) | ((uint32_t)rtr[1] << 16) | 
                                            ((uint32_t)rtr[2] << 8) | rtr[3];
                const uint8_t *dnsopt = dhcp_find_opt(d + 240, (size_t)n - (sizeof(eth_hdr_t) + ihl + 8 + 240), 6, &l);
                if (dnsopt && l >= 4) dns = ((uint32_t)dnsopt[0] << 24) | ((uint32_t)dnsopt[1] << 16) | 
                                            ((uint32_t)dnsopt[2] << 8) | dnsopt[3];
                offered_ip = yiaddr;
                klogprintf("dhcp: OFFER ip=%u.%u.%u.%u server=%u.%u.%u.%u\n",
                    (offered_ip >> 24) & 0xFF, (offered_ip >> 16) & 0xFF, 
                    (offered_ip >> 8) & 0xFF, offered_ip & 0xFF,
                    (server_id >> 24) & 0xFF, (server_id >> 16) & 0xFF, 
                    (server_id >> 8) & 0xFF, server_id & 0xFF);
                break;
            }
        }
        klogprintf("dhcp: DISCOVER phase rx_count=%d\n", rx_count);
    }
    
    if (!offered_ip || !server_id) {
        if (g_cached_lease_valid && memcmp(g_cached_mac, mac, 6) == 0) {
            *out_lease = g_cached_lease;
            klogprintf("dhcp: no OFFER, using cached lease ip=%u.%u.%u.%u\n",
                (g_cached_lease.ip_be >> 24) & 0xFF, (g_cached_lease.ip_be >> 16) & 0xFF,
                (g_cached_lease.ip_be >> 8) & 0xFF, g_cached_lease.ip_be & 0xFF);
                kfree(frame);
            return 0;
        }
        klogprintf("dhcp: failed - no OFFER\n");
        kfree(frame);
        return -1;
    }
    
    /* PHASE 2: REQUEST -> ACK (with retries) */
    for (int req_try = 0; req_try < 3; req_try++) {
        klogprintf("dhcp: REQUEST (try=%d)\n", req_try + 1);
        int send_rc = dhcp_send_packet(mac, 3, xid, offered_ip, server_id);
        klogprintf("dhcp: REQUEST send_rc=%d\n", send_rc);
        if (send_rc != 0) {
            klogprintf("dhcp: REQUEST send failed\n");
            for (int w = 0; w < 500; w++) thread_yield();
            continue;
        }
        
        for (int w = 0; w < 100; w++) thread_yield();
        
        uint64_t start = pit_get_time_ms();
        while ((pit_get_time_ms() - start) < 4000) {
            e1000_poll();
            int n = e1000_recv_frame(frame, DHCP_FRAME_BUF);
            if (n <= 0) { thread_yield(); continue; }
            if ((size_t)n < sizeof(eth_hdr_t) + 20 + 8 + 240) continue;
            
            const eth_hdr_t *eth = (const eth_hdr_t *)frame;
            if (be16(eth->ethertype) != ETH_TYPE_IPV4) continue;
            
            const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
            size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
            if (ip->proto != 17 || ihl < 20) continue;
            
            const udp_hdr_t *udp = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
            if (be16(udp->dst_port) != UDP_PORT_DHCP_CLIENT) continue;
            
            const uint8_t *d = (const uint8_t *)udp + sizeof(udp_hdr_t);
            if (!(d[236] == 99 && d[237] == 130 && d[238] == 83 && d[239] == 99)) continue;
            
            uint32_t rx_xid = ((uint32_t)d[4] << 24) | ((uint32_t)d[5] << 16) | 
                              ((uint32_t)d[6] << 8) | d[7];
            if (rx_xid != xid) continue;
            
            uint8_t l = 0;
            const uint8_t *t = dhcp_find_opt(d + 240, (size_t)n - (sizeof(eth_hdr_t) + ihl + 8 + 240), 53, &l);
            uint8_t msg_type = (t && l == 1) ? t[0] : 0;
            
            klogprintf("dhcp: rx type=%u\n", msg_type);
            
            if (msg_type == 5) { /* ACK */
                out_lease->ip_be = offered_ip;
                out_lease->mask_be = netmask ? netmask : 0xFFFFFF00u;
                out_lease->gw_be = router ? router : server_id;
                out_lease->dns_be = dns ? dns : server_id;
                out_lease->server_be = server_id;
                g_cached_lease = *out_lease;
                memcpy(g_cached_mac, mac, 6);
                g_cached_lease_valid = 1;
                klogprintf("dhcp: ACK! ip=%u.%u.%u.%u gw=%u.%u.%u.%u\n",
                    (out_lease->ip_be >> 24) & 0xFF, (out_lease->ip_be >> 16) & 0xFF,
                    (out_lease->ip_be >> 8) & 0xFF, out_lease->ip_be & 0xFF,
                    (out_lease->gw_be >> 24) & 0xFF, (out_lease->gw_be >> 16) & 0xFF,
                    (out_lease->gw_be >> 8) & 0xFF, out_lease->gw_be & 0xFF);
                return 0;
            } else if (msg_type == 6) { /* NAK */
                klogprintf("dhcp: NAK!\n");
                return -1;
            }
        }
        klogprintf("dhcp: REQUEST timeout\n");
    }
    
    if (g_cached_lease_valid && memcmp(g_cached_mac, mac, 6) == 0) {
        *out_lease = g_cached_lease;
        klogprintf("dhcp: no ACK, using cached lease ip=%u.%u.%u.%u\n",
            (g_cached_lease.ip_be >> 24) & 0xFF, (g_cached_lease.ip_be >> 16) & 0xFF,
            (g_cached_lease.ip_be >> 8) & 0xFF, g_cached_lease.ip_be & 0xFF);
        return 0;
    }

    klogprintf("dhcp: failed - no ACK\n");
    return -1;
}
