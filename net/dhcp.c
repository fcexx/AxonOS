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

/* IP checksum over wire-order (big-endian) 16-bit words. */
static uint16_t ip_checksum_be(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += ((uint16_t)data[i] << 8) | data[i + 1];
    if (len & 1)
        sum += (uint16_t)data[len - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFFu);
}

static void ip_put_csum(ipv4_hdr_t *ip, size_t ihl) {
    ip->csum = 0;
    uint16_t c = ip_checksum_be((const uint8_t *)ip, ihl);
    uint8_t *p = (uint8_t *)&ip->csum;
    p[0] = (uint8_t)(c >> 8);
    p[1] = (uint8_t)(c & 0xFF);
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
static uint32_t dhcp_last_logged_ip;
static uint8_t g_cached_mac[6];
static int g_cached_lease_valid = 0;

void dhcp_invalidate_cache(void) {
    g_cached_lease_valid = 0;
    memset(&g_cached_lease, 0, sizeof(g_cached_lease));
    memset(g_cached_mac, 0, sizeof(g_cached_mac));
}

static uint32_t dhcp_read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

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
    ip_put_csum(ip, sizeof(*ip));
    
    /* UDP header */
    udp_hdr_t *udp = (udp_hdr_t *)(frm + sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t));
    udp->src_port = be16(UDP_PORT_DHCP_CLIENT);
    udp->dst_port = be16(UDP_PORT_DHCP_SERVER);
    udp->len = be16((uint16_t)(sizeof(udp_hdr_t) + o));
    udp->csum = 0;
    memcpy((uint8_t *)udp + sizeof(udp_hdr_t), pkt, o);
    
    int sr = -1;
    for (int t = 0; t < 4 && sr < 0; t++)
        sr = e1000_send_frame(frm, frm_len);
    kfree(frm);
    return (sr < 0) ? -1 : 0;
}

#define DHCP_DISCOVER_TRIES  6
#define DHCP_REQUEST_TRIES   4
#define DHCP_RX_TIMEOUT_MS   10000u
#define DHCP_LINK_SETTLE_MS  4000u
#define DHCP_LINK_WAIT_MS    15000u

static int dhcp_parse_offer(const uint8_t *d, size_t opts_len, uint32_t xid,
                            uint32_t *offered_ip, uint32_t *server_id,
                            uint32_t *netmask, uint32_t *router, uint32_t *dns) {
    if (d[0] != 2) /* BOOTREPLY */
        return 0;

    uint32_t rx_xid = dhcp_read_be32(&d[4]);
    if (rx_xid != xid)
        return 0;

    uint8_t l = 0;
    const uint8_t *t = dhcp_find_opt(d + 240, opts_len, 53, &l);
    uint8_t msg_type = (t && l == 1) ? t[0] : 0;
    /* OFFER = 2; some firmware only sets op=2 without option 53. */
    if (msg_type != 0 && msg_type != 2)
        return 0;

    uint32_t yiaddr = dhcp_read_be32(&d[16]);
    uint32_t ciaddr = dhcp_read_be32(&d[12]);
    uint32_t siaddr = dhcp_read_be32(&d[20]);
    uint32_t ip = yiaddr ? yiaddr : ciaddr;

    const uint8_t *yip = dhcp_find_opt(d + 240, opts_len, 50, &l);
    if (!ip && yip && l == 4) ip = dhcp_read_be32(yip);

    const uint8_t *sid = dhcp_find_opt(d + 240, opts_len, 54, &l);
    uint32_t srv = (sid && l == 4) ? dhcp_read_be32(sid) : (siaddr ? siaddr : 0);

    const uint8_t *msk = dhcp_find_opt(d + 240, opts_len, 1, &l);
    uint32_t mask = (msk && l == 4) ? dhcp_read_be32(msk) : 0;
    const uint8_t *rtr = dhcp_find_opt(d + 240, opts_len, 3, &l);
    uint32_t gw = (rtr && l >= 4) ? dhcp_read_be32(rtr) : 0;
    const uint8_t *dnsopt = dhcp_find_opt(d + 240, opts_len, 6, &l);
    uint32_t dnsrv = (dnsopt && l >= 4) ? dhcp_read_be32(dnsopt) : 0;

    if (!ip) return 0;

    *offered_ip = ip;
    *server_id = srv;
    *netmask = mask;
    *router = gw;
    *dns = dnsrv;
    return 1;
}

static int dhcp_l2_ipv4_offset(const uint8_t *frame, int n, uint16_t *out_eth_type) {
    if (n < 14 || !out_eth_type)
        return -1;
    size_t off = 12;
    uint16_t et = (uint16_t)(((uint16_t)frame[off] << 8) | frame[off + 1]);
    /* 802.1Q / 802.1ad VLAN tags (common on VMware bridged). */
    if ((et == 0x8100u || et == 0x88A8u) && n >= (int)(off + 6)) {
        off += 4;
        et = (uint16_t)(((uint16_t)frame[off] << 8) | frame[off + 1]);
    }
    *out_eth_type = et;
    return (int)(off + 2); /* start of IPv4 header */
}

static int dhcp_handle_rx_frame(const uint8_t *frame, int n, uint32_t xid,
                                uint32_t *offered_ip, uint32_t *server_id,
                                uint32_t *netmask, uint32_t *router, uint32_t *dns) {
    uint16_t eth_type = 0;
    int ip_off = dhcp_l2_ipv4_offset(frame, n, &eth_type);
    if (ip_off < 0)
        return 0;
    if (eth_type != 0x0800u)
        return 0;
    if (n < ip_off + 20 + 8 + 240)
        return 0;

    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + ip_off);
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ip->proto != 17 || ihl < 20)
        return 0;
    if (be16(ip->flags_frag) & 0x3FFFu)
        return 0;

    const udp_hdr_t *udp = (const udp_hdr_t *)(frame + ip_off + ihl);
    uint16_t sport = be16(udp->src_port);
    uint16_t dport = be16(udp->dst_port);
    if (sport != UDP_PORT_DHCP_SERVER || dport != UDP_PORT_DHCP_CLIENT)
        return 0;

    uint16_t ulen = be16(udp->len);
    if (ulen < 8 + 240 || (size_t)n < (size_t)ip_off + ihl + ulen)
        return 0;

    const uint8_t *d = (const uint8_t *)udp + sizeof(udp_hdr_t);
    if (!(d[236] == 99 && d[237] == 130 && d[238] == 83 && d[239] == 99))
        return 0;

    size_t bootp_len = (size_t)ulen - 8;
    size_t opts_len = bootp_len > 240 ? bootp_len - 240 : 0;

    if (dhcp_parse_offer(d, opts_len, xid, offered_ip, server_id, netmask, router, dns))
        return 1;
    return 0;
}

static int dhcp_try_ack_frame(const uint8_t *frame, int n, uint32_t xid) {
    uint16_t eth_type = 0;
    int ip_off = dhcp_l2_ipv4_offset(frame, n, &eth_type);
    if (ip_off < 0 || eth_type != 0x0800u || n < ip_off + 20 + 8 + 240)
        return 0;

    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + ip_off);
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ip->proto != 17 || ihl < 20)
        return 0;

    const udp_hdr_t *udp = (const udp_hdr_t *)(frame + ip_off + ihl);
    if (be16(udp->src_port) != UDP_PORT_DHCP_SERVER ||
        be16(udp->dst_port) != UDP_PORT_DHCP_CLIENT)
        return 0;

    uint16_t ulen = be16(udp->len);
    if (ulen < 8 + 240 || (size_t)n < (size_t)ip_off + ihl + ulen)
        return 0;

    const uint8_t *d = (const uint8_t *)udp + sizeof(udp_hdr_t);
    if (!(d[236] == 99 && d[237] == 130 && d[238] == 83 && d[239] == 99))
        return 0;
    if (dhcp_read_be32(&d[4]) != xid)
        return 0;

    size_t bootp_len = (size_t)ulen - 8;
    size_t opts_len = bootp_len > 240 ? bootp_len - 240 : 0;
    uint8_t l = 0;
    const uint8_t *t = dhcp_find_opt(d + 240, opts_len, 53, &l);
    uint8_t msg_type = (t && l == 1) ? t[0] : 0;
    if (msg_type == 0 && d[0] == 2)
        msg_type = 5;
    if (msg_type == 5)
        return 1;
    if (msg_type == 6)
        return -1;
    return 0;
}

int dhcp_acquire(const uint8_t mac[6], dhcp_lease_t *out_lease) {
    if (!mac || !out_lease) return -1;
    
    memset(out_lease, 0, sizeof(*out_lease));

    /* Wait for link (VMware bridged WiFi can take many seconds after host roam). */
    uint64_t link_wait = pit_get_time_ms();
    while (!e1000_is_ready() && (pit_get_time_ms() - link_wait) < DHCP_LINK_WAIT_MS)
        thread_yield();
    if (!e1000_is_ready())
        klogprintf("dhcp: link not up after %us, proceeding anyway\n",
                   (unsigned)(DHCP_LINK_WAIT_MS / 1000u));

    /* Settle after link-up so bridged vSwitch/DHCP relay is ready. */
    uint64_t settle = pit_get_time_ms();
    while ((pit_get_time_ms() - settle) < DHCP_LINK_SETTLE_MS)
        thread_yield();

    e1000_flush_rx();
    
    uint32_t xid = (uint32_t)(pit_get_ticks() ^ 0xA5F0C31Du);
    uint32_t offered_ip = 0, server_id = 0, netmask = 0, router = 0, dns = 0;
    uint8_t *frame = kmalloc(DHCP_FRAME_BUF);
    if (!frame) return -1;
    
    /* PHASE 1: DISCOVER -> OFFER (with retries) */
    int rx_count = 0;
    for (int disc_try = 0; disc_try < DHCP_DISCOVER_TRIES && !offered_ip; disc_try++) {
        if (disc_try > 0)
            xid = (uint32_t)(pit_get_ticks() ^ 0xA5F0C31Du ^ (uint32_t)disc_try);
        if (dhcp_send_packet(mac, 1, xid, 0, 0) != 0) {
            for (int w = 0; w < 500; w++) thread_yield();
            continue;
        }
        
        /* Busy-poll RX right after TX (VMware often answers in <1ms). */
        for (int burst = 0; burst < 8000; burst++) {
            e1000_poll();
            int n = e1000_recv_frame(frame, DHCP_FRAME_BUF);
            if (n > 0) {
                rx_count++;
                if (dhcp_handle_rx_frame(frame, n, xid, &offered_ip, &server_id,
                                         &netmask, &router, &dns))
                    goto discover_done;
            }
        }
        
        uint64_t start = pit_get_time_ms();
        while ((pit_get_time_ms() - start) < DHCP_RX_TIMEOUT_MS) {
            e1000_poll();
            int got_pkt = 0;
            for (;;) {
                int n = e1000_recv_frame(frame, DHCP_FRAME_BUF);
                if (n <= 0)
                    break;
                got_pkt = 1;
                rx_count++;
                if (dhcp_handle_rx_frame(frame, n, xid, &offered_ip, &server_id,
                                         &netmask, &router, &dns))
                    goto discover_done;
            }
            if (offered_ip)
                goto discover_done;
            if (!got_pkt)
                thread_yield();
        }
discover_done:
        (void)rx_count;
    }
    
    if (!offered_ip) {
        klogprintf("dhcp: failed - no OFFER\n");
        kfree(frame);
        return -1;
    }
    if (!server_id)
        server_id = router ? router : offered_ip;
    
    /* PHASE 2: REQUEST -> ACK (with retries) */
    for (int req_try = 0; req_try < DHCP_REQUEST_TRIES; req_try++) {
        int send_rc = dhcp_send_packet(mac, 3, xid, offered_ip, server_id);
        if (send_rc != 0) {
            for (int w = 0; w < 500; w++) thread_yield();
            continue;
        }
        
        for (int burst = 0; burst < 8000; burst++) {
            e1000_poll();
            int n = e1000_recv_frame(frame, DHCP_FRAME_BUF);
            if (n <= 0)
                continue;
            int ar = dhcp_try_ack_frame(frame, n, xid);
            if (ar == 1)
                goto got_ack;
            if (ar < 0) {
                klogprintf("dhcp: NAK!\n");
                kfree(frame);
                return -1;
            }
        }

        uint64_t start = pit_get_time_ms();
        while ((pit_get_time_ms() - start) < DHCP_RX_TIMEOUT_MS) {
            e1000_poll();
            int got_pkt = 0;
            for (;;) {
                int n = e1000_recv_frame(frame, DHCP_FRAME_BUF);
                if (n <= 0)
                    break;
                got_pkt = 1;
                int ar = dhcp_try_ack_frame(frame, n, xid);
                if (ar == 1)
                    goto got_ack;
                if (ar < 0) {
                    klogprintf("dhcp: NAK!\n");
                    kfree(frame);
                    return -1;
                }
            }
            if (!got_pkt)
                thread_yield();
        }
    }
    
    klogprintf("dhcp: failed - no ACK\n");
    kfree(frame);
    return -1;

got_ack:
    out_lease->ip_be = offered_ip;
    out_lease->mask_be = netmask ? netmask : 0xFFFFFF00u;
    out_lease->gw_be = router ? router : server_id;
    out_lease->dns_be = dns ? dns : server_id;
    out_lease->server_be = server_id;
    g_cached_lease = *out_lease;
    memcpy(g_cached_mac, mac, 6);
    g_cached_lease_valid = 1;
    if (offered_ip != dhcp_last_logged_ip) {
        dhcp_last_logged_ip = offered_ip;
        klogprintf("dhcp: ACK! ip=%u.%u.%u.%u gw=%u.%u.%u.%u\n",
            (out_lease->ip_be >> 24) & 0xFF, (out_lease->ip_be >> 16) & 0xFF,
            (out_lease->ip_be >> 8) & 0xFF, out_lease->ip_be & 0xFF,
            (out_lease->gw_be >> 24) & 0xFF, (out_lease->gw_be >> 16) & 0xFF,
            (out_lease->gw_be >> 8) & 0xFF, out_lease->gw_be & 0xFF);
    }
    kfree(frame);
    return 0;
}
