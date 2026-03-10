/*
 * DNS Resolver - RFC 1035 compliant
 * Resolves hostnames to IPv4 (A records) via UDP port 53.
 */

#include <dns.h>
#include <string.h>

#define DNS_PORT     53
#define DNS_TYPE_A   1
#define DNS_CLASS_IN 1

static inline uint16_t get16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

int net_dns_encode_qname(const char *host, uint8_t *out, size_t cap) {
    if (!host || !out || cap == 0) return -1;
    size_t oi = 0;
    size_t li = 0;
    size_t ll = 0;
    for (;;) {
        char c = host[li];
        if (c == '.' || c == '\0') {
            if (ll > 63) return -1;
            if (oi + 1 + ll >= cap) return -1;
            out[oi++] = (uint8_t)ll;
            for (size_t k = 0; k < ll; k++) out[oi++] = (uint8_t)host[li - ll + k];
            ll = 0;
            if (c == '\0') break;
        } else {
            ll++;
        }
        li++;
    }
    if (oi >= cap) return -1;
    out[oi++] = 0;
    return (int)oi;
}

/* Build DNS query: header + qname + QTYPE A + QCLASS IN */
static int build_query(const char *hostname, uint16_t id, uint8_t *buf, size_t cap) {
    int qlen = net_dns_encode_qname(hostname, buf + 12, cap < 12 ? 0 : cap - 12);
    if (qlen < 0) return -1;
    size_t total = (size_t)(12 + qlen + 4);
    if (total > cap) return -1;

    /* Header */
    buf[0] = (uint8_t)(id >> 8);
    buf[1] = (uint8_t)(id & 0xFF);
    buf[2] = 0x01; /* RD=1 */
    buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01; /* QDCOUNT = 1 */
    buf[6] = 0x00; buf[7] = 0x00; /* ANCOUNT */
    buf[8] = 0x00; buf[9] = 0x00; /* NSCOUNT */
    buf[10] = 0x00; buf[11] = 0x00; /* ARCOUNT */

    /* QTYPE A, QCLASS IN */
    size_t off = 12 + (size_t)qlen;
    buf[off] = 0x00; buf[off + 1] = DNS_TYPE_A;
    buf[off + 2] = 0x00; buf[off + 3] = DNS_CLASS_IN;

    return (int)total;
}

/* Skip DNS name (handles compression pointers). Returns offset after name or -1 on error. */
static int skip_name(const uint8_t *msg, size_t msg_len, size_t off) {
    while (off < msg_len) {
        uint8_t b = msg[off];
        if (b == 0) return (int)(off + 1);
        if ((b & 0xC0) == 0xC0) {
            if (off + 1 >= msg_len) return -1;
            size_t ptr = (size_t)(((b & 0x3F) << 8) | msg[off + 1]);
            if (ptr >= msg_len) return -1;
            off = ptr;
            continue;
        }
        if (b > 63) return -1;
        off += 1 + (size_t)b;
        if (off > msg_len) return -1;
    }
    return -1;
}

/* Parse response, extract first A record. Returns 0 on success, -1 on failure. */
static int parse_response(const uint8_t *buf, size_t len, uint16_t expected_id, uint32_t *out_ip_be) {
    if (len < 12 || !out_ip_be) return -1;
    uint16_t id = get16(buf);
    if (id != expected_id) return -1;
    uint8_t rcode = buf[3] & 0x0F;
    if (rcode != 0) return -1; /* NXDOMAIN, SERVFAIL, etc. */
    uint16_t qdcount = get16(buf + 4);
    uint16_t ancount = get16(buf + 6);

    size_t off = 12;
    /* Skip question section */
    for (uint16_t i = 0; i < qdcount && off < len; i++) {
        int next = skip_name(buf, len, off);
        if (next < 0) return -1;
        off = (size_t)next;
        if (off + 4 > len) return -1;
        off += 4; /* QTYPE, QCLASS */
    }

    /* Scan answer RRs for type A */
    for (uint16_t i = 0; i < ancount && off < len; i++) {
        int next = skip_name(buf, len, off);
        if (next < 0) return -1;
        off = (size_t)next;
        if (off + 10 > len) return -1;
        uint16_t rtype = get16(buf + off);
        uint16_t rdlen = get16(buf + off + 8);
        off += 10;
        if (off + rdlen > len) return -1;
        if (rtype == DNS_TYPE_A && rdlen == 4) {
            *out_ip_be = (uint32_t)buf[off] << 24 | (uint32_t)buf[off + 1] << 16 |
                         (uint32_t)buf[off + 2] << 8 | (uint32_t)buf[off + 3];
            return 0;
        }
        off += rdlen;
    }
    return -1;
}

int net_dns_resolve(const char *hostname, uint32_t dns_ip_be,
                    net_dns_send_udp_fn send_udp, net_dns_recv_udp_fn recv_udp,
                    void *ctx, uint32_t *out_ip_be) {
    if (!hostname || !hostname[0] || !send_udp || !recv_udp || !out_ip_be) return -1;

    uint8_t query[512];
    uint16_t id = (uint16_t)0xD351; /* fixed ID for simplicity; matches in reply */
    int qlen = build_query(hostname, id, query, sizeof(query));
    if (qlen < 0) return -1;

    /* Ephemeral src port in high range */
    uint16_t src_port = 54321;

    if (send_udp(dns_ip_be, src_port, DNS_PORT, query, (size_t)qlen, ctx) != 0)
        return -1;

    uint8_t reply[512];
    int rlen;
    /* Retry: VMware NAT and slow networks need longer wait; 5s single shot often fails */
    for (int retry = 0; retry < 3; retry++) {
        rlen = recv_udp(src_port, dns_ip_be, DNS_PORT, reply, sizeof(reply), 8000, ctx);
        if (rlen > 0) break;
    }
    if (rlen <= 0) return -1;

    return parse_response(reply, (size_t)rlen, id, out_ip_be);
}
