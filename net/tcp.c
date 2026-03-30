#include <net_tcp.h>
#include <heap.h>
#include <string.h>

#define ETH_TYPE_IPV4 0x0800
#define IPPROTO_TCP_LOCAL 6

typedef struct __attribute__((packed)) {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
} eth_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t src;
    uint32_t dst;
} ipv4_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t doff_res;
    uint8_t flags;
    uint16_t wnd;
    uint16_t csum;
    uint16_t urg;
} tcp_hdr_t;

static inline uint16_t be16(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static inline uint32_t be32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) | ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

static uint16_t csum16(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    while (len > 1) { sum += (uint32_t)((p[0] << 8) | p[1]); p += 2; len -= 2; }
    if (len) sum += (uint32_t)(p[0] << 8);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t tcp_checksum(uint32_t src_ip_be, uint32_t dst_ip_be, const uint8_t *seg, size_t seg_len) {
    uint32_t sum = 0;
    sum += (src_ip_be >> 16) & 0xFFFFu;
    sum += src_ip_be & 0xFFFFu;
    sum += (dst_ip_be >> 16) & 0xFFFFu;
    sum += dst_ip_be & 0xFFFFu;
    sum += (uint32_t)IPPROTO_TCP_LOCAL;
    sum += (uint32_t)seg_len;
    const uint8_t *p = seg;
    size_t len = seg_len;
    while (len > 1) { sum += (uint32_t)((p[0] << 8) | p[1]); p += 2; len -= 2; }
    if (len) sum += (uint32_t)(p[0] << 8);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static int tcp_send_seg(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint8_t flags, const uint8_t *payload, size_t payload_len) {
    if (!c || !ops || !ops->send_l4) return -1;
    size_t seg_len = sizeof(tcp_hdr_t) + payload_len;
    if (seg_len > 1500) return -1;
    uint8_t seg[1600];
    memset(seg, 0, seg_len);
    tcp_hdr_t *th = (tcp_hdr_t *)seg;
    th->src_port = be16(c->src_port);
    th->dst_port = be16(c->dst_port);
    th->seq = be32(c->snd_nxt);
    th->ack = be32(c->rcv_nxt);
    th->doff_res = (uint8_t)((sizeof(tcp_hdr_t) / 4u) << 4);
    th->flags = flags;
    th->wnd = be16(8192);
    th->csum = 0;
    th->urg = 0;
    if (payload_len > 0) memcpy(seg + sizeof(tcp_hdr_t), payload, payload_len);
    th->csum = be16(tcp_checksum(ops->local_ip_be, c->dst_ip_be, seg, seg_len));
    if (ops->send_l4(c->dst_ip_be, IPPROTO_TCP_LOCAL, seg, seg_len) != 0) return -1;
    return 0;
}

#define TCP_FRAME_BUF 2048
int net_tcp_service(net_tcp_conn_t *c, const net_tcp_ops_t *ops, int budget) {
    if (!c || !ops || !ops->recv_frame) return -1;
    uint8_t *frame = kmalloc(TCP_FRAME_BUF);
    if (!frame) return -1;
    int got = 0;
    for (int i = 0; i < budget; i++) {
        int n = ops->recv_frame(frame, TCP_FRAME_BUF);
        if (n <= 0) break;
        if ((size_t)n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(tcp_hdr_t)) continue;
        const eth_hdr_t *eth = (const eth_hdr_t *)frame;
        if (be16(eth->ethertype) != ETH_TYPE_IPV4) continue;
        const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
        size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
        if (ip->proto != IPPROTO_TCP_LOCAL || ihl < sizeof(ipv4_hdr_t)) continue;
        if ((size_t)n < sizeof(eth_hdr_t) + ihl + sizeof(tcp_hdr_t)) continue;
        uint32_t src_ip_be = be32(ip->src);
        uint32_t dst_ip_be = be32(ip->dst);
        if (dst_ip_be != ops->local_ip_be || src_ip_be != c->dst_ip_be) continue;
        const tcp_hdr_t *th = (const tcp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
        uint16_t sport = be16(th->src_port), dport = be16(th->dst_port);
        if (sport != c->dst_port || dport != c->src_port) continue;
        uint32_t seq = be32(th->seq);
        uint32_t ack = be32(th->ack);
        size_t doff = (size_t)((th->doff_res >> 4) * 4u);
        if (doff < sizeof(tcp_hdr_t)) continue;
        if ((size_t)n < sizeof(eth_hdr_t) + ihl + doff) continue;
        size_t ip_tot = (size_t)be16(ip->total_len);
        if (ip_tot < ihl + doff) continue;
        size_t payload_len = ip_tot - ihl - doff;
        const uint8_t *payload = frame + sizeof(eth_hdr_t) + ihl + doff;

        if (ack > c->snd_una) c->snd_una = ack;
        if ((th->flags & 0x12u) == 0x12u && !c->established) {
            c->rcv_nxt = seq + 1;
            c->snd_una = ack;
            c->snd_nxt = ack;
            (void)tcp_send_seg(c, ops, 0x10u, NULL, 0); /* ACK */
            c->established = 1;
            got = 1;
            continue;
        }
        if (payload_len > 0 && seq == c->rcv_nxt) {
            size_t room = sizeof(c->rx_buf) - c->rx_len;
            size_t cp = (payload_len > room) ? room : payload_len;
            if (cp > 0) {
                memcpy(c->rx_buf + c->rx_len, payload, cp);
                c->rx_len += cp;
            }
            c->rcv_nxt += (uint32_t)payload_len;
            (void)tcp_send_seg(c, ops, 0x10u, NULL, 0); /* ACK payload */
            got = 1;
        }
        if (th->flags & 0x01u) { /* FIN */
            c->peer_fin = 1;
            if (seq == c->rcv_nxt) c->rcv_nxt++;
            (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
            got = 1;
        }
    }
    kfree(frame);
    return got;
}

int net_tcp_connect(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t dst_ip_be, uint16_t dst_port, uint16_t src_port, uint32_t timeout_ms) {
    if (!c || !ops || !ops->time_ms || !ops->yield) return -1;
    /* Drain RX so SYN-ACK is not behind stale frames (ICMP echo, DNS, etc.). */
    if (ops->recv_frame) {
        uint8_t drain[256];
        for (int d = 0; d < 64; d++) { if (ops->recv_frame(drain, sizeof(drain)) <= 0) break; }
    }
    memset(c, 0, sizeof(*c));
    c->used = 1;
    c->dst_ip_be = dst_ip_be;
    c->dst_port = dst_port;
    c->src_port = src_port;
    c->snd_una = (uint32_t)(ops->time_ms() ^ 0x71A9C33Du);
    c->snd_nxt = c->snd_una + 1;
    c->rcv_nxt = 0;
    if (tcp_send_seg(c, ops, 0x02u, NULL, 0) != 0) return -1; /* SYN */
    ops->yield();
    ops->yield();
    ops->yield();
    ops->yield();
    ops->yield(); /* give VMware/NAT time to deliver SYN-ACK */
    uint64_t start = ops->time_ms();
    while ((ops->time_ms() - start) < timeout_ms) {
        (void)net_tcp_service(c, ops, 16);
        if (c->established) return 0;
        ops->yield();
    }
    return -2; /* timeout: callers map to ETIMEDOUT */
}

int net_tcp_send(net_tcp_conn_t *c, const net_tcp_ops_t *ops, const uint8_t *data, size_t len, uint32_t timeout_ms) {
    if (!c || !ops || !data) return -1;
    if (!c->established) return -1;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 1200) chunk = 1200;
        uint32_t seq0 = c->snd_nxt;
        if (tcp_send_seg(c, ops, 0x18u, data + off, chunk) != 0) return -1; /* PSH|ACK */
        c->snd_nxt += (uint32_t)chunk;
        uint64_t start = ops->time_ms();
        while ((ops->time_ms() - start) < timeout_ms) {
            (void)net_tcp_service(c, ops, 8);
            if (c->snd_una >= seq0 + (uint32_t)chunk) break;
            ops->yield();
        }
        off += chunk;
    }
    return (int)len;
}

int net_tcp_recv(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint8_t *out, size_t cap, uint32_t timeout_ms) {
    if (!c || !ops || !out || cap == 0) return -1;
    if (c->rx_len > 0) {
        size_t n = (c->rx_len > cap) ? cap : c->rx_len;
        memcpy(out, c->rx_buf, n);
        if (n < c->rx_len) memmove(c->rx_buf, c->rx_buf + n, c->rx_len - n);
        c->rx_len -= n;
        return (int)n;
    }
    ops->yield();
    ops->yield(); /* VMware: let first response arrive */
    uint64_t start = ops->time_ms();
    while ((ops->time_ms() - start) < timeout_ms) {
        (void)net_tcp_service(c, ops, 16);
        if (c->rx_len > 0) {
            size_t n = (c->rx_len > cap) ? cap : c->rx_len;
            memcpy(out, c->rx_buf, n);
            if (n < c->rx_len) memmove(c->rx_buf, c->rx_buf + n, c->rx_len - n);
            c->rx_len -= n;
            return (int)n;
        }
        if (c->peer_fin) return 0;
        ops->yield();
    }
    return -2;
}

int net_tcp_close(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t timeout_ms) {
    if (!c || !ops) return -1;
    if (!c->used) return 0;
    if (c->established) {
        (void)tcp_send_seg(c, ops, 0x11u, NULL, 0); /* FIN|ACK */
        c->snd_nxt += 1;
        uint64_t start = ops->time_ms();
        while ((ops->time_ms() - start) < timeout_ms) {
            (void)net_tcp_service(c, ops, 8);
            if (c->peer_fin || c->snd_una >= c->snd_nxt) break;
            ops->yield();
        }
    }
    memset(c, 0, sizeof(*c));
    return 0;
}
