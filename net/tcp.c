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

static int tcp_seq_after(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) > 0;
}

static void tcp_apply_ack(net_tcp_conn_t *c, uint32_t ack) {
    if (ack == 0)
        return;
    if (tcp_seq_after(ack, c->snd_una))
        c->snd_una = ack;
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
    size_t free_rx = sizeof(c->rx_buf) - c->rx_len;
    uint16_t wnd = (free_rx > 65535u) ? 65535u : (uint16_t)free_rx;
    if (wnd == 0) wnd = 1;
    th->wnd = be16(wnd);
    th->csum = 0;
    th->urg = 0;
    if (payload_len > 0) memcpy(seg + sizeof(tcp_hdr_t), payload, payload_len);
    th->csum = be16(tcp_checksum(ops->local_ip_be, c->dst_ip_be, seg, seg_len));
    if (ops->send_l4(c->dst_ip_be, IPPROTO_TCP_LOCAL, seg, seg_len) != 0) return -1;
    return 0;
}

#define TCP_FRAME_BUF 2048

static void tcp_return_frame(const net_tcp_ops_t *ops, const uint8_t *frame, size_t n) {
    if (ops && ops->return_frame && frame && n > 0)
        (void)ops->return_frame(frame, n);
}

static void tcp_try_merge_ooo(net_tcp_conn_t *c, const net_tcp_ops_t *ops) {
    while (c->ooo_valid && c->ooo_seq == c->rcv_nxt && c->ooo_len > 0) {
        size_t room = sizeof(c->rx_buf) - c->rx_len;
        size_t cp = (c->ooo_len > room) ? room : c->ooo_len;
        if (cp == 0)
            break;
        memcpy(c->rx_buf + c->rx_len, c->ooo_buf, cp);
        c->rx_len += cp;
        c->rcv_nxt += (uint32_t)cp;
        if (cp < c->ooo_len) {
            memmove(c->ooo_buf, c->ooo_buf + cp, c->ooo_len - cp);
            c->ooo_len -= cp;
            c->ooo_seq += (uint32_t)cp;
            break;
        }
        c->ooo_valid = 0;
        c->ooo_len = 0;
    }
    if (c->ooo_valid)
        return;
    (void)ops;
}

static size_t tcp_accept_inorder(net_tcp_conn_t *c, uint32_t seq, const uint8_t *payload, size_t payload_len) {
    size_t accepted = 0;
    if (seq == c->rcv_nxt) {
        size_t room = sizeof(c->rx_buf) - c->rx_len;
        size_t cp = (payload_len > room) ? room : payload_len;
        if (cp > 0) {
            memcpy(c->rx_buf + c->rx_len, payload, cp);
            c->rx_len += cp;
            accepted = cp;
        }
    } else if (seq < c->rcv_nxt) {
        uint32_t skip_u32 = c->rcv_nxt - seq;
        size_t skip = (size_t)skip_u32;
        if (skip < payload_len) {
            size_t room = sizeof(c->rx_buf) - c->rx_len;
            size_t tail = payload_len - skip;
            size_t cp = (tail > room) ? room : tail;
            if (cp > 0) {
                memcpy(c->rx_buf + c->rx_len, payload + skip, cp);
                c->rx_len += cp;
                accepted = cp;
            }
        }
    }
    c->rcv_nxt += (uint32_t)accepted;
    return accepted;
}

static void tcp_store_ooo(net_tcp_conn_t *c, uint32_t seq, const uint8_t *payload, size_t payload_len) {
    if (!c->ooo_valid || seq < c->ooo_seq || (seq == c->ooo_seq && payload_len > c->ooo_len)) {
        if (payload_len > sizeof(c->ooo_buf))
            payload_len = sizeof(c->ooo_buf);
        memcpy(c->ooo_buf, payload, payload_len);
        c->ooo_len = payload_len;
        c->ooo_seq = seq;
        c->ooo_valid = 1;
    }
}

int net_tcp_service(net_tcp_conn_t *c, const net_tcp_ops_t *ops, int budget) {
    if (!c || !ops || !ops->recv_frame) return -1;
    uint8_t frame[TCP_FRAME_BUF];
    int got = 0;
    for (int i = 0; i < budget; i++) {
        int n = ops->recv_frame(frame, sizeof(frame));
        if (n <= 0) break;
        if ((size_t)n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t)) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        const eth_hdr_t *eth = (const eth_hdr_t *)frame;
        if (be16(eth->ethertype) != ETH_TYPE_IPV4) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
        size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
        if (ip->proto != IPPROTO_TCP_LOCAL || ihl < sizeof(ipv4_hdr_t)) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        if ((be16(ip->frag_off) & 0x1FFFu) != 0) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        if ((size_t)n < sizeof(eth_hdr_t) + ihl + sizeof(tcp_hdr_t)) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        uint32_t src_ip_be = be32(ip->src);
        uint32_t dst_ip_be = be32(ip->dst);
        if (dst_ip_be != ops->local_ip_be || src_ip_be != c->dst_ip_be) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        const tcp_hdr_t *th = (const tcp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
        uint16_t sport = be16(th->src_port), dport = be16(th->dst_port);
        if (sport != c->dst_port || dport != c->src_port) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        uint32_t seq = be32(th->seq);
        uint32_t ack = be32(th->ack);
        size_t doff = (size_t)((th->doff_res >> 4) * 4u);
        if (doff < sizeof(tcp_hdr_t) || doff > 60) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        if ((size_t)n < sizeof(eth_hdr_t) + ihl + doff) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        size_t ip_tot = (size_t)be16(ip->total_len);
        if (ip_tot < ihl + doff) {
            tcp_return_frame(ops, frame, (size_t)n);
            continue;
        }
        size_t payload_len = ip_tot - ihl - doff;
        size_t frame_pay = (size_t)n - (sizeof(eth_hdr_t) + ihl + doff);
        if (payload_len > frame_pay)
            payload_len = frame_pay;
        const uint8_t *payload = frame + sizeof(eth_hdr_t) + ihl + doff;

        if (th->flags & 0x04u) {
            c->established = 0;
            c->peer_fin = 1;
            got = 1;
            continue;
        }

        tcp_apply_ack(c, ack);

        /* Pure ACK (no data): cumulative ack for our sends — must not be ignored. */
        if (payload_len == 0 && (th->flags & 0x10u) && !(th->flags & 0x02u) && !(th->flags & 0x01u)) {
            got = 1;
            continue;
        }

        if ((th->flags & 0x12u) == 0x12u && !c->established) {
            c->rcv_nxt = seq + 1;
            c->snd_una = ack;
            c->snd_nxt = ack;
            (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
            c->established = 1;
            got = 1;
            continue;
        }

        if (payload_len > 0) {
            if (seq == c->rcv_nxt || seq < c->rcv_nxt) {
                (void)tcp_accept_inorder(c, seq, payload, payload_len);
                tcp_try_merge_ooo(c, ops);
            } else if (!c->ooo_valid || seq < c->ooo_seq) {
                tcp_store_ooo(c, seq, payload, payload_len);
            }
            (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
            got = 1;
        }

        if (th->flags & 0x01u) {
            uint32_t fin_seq = seq + (uint32_t)payload_len;
            if (fin_seq == c->rcv_nxt) {
                c->peer_fin = 1;
                c->rcv_nxt++;
            } else if (fin_seq < c->rcv_nxt) {
                c->peer_fin = 1;
            }
            (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
            got = 1;
        }
    }
    return got;
}

int net_tcp_connect(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t dst_ip_be, uint16_t dst_port, uint16_t src_port, uint32_t timeout_ms) {
    if (!c || !ops || !ops->time_ms || !ops->yield) return -1;
    if (ops->recv_frame) {
        uint8_t drain[256];
        for (int d = 0; d < 64; d++) {
            int dn = ops->recv_frame(drain, sizeof(drain));
            if (dn <= 0) break;
            if (ops->return_frame)
                ops->return_frame(drain, (size_t)dn);
        }
    }
    memset(c, 0, sizeof(*c));
    c->used = 1;
    c->dst_ip_be = dst_ip_be;
    c->dst_port = dst_port;
    c->src_port = src_port;
    uint32_t isn = (uint32_t)(ops->time_ms() ^ 0x71A9C33Du);
    c->snd_una = isn;
    c->snd_nxt = isn;
    c->rcv_nxt = 0;
    if (tcp_send_seg(c, ops, 0x02u, NULL, 0) != 0) return -1;
    c->snd_nxt = isn + 1;
    if (timeout_ms == 0) {
        c->connect_pending = 1;
        return 0;
    }
    for (int y = 0; y < 5; y++) ops->yield();
    return net_tcp_connect_poll(c, ops, timeout_ms);
}

int net_tcp_connect_poll(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t timeout_ms) {
    if (!c || !ops || !ops->time_ms || !ops->yield) return -1;
    if (c->established) {
        c->connect_pending = 0;
        return 0;
    }
    if (!c->connect_pending && !c->used) return -1;
    uint64_t start = ops->time_ms();
    uint64_t last_syn = start;
    if (timeout_ms == 0) {
        for (int i = 0; i < 32; i++) {
            (void)net_tcp_service(c, ops, 128);
            if (c->established) {
                c->connect_pending = 0;
                return 0;
            }
            if (c->peer_fin) {
                c->connect_pending = 0;
                return -2;
            }
        }
        return -1;
    }
    while ((ops->time_ms() - start) < timeout_ms) {
        (void)net_tcp_service(c, ops, 128);
        if (c->established) {
            c->connect_pending = 0;
            return 0;
        }
        if (c->peer_fin) {
            c->connect_pending = 0;
            return -2;
        }
        uint64_t now = ops->time_ms();
        if (now - last_syn >= 1000) {
            uint32_t save = c->snd_nxt;
            c->snd_nxt = save - 1;
            (void)tcp_send_seg(c, ops, 0x02u, NULL, 0);
            c->snd_nxt = save;
            last_syn = now;
        }
        ops->yield();
    }
    c->connect_pending = 0;
    return -2;
}

int net_tcp_send(net_tcp_conn_t *c, const net_tcp_ops_t *ops, const uint8_t *data, size_t len, uint32_t timeout_ms) {
    if (!c || !ops || !data) return -1;
    if (!c->established) return -1;
    (void)timeout_ms;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 1200) chunk = 1200;
        uint32_t seq0 = c->snd_nxt;
        if (tcp_send_seg(c, ops, 0x18u, data + off, chunk) != 0) return (off > 0) ? (int)off : -1;
        c->snd_nxt += (uint32_t)chunk;
        /* Do not block until peer ACK (wget hung 30s here). Pump RX briefly; ACK/data handled on read(). */
        for (int poll = 0; poll < 256; poll++) {
            (void)net_tcp_service(c, ops, 32);
            if (c->snd_una >= seq0 + (uint32_t)chunk)
                break;
            if ((poll & 31) == 31)
                ops->yield();
        }
        off += chunk;
    }
    return (int)len;
}

int net_tcp_window_update(net_tcp_conn_t *c, const net_tcp_ops_t *ops) {
    if (!c || !ops || !c->established) return -1;
    return tcp_send_seg(c, ops, 0x10u, NULL, 0);
}

static void net_tcp_drain_rx(net_tcp_conn_t *c, const net_tcp_ops_t *ops, int max_rounds) {
    for (int r = 0; r < max_rounds; r++) {
        (void)net_tcp_service(c, ops, 128);
        if (c->rx_len > 0)
            break;
    }
}

int net_tcp_recv(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint8_t *out, size_t cap, uint32_t timeout_ms) {
    if (!c || !ops || !out || cap == 0) return -1;
    if (c->rx_len > 0) {
        size_t n = (c->rx_len > cap) ? cap : c->rx_len;
        memcpy(out, c->rx_buf, n);
        if (n < c->rx_len) memmove(c->rx_buf, c->rx_buf + n, c->rx_len - n);
        c->rx_len -= n;
        (void)net_tcp_window_update(c, ops);
        return (int)n;
    }
    ops->yield();
    ops->yield();
    uint64_t start = ops->time_ms();
    uint64_t last_win = start;
    while ((ops->time_ms() - start) < timeout_ms) {
        net_tcp_drain_rx(c, ops, 16);
        if (c->rx_len > 0) {
            size_t n = (c->rx_len > cap) ? cap : c->rx_len;
            memcpy(out, c->rx_buf, n);
            if (n < c->rx_len) memmove(c->rx_buf, c->rx_buf + n, c->rx_len - n);
            c->rx_len -= n;
            (void)net_tcp_window_update(c, ops);
            return (int)n;
        }
        if (c->peer_fin) return 0;
        uint64_t now = ops->time_ms();
        if (now - last_win >= 50) {
            (void)net_tcp_window_update(c, ops);
            last_win = now;
        }
        ops->yield();
    }
    return -2;
}

int net_tcp_close(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t timeout_ms) {
    if (!c || !ops) return -1;
    if (!c->used) return 0;
    if (c->established) {
        (void)tcp_send_seg(c, ops, 0x11u, NULL, 0);
        c->snd_nxt += 1;
        uint64_t start = ops->time_ms();
        while ((ops->time_ms() - start) < timeout_ms) {
            (void)net_tcp_service(c, ops, 32);
            if (c->peer_fin || c->snd_una >= c->snd_nxt) break;
            ops->yield();
        }
    }
    memset(c, 0, sizeof(*c));
    return 0;
}
