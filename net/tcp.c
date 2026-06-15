#include <net_tcp.h>
#include <heap.h>
#include <string.h>

extern void klogprintf(const char *fmt, ...);

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

static int tcp_seq_in_window(uint32_t seq, uint32_t rcv_nxt, uint32_t wnd) {
    if (wnd == 0)
        return seq == rcv_nxt;
    uint32_t last = rcv_nxt + wnd - 1u;
    return !tcp_seq_after(rcv_nxt, seq) && !tcp_seq_after(seq, last);
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
    uint8_t pseudo[12];
    pseudo[0] = (uint8_t)(src_ip_be >> 24);
    pseudo[1] = (uint8_t)(src_ip_be >> 16);
    pseudo[2] = (uint8_t)(src_ip_be >> 8);
    pseudo[3] = (uint8_t)(src_ip_be);
    pseudo[4] = (uint8_t)(dst_ip_be >> 24);
    pseudo[5] = (uint8_t)(dst_ip_be >> 16);
    pseudo[6] = (uint8_t)(dst_ip_be >> 8);
    pseudo[7] = (uint8_t)(dst_ip_be);
    pseudo[8] = 0;
    pseudo[9] = (uint8_t)IPPROTO_TCP_LOCAL;
    pseudo[10] = (uint8_t)(seg_len >> 8);
    pseudo[11] = (uint8_t)(seg_len);
    uint32_t sum = 0;
    const uint8_t *p = pseudo;
    for (size_t i = 0; i < sizeof(pseudo); i += 2)
        sum += (uint32_t)((p[i] << 8) | p[i + 1]);
    p = seg;
    size_t len = seg_len;
    while (len > 1) { sum += (uint32_t)((p[0] << 8) | p[1]); p += 2; len -= 2; }
    if (len) sum += (uint32_t)(p[0] << 8);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    uint16_t c = (uint16_t)(~sum);
    return (c == 0) ? 0xFFFFu : c;
}

static int tcp_send_seg_len(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint8_t flags,
    const uint8_t *payload, size_t payload_len, const uint8_t *opts, size_t opt_len) {
    if (!c || !ops || !ops->send_l4) return -1;
    size_t hdr_len = sizeof(tcp_hdr_t) + opt_len;
    size_t seg_len = hdr_len + payload_len;
    if (seg_len > 1500 || (hdr_len % 4u) != 0) return -1;
    uint8_t seg[1600];
    memset(seg, 0, seg_len);
    tcp_hdr_t *th = (tcp_hdr_t *)seg;
    th->src_port = be16(c->src_port);
    th->dst_port = be16(c->dst_port);
    th->seq = be32(c->snd_nxt);
    th->ack = be32(c->rcv_nxt);
    th->doff_res = (uint8_t)((hdr_len / 4u) << 4);
    th->flags = flags;
    size_t free_rx = sizeof(c->rx_buf) - c->rx_len;
    uint16_t wnd = (free_rx > 65535u) ? 65535u : (uint16_t)free_rx;
    if (wnd == 0) wnd = 1;
    th->wnd = be16(wnd);
    th->csum = 0;
    th->urg = 0;
    if (opt_len > 0 && opts)
        memcpy(seg + sizeof(tcp_hdr_t), opts, opt_len);
    if (payload_len > 0) memcpy(seg + hdr_len, payload, payload_len);
    {
        uint16_t tc = tcp_checksum(ops->local_ip_be, c->dst_ip_be, seg, seg_len);
        th->csum = be16(tc);
    }
    if (ops->send_l4(c->dst_ip_be, IPPROTO_TCP_LOCAL, seg, seg_len) != 0) return -1;
    return 0;
}

static int tcp_send_seg(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint8_t flags, const uint8_t *payload, size_t payload_len) {
    return tcp_send_seg_len(c, ops, flags, payload, payload_len, NULL, 0);
}

static int tcp_send_syn(net_tcp_conn_t *c, const net_tcp_ops_t *ops) {
    static const uint8_t mss_opt[4] = { 0x02, 0x04, 0x05, 0xB4 }; /* MSS 1460 */
    return tcp_send_seg_len(c, ops, 0x02u, NULL, 0, mss_opt, sizeof(mss_opt));
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
        /* Advance only over bytes we accepted (never ACK-skipped data). */
        if (payload_len > 0)
            c->rcv_nxt += (uint32_t)cp;
        return accepted;
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
        c->rcv_nxt += (uint32_t)accepted;
        return accepted;
    }
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
        if (n <= 0) continue;
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
        if (c->connect_pending && !c->established)
            c->connect_peer_pkts++;
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
            int rst_ok = 0;
            if (c->connect_pending && !c->established) {
                if ((th->flags & 0x10u) && ack == c->syn_isn + 1u) {
                    rst_ok = 1;
                    c->connect_refused = 1;
                }
            } else if (c->established) {
                uint32_t wnd = (uint32_t)(sizeof(c->rx_buf) - c->rx_len);
                if (wnd > 65535u)
                    wnd = 65535u;
                if (seq == c->rcv_nxt) {
                    rst_ok = 1;
                } else if (tcp_seq_in_window(seq, c->rcv_nxt, wnd)) {
                    /* Linux/RFC5961-style: in-window but non-exact RST gets a challenge ACK. */
                    (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
                    got = 1;
                    continue;
                }
            }
            if (!rst_ok) {
                got = 1;
                continue;
            }
            klogprintf("tcp: peer rst sport=%u dport=%u\n", (unsigned)sport, (unsigned)dport);
            c->established = 0;
            c->connect_pending = 0;
            c->peer_rst = 1;
            got = 1;
            continue;
        }

        /* Handshake before tcp_apply_ack — stray large ack must not move snd_una early. */
        if ((th->flags & 0x02u) && (th->flags & 0x10u) && !c->established) {
            if (!c->connect_pending || ack != c->syn_isn + 1u) {
                klogprintf("tcp: ignored syn-ack seq=%u ack=%u syn=%u\n",
                    (unsigned)seq, (unsigned)ack, (unsigned)c->syn_isn);
                got = 1;
                continue;
            }
            klogprintf("tcp: syn-ack seq=%u ack=%u sport=%u dport=%u\n",
                (unsigned)seq, (unsigned)ack, (unsigned)sport, (unsigned)dport);
            c->rcv_nxt = seq + 1;
            c->snd_una = ack;
            c->snd_nxt = ack;
            c->established = 1;
            c->connect_pending = 0;
            (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
            got = 1;
            continue;
        }

        tcp_apply_ack(c, ack);

        /* Pure ACK (no data): cumulative ack for our sends — must not be ignored. */
        if (payload_len == 0 && (th->flags & 0x10u) && !(th->flags & 0x02u) && !(th->flags & 0x01u)) {
            got = 1;
            continue;
        }

        if (payload_len > 0) {
            size_t before = c->rx_len;
            if (seq == c->rcv_nxt || seq < c->rcv_nxt) {
                (void)tcp_accept_inorder(c, seq, payload, payload_len);
                tcp_try_merge_ooo(c, ops);
            } else if (!c->ooo_valid || seq < c->ooo_seq) {
                tcp_store_ooo(c, seq, payload, payload_len);
            }
            if (c->rx_len > before && c->rx_len - before >= 512)
                klogprintf("tcp: rx +%u total=%u seq=%u\n",
                    (unsigned)(c->rx_len - before), (unsigned)c->rx_len, (unsigned)seq);
            (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
            got = 1;
        }

        if (th->flags & 0x01u) {
            if (!c->established) {
                got = 1;
                continue;
            }
            uint32_t fin_seq = seq + (uint32_t)payload_len;
            klogprintf("tcp: peer fin seq=%u rcv_nxt=%u\n", (unsigned)fin_seq, (unsigned)c->rcv_nxt);
            int fin_ok = 0;
            if (fin_seq == c->rcv_nxt) {
                c->peer_fin = 1;
                c->rcv_nxt++;
                fin_ok = 1;
            } else if (fin_seq < c->rcv_nxt) {
                c->peer_fin = 1;
                fin_ok = 1;
            }
            if (fin_ok) {
                c->established = 0;
                (void)tcp_send_seg(c, ops, 0x10u, NULL, 0);
            }
            got = 1;
        }
    }
    return got;
}

int net_tcp_connect(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t dst_ip_be, uint16_t dst_port, uint16_t src_port, uint32_t timeout_ms) {
    if (!c || !ops || !ops->time_ms || !ops->yield) return -1;
    if (ops->recv_frame) {
        uint8_t drain[TCP_FRAME_BUF];
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
    c->syn_isn = isn;
    c->snd_una = isn;
    c->snd_nxt = isn;
    c->rcv_nxt = 0;
    c->connect_pending = 1; /* before SYN: post_tx_drain must see handshake state */
    if (tcp_send_syn(c, ops) != 0) {
        c->used = 0;
        c->connect_pending = 0;
        return -1;
    }
    c->snd_nxt = isn + 1;
    klogprintf("tcp: syn sent isn=%u sport=%u dport=%u\n",
        (unsigned)isn, (unsigned)c->src_port, (unsigned)c->dst_port);
    if (timeout_ms == 0) {
        c->connect_pending = 1;
        return 0;
    }
    for (int y = 0; y < 64; y++) {
        (void)net_tcp_service(c, ops, 256);
        if (c->established) {
            c->connect_pending = 0;
            return 0;
        }
        ops->yield();
    }
    return net_tcp_connect_poll(c, ops, timeout_ms);
}

int net_tcp_server_reply_syn(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t client_seq) {
    if (!c || !ops || !ops->time_ms) return -1;
    uint32_t isn = (uint32_t)(ops->time_ms() ^ 0x81A5D77Du);
    c->used = 1;
    c->established = 0;
    c->connect_pending = 0;
    c->peer_fin = 0;
    c->peer_rst = 0;
    c->syn_isn = isn;
    c->snd_una = isn;
    /* SYN-ACK must carry SEQ=ISN; snd_nxt advances to ISN+1 only after the segment is sent. */
    c->snd_nxt = isn;
    c->rcv_nxt = client_seq + 1u;
    c->rx_len = 0;
    c->ooo_valid = 0;
    static const uint8_t mss_opt[4] = { 0x02, 0x04, 0x05, 0xB4 };
    if (tcp_send_seg_len(c, ops, 0x12u, NULL, 0, mss_opt, sizeof(mss_opt)) != 0)
        return -1;
    c->snd_nxt = isn + 1u;
    return 0;
}

int net_tcp_server_complete_ack(net_tcp_conn_t *c, uint32_t ack) {
    if (!c || !c->used || c->established) return -1;
    /* Client ACK must confirm our SYN (ISN+1). Allow retransmit ACKs in [snd_una+1, snd_nxt]. */
    if (ack < c->syn_isn + 1u || ack > c->snd_nxt) return -1;
    c->snd_una = ack;
    if (ack > c->snd_nxt)
        c->snd_nxt = ack;
    c->established = 1;
    c->connect_pending = 0;
    return 0;
}

int net_tcp_server_resend_synack(net_tcp_conn_t *c, const net_tcp_ops_t *ops) {
    if (!c || !c->used || !ops) return -1;
    uint32_t save_snd = c->snd_nxt;
    c->snd_nxt = c->syn_isn;
    static const uint8_t mss_opt[4] = { 0x02, 0x04, 0x05, 0xB4 };
    int r = tcp_send_seg_len(c, ops, 0x12u, NULL, 0, mss_opt, sizeof(mss_opt));
    if (save_snd > c->syn_isn)
        c->snd_nxt = save_snd;
    return r;
}

int net_tcp_connect_poll(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t timeout_ms) {
    if (!c || !ops || !ops->time_ms || !ops->yield) return -1;
    if (c->established) {
        c->connect_pending = 0;
        return 0;
    }
    if (c->connect_refused && !c->established) {
        c->connect_pending = 0;
        return -3;
    }
    if (!c->connect_pending && !c->used) return -1;
    uint64_t start = ops->time_ms();
    uint64_t last_syn = start;
    if (timeout_ms == 0) {
        for (int i = 0; i < 64; i++) {
            (void)net_tcp_service(c, ops, 256);
            if (c->established) {
                c->connect_pending = 0;
                return 0;
            }
            if (c->connect_refused && !c->established) {
                c->connect_pending = 0;
                return -3;
            }
        }
        return -1;
    }
    uint64_t busy_until = start + 400;
    while ((ops->time_ms() - start) < timeout_ms) {
        ops->yield();
        for (int burst = 0; burst < 16; burst++) {
            (void)net_tcp_service(c, ops, 256);
            if (c->established) {
                c->connect_pending = 0;
                return 0;
            }
            if (c->connect_refused && !c->established) {
                c->connect_pending = 0;
                return -3;
            }
        }
        uint64_t now = ops->time_ms();
        if (now - last_syn >= 1000) {
            uint32_t save = c->snd_nxt;
            c->snd_nxt = save - 1;
            {
                static const uint8_t mss_opt[4] = { 0x02, 0x04, 0x05, 0xB4 };
                (void)tcp_send_seg_len(c, ops, 0x02u, NULL, 0, mss_opt, sizeof(mss_opt));
            }
            c->snd_nxt = save;
            last_syn = now;
            klogprintf("tcp: syn rexmit sport=%u\n", (unsigned)c->src_port);
            for (int r = 0; r < 32; r++)
                (void)net_tcp_service(c, ops, 256);
            if (c->established) {
                c->connect_pending = 0;
                return 0;
            }
        }
        if (now < busy_until)
            continue;
    }
    c->connect_pending = 0;
    klogprintf("tcp: connect give up peer_pkts=%d syn=%u\n",
        c->connect_peer_pkts, (unsigned)c->syn_isn);
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
        /* Do not block until peer ACK here: HTTP servers may reply+close before send() returns. */
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

int net_tcp_flush_tx(net_tcp_conn_t *c, const net_tcp_ops_t *ops, uint32_t timeout_ms) {
    if (!c || !ops || !ops->time_ms || !ops->yield) return -1;
    if (!c->established || c->snd_una >= c->snd_nxt) return 0;
    uint64_t start = ops->time_ms();
    while ((ops->time_ms() - start) < timeout_ms) {
        (void)net_tcp_service(c, ops, 64);
        if (c->snd_una >= c->snd_nxt)
            return 0;
        ops->yield();
    }
    return (c->snd_una >= c->snd_nxt) ? 0 : -2;
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
    uint64_t start = ops->time_ms();
    uint64_t last_win = start;
    do {
        net_tcp_drain_rx(c, ops, 32);
        if (c->rx_len > 0) {
            size_t n = (c->rx_len > cap) ? cap : c->rx_len;
            memcpy(out, c->rx_buf, n);
            if (n < c->rx_len) memmove(c->rx_buf, c->rx_buf + n, c->rx_len - n);
            c->rx_len -= n;
            (void)net_tcp_window_update(c, ops);
            return (int)n;
        }
        if (c->peer_rst) return -4;
        if (c->peer_fin) return 0;
        uint64_t now = ops->time_ms();
        if (now - last_win >= 50) {
            (void)net_tcp_window_update(c, ops);
            last_win = now;
        }
        ops->yield();
    } while ((ops->time_ms() - start) < timeout_ms);
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
