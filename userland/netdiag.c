/* netdiag: syscall-only static binary for AxonOS (no libc). */
#include <stdint.h>
#include <stddef.h>

#define SYS_read         0
#define SYS_write        1
#define SYS_open         2
#define SYS_close        3
#define SYS_lseek        8
#define SYS_exit         60
#define SYS_getpid       39
#define SYS_socket       41
#define SYS_connect      42
#define SYS_sendto       44
#define SYS_recvfrom     45
#define SYS_resolve      1000

#define O_RDWR   2
#define O_CREAT  0100
#define O_TRUNC  01000

#define SEEK_SET 0

#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define IPPROTO_ICMP 1

static inline long sc6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    __asm__ volatile (
        "mov %5, %%r10\n\t"
        "mov %6, %%r8\n\t"
        "mov %7, %%r9\n\t"
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(a4), "r"(a5), "r"(a6)
        : "rcx", "r11", "r10", "r8", "r9", "memory"
    );
    return ret;
}
static inline long sc3(long n, long a1, long a2, long a3) { return sc6(n,a1,a2,a3,0,0,0); }
static inline long sc2(long n, long a1, long a2) { return sc6(n,a1,a2,0,0,0,0); }
static inline long sc1(long n, long a1) { return sc6(n,a1,0,0,0,0,0); }
static inline long sc0(long n) { return sc6(n,0,0,0,0,0,0); }

__attribute__((noreturn)) static void sys_exit(int code) { (void)sc1(SYS_exit, code); for(;;){} }

static size_t c_strlen(const char *s) { size_t n=0; while (s && s[n]) n++; return n; }
static void write_all(int fd, const char *s) { (void)sc3(SYS_write, fd, (long)s, (long)c_strlen(s)); }

static void u32_to_dec(uint32_t v, char *out) {
    char tmp[16];
    int n = 0;
    if (v == 0) { out[0] = '0'; out[1] = 0; return; }
    while (v && n < (int)sizeof(tmp)) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    for (int i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    out[n] = 0;
}

static void i64_to_dec(long v, char *out) {
    char tmp[32];
    int n = 0;
    unsigned long uv;
    if (v == 0) { out[0] = '0'; out[1] = 0; return; }
    if (v < 0) uv = (unsigned long)(-v);
    else uv = (unsigned long)v;
    while (uv && n < (int)sizeof(tmp)) { tmp[n++] = (char)('0' + (uv % 10)); uv /= 10; }
    int oi = 0;
    if (v < 0) out[oi++] = '-';
    for (int i = 0; i < n; i++) out[oi++] = tmp[n - 1 - i];
    out[oi] = 0;
}

/* Argument is Linux in_addr_t (what SYS_resolve writes), not internal kernel ip_be. */
static void ip_to_str(uint32_t s_addr, char out[32]) {
    uint8_t a = (uint8_t)(s_addr & 0xFFu);
    uint8_t b = (uint8_t)((s_addr >> 8) & 0xFFu);
    uint8_t c = (uint8_t)((s_addr >> 16) & 0xFFu);
    uint8_t d = (uint8_t)((s_addr >> 24) & 0xFFu);
    char buf[4][16];
    u32_to_dec(a, buf[0]); u32_to_dec(b, buf[1]); u32_to_dec(c, buf[2]); u32_to_dec(d, buf[3]);
    char *p = out;
    for (int i = 0; buf[0][i]; i++) *p++ = buf[0][i];
    *p++ = '.';
    for (int i = 0; buf[1][i]; i++) *p++ = buf[1][i];
    *p++ = '.';
    for (int i = 0; buf[2][i]; i++) *p++ = buf[2][i];
    *p++ = '.';
    for (int i = 0; buf[3][i]; i++) *p++ = buf[3][i];
    *p = 0;
}

static uint16_t be16(uint16_t x) { return (uint16_t)((x >> 8) | (x << 8)); }
static uint32_t be32(uint32_t v) {
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

struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t  zero[8];
};

static int test_file(void) {
    const char *path = "/root/netdiag.txt";
    long fd = sc3(SYS_open, (long)path, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (fd < 0) { write_all(2, "file: FAIL(open)\n"); return -1; }
    const char msg[] = "AxonOS netdiag file ok\n";
    if (sc3(SYS_write, fd, (long)msg, (long)(sizeof(msg)-1)) < 0) { (void)sc1(SYS_close, fd); write_all(2, "file: FAIL(write)\n"); return -1; }
    (void)sc3(SYS_lseek, fd, 0, SEEK_SET);
    char buf[64];
    long rn = sc3(SYS_read, fd, (long)buf, (long)sizeof(buf));
    (void)sc1(SYS_close, fd);
    if (rn <= 0) { write_all(2, "file: FAIL(read)\n"); return -1; }
    write_all(1, "file: ok\n");
    return 0;
}

static int test_dns(const char *host, uint32_t *out_ip_be) {
    uint32_t ip_be = 0;
    write_all(1, "dns: syscall SYS_resolve(1000) name=");
    write_all(1, host);
    write_all(1, "\n");
    long r = sc2(SYS_resolve, (long)host, (long)&ip_be);
    {
        /* Print raw return and ip for debugging. */
        char num[32];
        write_all(1, "dns: ret=");
        if (r < 0) { write_all(1, "-"); u32_to_dec((uint32_t)(-r), num); write_all(1, num); }
        else { u32_to_dec((uint32_t)r, num); write_all(1, num); }
        write_all(1, " ip=");
        char ip[32];
        ip_to_str(ip_be, ip);
        write_all(1, ip);
        write_all(1, "\n");
    }
    if (r < 0 || ip_be == 0) { write_all(2, "dns: FAIL\n"); return -1; }
    if (out_ip_be) *out_ip_be = ip_be;
    char ip[32];
    ip_to_str(ip_be, ip);
    write_all(1, "dns: ok (");
    write_all(1, host);
    write_all(1, " -> ");
    write_all(1, ip);
    write_all(1, ")\n");
    return 0;
}

static int test_ping(uint32_t dst_ip_be) {
    long fd = sc3(SYS_socket, AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (fd < 0) { write_all(2, "ping: FAIL(socket)\n"); return -1; }
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = 0;
    /* Kernel ABI: user sockaddr stores IPv4 as be32(net_ip_be). */
    dst.sin_addr = be32(dst_ip_be);
    for (int i = 0; i < 8; i++) dst.zero[i] = 0;

    uint8_t pkt[64];
    for (int i = 0; i < (int)sizeof(pkt); i++) pkt[i] = 0;
    pkt[0] = 8; /* type */
    pkt[1] = 0; /* code */
    uint16_t id = (uint16_t)(sc0(SYS_getpid) & 0xFFFF);
    pkt[4] = (uint8_t)(id >> 8); pkt[5] = (uint8_t)id;
    pkt[6] = 0; pkt[7] = 1; /* seq=1 */
    const char pay[] = "axon";
    for (int i = 0; i < (int)sizeof(pay); i++) pkt[8 + i] = (uint8_t)pay[i];
    uint16_t cs = csum16(pkt, sizeof(pkt));
    pkt[2] = (uint8_t)(cs >> 8);
    pkt[3] = (uint8_t)(cs);

    if (sc6(SYS_sendto, fd, (long)pkt, (long)sizeof(pkt), 0, (long)&dst, (long)sizeof(dst)) < 0) {
        (void)sc1(SYS_close, fd);
        write_all(2, "ping: FAIL(send)\n");
        return -1;
    }
    uint8_t rx[256];
    struct sockaddr_in src;
    uint32_t sl = (uint32_t)sizeof(src);
    long rn = sc6(SYS_recvfrom, fd, (long)rx, (long)sizeof(rx), 0, (long)&src, (long)&sl);
    (void)sc1(SYS_close, fd);
    if (rn <= 0) { write_all(2, "ping: FAIL(recv)\n"); return -1; }
    write_all(1, "ping: ok\n");
    return 0;
}

static int test_tcp_http(uint32_t dst_ip_be) {
    write_all(1, "tcp: socket(AF_INET,SOCK_STREAM,0)\n");
    long fd = sc3(SYS_socket, AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        char num[32]; i64_to_dec(fd, num);
        write_all(2, "tcp: FAIL(socket) ret="); write_all(2, num); write_all(2, "\n");
        return -1;
    }
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = be16(80);
    dst.sin_addr = dst_ip_be;
    for (int i = 0; i < 8; i++) dst.zero[i] = 0;
    write_all(1, "tcp: connect(fd,:80)\n");
    long cr = sc3(SYS_connect, fd, (long)&dst, (long)sizeof(dst));
    if (cr < 0) {
        char num[32]; i64_to_dec(cr, num);
        (void)sc1(SYS_close, fd);
        write_all(2, "tcp: FAIL(connect) ret="); write_all(2, num); write_all(2, "\n");
        return -1;
    }
    const char req[] = "GET / HTTP/1.0\r\nHost: example.com\r\nUser-Agent: axonos-netdiag\r\n\r\n";
    /* AxonOS TCP sockets send/recv via write/read syscalls (sendto handles ICMP/UDP only). */
    write_all(1, "tcp: write(fd,http_req)\n");
    long wr = sc3(SYS_write, fd, (long)req, (long)(sizeof(req)-1));
    if (wr < 0) {
        char num[32]; i64_to_dec(wr, num);
        (void)sc1(SYS_close, fd);
        write_all(2, "tcp: FAIL(send) ret="); write_all(2, num); write_all(2, "\n");
        return -1;
    }
    char buf[256];
    write_all(1, "tcp: read(fd)\n");
    long rn = sc3(SYS_read, fd, (long)buf, (long)sizeof(buf));
    (void)sc1(SYS_close, fd);
    if (rn <= 0) {
        char num[32]; i64_to_dec(rn, num);
        write_all(2, "tcp: FAIL(recv) ret="); write_all(2, num); write_all(2, "\n");
        return -1;
    }
    write_all(1, "tcp: ok\n");
    return 0;
}

__attribute__((noreturn, noinline, used)) void netdiag_entry(void) {
    write_all(1, "AxonOS netdiag (syscall-only)\n");
    int fail = 0;
    if (test_file() != 0) fail = 1;
    uint32_t ip_be = 0;
    if (test_dns("example.com", &ip_be) != 0) fail = 1;
    if (ip_be != 0) {
        if (test_ping(ip_be) != 0) fail = 1;
        if (test_tcp_http(ip_be) != 0) fail = 1;
    }
    write_all(1, fail ? "netdiag: FAIL\n" : "netdiag: OK\n");
    sys_exit(fail ? 2 : 0);
}

/* Kernel/userspace loader doesn't guarantee SysV ABI stack alignment here.
   Align RSP to 16 before any compiler-generated SSE spills (movaps). */
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "andq $-16, %rsp\n\t"
        "call netdiag_entry\n\t"
        "ud2\n\t"
    );
}

