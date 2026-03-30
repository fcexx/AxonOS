/*
 * Minimal getaddrinfo/freeaddrinfo/gai_strerror using AxonOS SYS_resolve (1000).
 * Overrides libc for static builds - link -laxonos_resolve before -lc.
 */

#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>

#define SYS_resolve 1000

static long do_syscall(long n, long a1, long a2) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return ret;
}

static int axonos_resolve(const char *name, uint32_t *out_ip_be) {
    long r = do_syscall(SYS_resolve, (long)name, (long)out_ip_be);
    return (r >= 0) ? 0 : (int)-r;
}

static int parse_ipv4(const char *s, uint32_t *out) {
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255) return -1;
    *out = (a << 24) | (b << 16) | (c << 8) | d;
    return 0;
}

static int is_dotted_ip(const char *s) {
    if (!s || !*s) return 0;
    int dots = 0;
    while (*s) {
        if (*s >= '0' && *s <= '9') { s++; continue; }
        if (*s == '.') { dots++; s++; continue; }
        return 0;
    }
    return (dots == 3);
}

static uint16_t htons_u16(uint16_t v) {
    return (uint16_t)((v >> 8) | (v << 8));
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    if (!res) return EAI_FAIL;
    *res = NULL;
    int family = hints ? hints->ai_family : AF_UNSPEC;
    if (family != AF_UNSPEC && family != AF_INET) return EAI_FAMILY;

    uint32_t ip_be = 0;
    const char *resolve_name = (node && node[0]) ? node : "localhost";

    if (is_dotted_ip(resolve_name)) {
        if (parse_ipv4(resolve_name, &ip_be) != 0) return EAI_NONAME;
    } else {
        if (axonos_resolve(resolve_name, &ip_be) != 0) return EAI_NONAME;
    }

    unsigned port = 0;
    if (service && service[0]) {
        port = (unsigned)atoi(service);
        if (port > 65535) return EAI_SERVICE;
    }

    struct addrinfo *ai = calloc(1, sizeof(*ai));
    if (!ai) return EAI_MEMORY;
    struct sockaddr_in *sin = calloc(1, sizeof(*sin));
    if (!sin) { free(ai); return EAI_MEMORY; }

    sin->sin_family = AF_INET;
    sin->sin_port = htons_u16((uint16_t)port);
    sin->sin_addr.s_addr = ip_be;

    ai->ai_family = AF_INET;
    ai->ai_socktype = (hints && hints->ai_socktype) ? hints->ai_socktype : SOCK_STREAM;
    ai->ai_protocol = (hints && hints->ai_protocol) ? hints->ai_protocol : 0;
    ai->ai_addrlen = sizeof(*sin);
    ai->ai_addr = (struct sockaddr *)sin;
    ai->ai_next = NULL;
    *res = ai;
    return 0;
}

void freeaddrinfo(struct addrinfo *res) {
    while (res) {
        struct addrinfo *next = res->ai_next;
        free(res->ai_addr);
        free(res);
        res = next;
    }
}

const char *gai_strerror(int err) {
    switch (err) {
        case 0: return "Success";
        case EAI_NONAME: return "Name or service not known";
        case EAI_SERVICE: return "Servname not supported for ai_socktype";
        case EAI_FAMILY: return "ai_family not supported";
        case EAI_MEMORY: return "Memory allocation failure";
        case EAI_FAIL: return "Non-recoverable failure";
        default: return "Unknown error";
    }
}
