/*
 * Minimal glibc NSS "dns" module for AxonOS: hostname -> IPv4 via SYS_resolve (1000).
 * Built as shared lib on the host; embedded in the kernel payload and exposed as /lib/libnss_dns.so.2.
 */
#define _GNU_SOURCE
#include <nss.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef SYS_resolve
#define SYS_resolve 1000
#endif

/* ip_be from SYS_resolve is in_addr.s_addr layout (network-order octets in LE memory). */
static void fill_v4mapped_addr(uint8_t out[16], uint32_t ip_be)
{
    memset(out, 0, 16);
    out[10] = 0xff;
    out[11] = 0xff;
    memcpy(out + 12, &ip_be, 4);
}

enum nss_status _nss_dns_gethostbyname3_r(const char *name, int af, struct hostent *result,
                                          char *buffer, size_t buflen, int *errnop,
                                          int *h_errnop, int32_t *ttlp, char **canon);

/* glibc NSS dispatches gethostbyname2_r / gethostbyname_r into the dns module; without these
 * symbols the DSO can fail to bind and hosts: dns never runs (wget: bad address). */

enum nss_status _nss_dns_gethostbyname2_r(const char *name, int af, struct hostent *result,
                                           char *buffer, size_t buflen, int *errnop,
                                           int *h_errnop)
{
    if (!name || !name[0]) {
        if (h_errnop) *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }
    return _nss_dns_gethostbyname3_r(name, af, result, buffer, buflen, errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_dns_gethostbyname_r(const char *name, struct hostent *result,
                                          char *buffer, size_t buflen, int *errnop,
                                          int *h_errnop)
{
    if (!name || !name[0]) {
        if (h_errnop) *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }
    return _nss_dns_gethostbyname3_r(name, AF_INET, result, buffer, buflen, errnop, h_errnop, NULL, NULL);
}

enum nss_status _nss_dns_gethostbyname4_r(const char *name, struct gaih_addrtuple **pat,
                                           char *buffer, size_t buflen, int *errnop,
                                           int *h_errnop, int32_t *ttlp)
{
    if (!name || !pat || !buffer || !errnop || !h_errnop)
        return NSS_STATUS_UNAVAIL;

    *pat = NULL;
    if (ttlp)
        *ttlp = 0;

    uint32_t ip_be = 0;
    if (syscall(SYS_resolve, name, &ip_be) != 0) {
        int e = errno;
        if (e == EIO || e == ENOENT) {
            *errnop = e;
            *h_errnop = HOST_NOT_FOUND;
            return NSS_STATUS_NOTFOUND;
        }
        *errnop = e;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }

    if (buflen < 2 * sizeof(struct gaih_addrtuple)) {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }

    struct gaih_addrtuple *t6 = (struct gaih_addrtuple *)buffer;
    struct gaih_addrtuple *t4 = (struct gaih_addrtuple *)(buffer + sizeof(struct gaih_addrtuple));
    memset(t6, 0, sizeof(*t6));
    memset(t4, 0, sizeof(*t4));
    t6->next = t4;
    t6->name = NULL;
    t4->next = NULL;
    t4->name = NULL;
    /* glibc getaddrinfo asserts IN6_IS_ADDR_V4MAPPED for AF_INET6 results. */
    t6->family = AF_INET6;
    fill_v4mapped_addr((uint8_t *)t6->addr, ip_be);
    t6->scopeid = 0;
    t4->family = AF_INET;
    t4->addr[0] = ip_be;
    t4->scopeid = 0;
    *pat = t6;
    *errnop = 0;
    *h_errnop = NETDB_SUCCESS;
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_dns_gethostbyname3_r(const char *name, int af, struct hostent *result,
                                            char *buffer, size_t buflen, int *errnop,
                                            int *h_errnop, int32_t *ttlp, char **canon)
{
    if (af != AF_INET && af != AF_INET6 && af != AF_UNSPEC)
        return NSS_STATUS_NOTFOUND;
    if (!name || !result || !buffer || !errnop || !h_errnop)
        return NSS_STATUS_UNAVAIL;
    if (canon)
        *canon = NULL;
    if (ttlp)
        *ttlp = 0;

    uint32_t ip_be = 0;
    if (syscall(SYS_resolve, name, &ip_be) != 0) {
        int e = errno;
        if (e == EIO || e == ENOENT) {
            *errnop = e;
            *h_errnop = HOST_NOT_FOUND;
            return NSS_STATUS_NOTFOUND;
        }
        *errnop = e;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }

    size_t nl = strlen(name) + 1;
    /* AF_UNSPEC: glibc getaddrinfo expects IPv6 v4-mapped, not bare AF_INET. */
    int out_af = (af == AF_INET) ? AF_INET : AF_INET6;
    size_t addr_len = (out_af == AF_INET6) ? 16u : 4u;
    size_t off_addr = (nl + sizeof(void *) - 1) & ~(sizeof(void *) - 1);
    size_t need = off_addr + addr_len + sizeof(char *) * 2 + sizeof(char *) * 2;

    if (buflen < need) {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }

    memcpy(buffer, name, nl);
    if (out_af == AF_INET6)
        fill_v4mapped_addr((uint8_t *)(buffer + off_addr), ip_be);
    else
        memcpy(buffer + off_addr, &ip_be, 4);

    char **addrlist = (char **)(buffer + off_addr + addr_len);
    char **aliases = addrlist + 2;
    aliases[0] = NULL;
    addrlist[0] = buffer + off_addr;
    addrlist[1] = NULL;

    memset(result, 0, sizeof(*result));
    result->h_name = buffer;
    result->h_aliases = aliases;
    result->h_addrtype = out_af;
    result->h_length = (int)addr_len;
    result->h_addr_list = addrlist;

    *errnop = 0;
    *h_errnop = NETDB_SUCCESS;
    return NSS_STATUS_SUCCESS;
}
