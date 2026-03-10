/*
 * libnss_axonos - NSS module that uses AxonOS SYS_resolve (1000) for hostname lookup.
 * Provides full DNS resolution via kernel (hosts + DNS) for getaddrinfo/ping etc.
 *
 * Build: gcc -shared -fPIC -o libnss_axonos.so.2 nss_axonos.c
 * Install: cp libnss_axonos.so.2 /lib/ (or add to initfs)
 * nsswitch.conf: hosts: files axonos dns
 */

#define _GNU_SOURCE
#include <nss.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#define SYS_resolve 1000

static long do_syscall(long n, long a1, long a2) {
    long ret;
    __asm__ volatile ("syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2)
        : "rcx", "r11", "memory");
    return ret;
}

static int axonos_resolve(const char *name, uint32_t *out_ip_be) {
    long r = do_syscall(SYS_resolve, (long)name, (long)out_ip_be);
    return (r >= 0) ? 0 : (int)-r;
}

/* gethostbyname2_r - used by older code paths */
enum nss_status _nss_axonos_gethostbyname2_r(const char *name, int af,
    struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop) {
    (void)af; /* we only support IPv4 */
    if (af != 2 /* AF_INET */)
        return NSS_STATUS_UNAVAIL;
    uint32_t ip_be;
    int err = axonos_resolve(name, &ip_be);
    if (err != 0) {
        *errnop = err;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }
    /* Fill hostent: h_name, h_aliases (ptr+NULL), h_addr_list (ptr+NULL), 4-byte IP */
    size_t need = strlen(name) + 1 + 2 * sizeof(char*) + 2 * sizeof(char*) + 4;
    if (buflen < need) {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }
    char *p = buffer;
    strcpy(p, name);
    result->h_name = p;
    p += strlen(name) + 1;
    result->h_aliases = (char**)p;
    ((char**)p)[0] = NULL;
    p += 2 * sizeof(char*);
    result->h_addrtype = AF_INET;
    result->h_length = 4;
    result->h_addr_list = (char**)p;
    p += 2 * sizeof(char*);  /* leave room for [addr_ptr, NULL] */
    ((char**)result->h_addr_list)[0] = p;
    ((char**)result->h_addr_list)[1] = NULL;
    /* Store IP in network byte order */
    *(uint32_t*)p = ip_be;
    *errnop = 0;
    *h_errnop = 0;
    return NSS_STATUS_SUCCESS;
}

/* gethostbyname3_r - used by getaddrinfo */
enum nss_status _nss_axonos_gethostbyname3_r(const char *name, int af,
    struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop,
    int32_t *ttlp, char **canonp) {
    (void)ttlp;
    (void)canonp;
    return _nss_axonos_gethostbyname2_r(name, af, result, buffer, buflen, errnop, h_errnop);
}
