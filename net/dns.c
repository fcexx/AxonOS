#include <stddef.h>
#include <stdint.h>

/* Minimal DNS helper module placeholder.
   Kept separate from syscall.c so resolver-related logic can move here incrementally. */

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
