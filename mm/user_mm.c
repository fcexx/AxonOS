#include <user_mm.h>
#include <exec.h>

int user_mm_range_fits(uintptr_t addr, uint64_t len, uintptr_t top_exclusive) {
    if (len == 0)
        return 0;
    uintptr_t cap = top_exclusive;
    if (cap > (uintptr_t)USER_STACK_TOP)
        cap = (uintptr_t)USER_STACK_TOP;
    uint64_t a = (uint64_t)addr;
    uint64_t end = a + len;
    if (end < a)
        return 0;
    if (a >= (uint64_t)cap)
        return 0;
    if (end > (uint64_t)cap)
        return 0;
    return 1;
}
