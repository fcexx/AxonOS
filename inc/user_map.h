#pragma once

#include <stdint.h>

/* Mark [va_begin, va_end) user-accessible in current CR3 (2MiB walk). */
int user_map_mark_identity_2m(uint64_t va_begin, uint64_t va_end);

/* Change protection on [va_begin, va_end) (2MiB-oriented). prot: PROT_NONE=0, READ=1, WRITE=2, EXEC=4. */
int user_map_mprotect_range(uint64_t va_begin, uint64_t va_end, int prot);

/* Clear PTEs in range (page-oriented). */
int user_map_unmap_range(uint64_t va_begin, uint64_t va_end);
