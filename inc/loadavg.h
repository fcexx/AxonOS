#ifndef LOADAVG_H
#define LOADAVG_H

#include <stdint.h>

/* Linux-style scaled averages (divide by 65536 for floating load). */
void loadavg_second_tick(void);
void loadavg_get_user(unsigned long loads_out[3]);

#endif
