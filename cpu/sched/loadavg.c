#include <loadavg.h>
#include <thread.h>

#define LOAD_FIXED_1 65536ULL
/* exp(-1s / tau) * LOAD_FIXED_1 for tau = 60, 300, 900 seconds */
#define EXP_1  64453ULL
#define EXP_5  65318ULL
#define EXP_15 65463ULL

static uint64_t avenrun[3];

static void calc_load(uint64_t *load, uint64_t exp, int active) {
	uint64_t a = *load;
	*load = (a * exp + (uint64_t)active * (LOAD_FIXED_1 - exp)) >> 16;
}

void loadavg_second_tick(void) {
	int n = thread_runnable_nonidle_count();
	if (n < 0)
		n = 0;
	calc_load(&avenrun[0], EXP_1, n);
	calc_load(&avenrun[1], EXP_5, n);
	calc_load(&avenrun[2], EXP_15, n);
}

void loadavg_get_user(unsigned long loads_out[3]) {
	loads_out[0] = (unsigned long)avenrun[0];
	loads_out[1] = (unsigned long)avenrun[1];
	loads_out[2] = (unsigned long)avenrun[2];
}
