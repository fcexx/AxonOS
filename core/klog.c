/*
 * core/klog.c
 * klog tools
 * Author: fcexx
*/

#include <klog.h>
#include <stdarg.h>
#include <stdio.h>
#include <heap.h>
#include <fs.h>
#include <ramfs.h>
#include <spinlock.h>
#include <string.h>
#include <apic_timer.h>

static spinlock_t klog_lock = { 0 };
static int klog_inited = 0;
/* TSC-based high-res time calibration */
uint64_t klog_tsc_base = 0;
uint64_t klog_time_base_usec = 0;
uint64_t klog_tsc_per_us = 0; /* tsc ticks per microsecond */

static inline uint64_t read_tsc(void) {
	unsigned int lo, hi;
	asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
}

/* Public: calibrate TSC against APIC timer. Safe to call early; if APIC not running it returns. */
void klog_calibrate_tsc(void) {
	if (klog_tsc_per_us != 0) return;
	if (!apic_timer_is_calibrated() && !apic_timer_is_running()) return;

	/* sample for ~10 ms to get measurable delta, but avoid long blocking:
	 * wait up to max_wait_us (200 ms) */
	const uint64_t want_us = 10000;   /* desired sample window: 10 ms */
	const uint64_t max_wait_us = 200000; /* max wait: 200 ms */

	uint64_t u1 = apic_timer_get_time_us();
	uint64_t t1 = read_tsc();
	uint64_t now = u1;
	while (1) {
		now = apic_timer_get_time_us();
		if (now > u1 && (now - u1) >= want_us) break;
		if (now > u1 && (now - u1) >= max_wait_us) {
			/* timeout: give up calibration for now */
			return;
		}
		/* small pause to avoid busy burn */
		asm volatile("pause");
	}

	uint64_t t2 = read_tsc();
	uint64_t u2 = apic_timer_get_time_us();
	uint64_t dt_usec = (u2 > u1) ? (u2 - u1) : 0;
	uint64_t dt_tsc = (t2 > t1) ? (t2 - t1) : 0;
	if (dt_usec > 0 && dt_tsc > 0) {
		klog_tsc_per_us = dt_tsc / dt_usec;
		/* store base at t2/u2 */
		klog_tsc_base = t2;
		klog_time_base_usec = u2;
		kprintf("klog: calibrated tsc_per_us=%llu\n", (unsigned long long)klog_tsc_per_us);
	}
}
/* TSC-based high-res time calibration */
/* Simple time source: use APIC timer microseconds (non-blocking). */
static uint64_t klog_get_time_us(void) {
	/* Use TSC-derived time if calibrated */
	if (klog_tsc_per_us != 0 && klog_tsc_base != 0) {
		uint64_t now_tsc = read_tsc();
		uint64_t dt_tsc = (now_tsc > klog_tsc_base) ? (now_tsc - klog_tsc_base) : 0;
		uint64_t dt_us = klog_tsc_per_us ? (dt_tsc / klog_tsc_per_us) : 0;
		return klog_time_base_usec + dt_us;
	}
	/* else fall back to APIC timer */
	return apic_timer_get_time_us();
}

void klog_init(void) {
    acquire(&klog_lock);
    if (klog_inited) { release(&klog_lock); return; }
    /* Ensure /var and /var/log exist (ramfs-backed) */
    ramfs_mkdir("/var");
    ramfs_mkdir("/var/log");
    klog_inited = 1;
    release(&klog_lock);
}

void klogprintf(const char *fmt, ...) {
    const size_t cap = 1024;
    char *buf = kmalloc(cap);
    if (!buf) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
    if (n < 0) { kfree(buf); return; }
    size_t len = (size_t)n;
    if (len >= cap) len = cap - 1;

    /* Build timestamp prefix like: [    0.000000]  */
    char tsbuf[32];
    uint64_t usec = klog_get_time_us();
    uint64_t secs = usec / 1000000;
    uint64_t micros = usec % 1000000;
    int tslen = snprintf(tsbuf, sizeof(tsbuf), "[%5llu.%06llu] ", (unsigned long long)secs, (unsigned long long)micros);
    if (tslen < 0) tslen = 0;

    /* Combine timestamp + message for console and file */
    size_t total_cap = tslen + len + 1;
    char *full = kmalloc(total_cap);
    if (full) {
        memcpy(full, tsbuf, tslen);
        memcpy(full + tslen, buf, len);
        full[tslen + len] = '\0';
        kprintf("%s", full);
    } else {
        /* Fallback: print without timestamp */
        kprintf("%s", buf);
    }

    acquire(&klog_lock);
    if (!klog_inited) {
        /* try to initialize lazily */
        ramfs_mkdir("/var");
        ramfs_mkdir("/var/log");
        klog_inited = 1;
    }
    /* best-effort append to /var/log/kernel */
    struct fs_file *f = fs_open("/var/log/kernel");
    if (!f) {
        f = fs_create_file("/var/log/kernel");
    }
    if (f) {
        /* write at end */
        if (full) {
            ssize_t wr = fs_write(f, full, tslen + len, f->size);
            (void)wr;
        } else {
            ssize_t wr = fs_write(f, buf, len, f->size);
            (void)wr;
        }
        fs_file_free(f);
    }
    if (full) kfree(full);
    kfree(buf);
    release(&klog_lock);
}


