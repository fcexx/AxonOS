/*
 * core/klog.c — kernel ring buffer log + /var/log/kernel
 *
 * Until klog_init(): messages go only to console + a fixed early buffer (no VFS).
 * klog_init() creates /var/log, flushes the early buffer to /var/log/kernel, then
 * each line is appended in a single fs_write (one contiguous buffer: timestamp + text).
 */

#include <klog.h>
#include <debug.h>
#include <vga.h>
#include <stdarg.h>
#include <stdio.h>
#include <fs.h>
#include <ramfs.h>
#include <stat.h>
#include <spinlock.h>
#include <string.h>
#include <apic_timer.h>
#include <pit.h>
#include <console.h>
#include <devfs.h>

static spinlock_t klog_lock;
static int klog_inited;

/* Early log ring: no kmalloc, safe before klog_init() and avoids fragile heap+vfs races. */
#define KLOG_EARLY_SZ (96 * 1024)
static char klog_early[KLOG_EARLY_SZ];
static size_t klog_early_used;

#define KLOG_TS_MAX 48
#define KLOG_MSG_MAX 900
#define KLOG_OUT_MAX 1024
static char klog_out[KLOG_OUT_MAX];

uint64_t klog_tsc_base = 0;
uint64_t klog_time_base_usec = 0;
uint64_t klog_tsc_per_us = 0;

static void klog_console_write_sync_tty(const char *s, size_t n) {
	/* Keep devfs tty cursor in sync for kernel log output so that interactive
	   tty programs don't overwrite logs (klogprintf bypasses /dev/tty writes). */
	if (!s || n == 0) return;
	struct devfs_tty *tty = devfs_get_tty_by_index(devfs_get_active());
	if (!tty) {
		/* Fall back to VGA printf path. */
		kprintf("%.*s", (int)n, s);
		return;
	}
	for (size_t i = 0; i < n; i++) {
		console_set_cursor(tty->cursor_x, tty->cursor_y);
		console_putc_tty_literal((uint8_t)s[i], tty->current_attr ? tty->current_attr : 0x07);
		console_get_cursor(&tty->cursor_x, &tty->cursor_y);
	}
}

static inline uint64_t read_tsc(void) {
	unsigned int lo, hi;
	asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
}

void klog_calibrate_tsc(void) {
	if (klog_tsc_per_us != 0) return;

	if (apic_timer_is_running()) {
		const uint64_t want_us = 10000;
		const uint64_t max_wait_us = 200000;

		uint64_t u1 = apic_timer_get_time_us();
		uint64_t t1 = read_tsc();
		uint64_t now = u1;
		while (1) {
			now = apic_timer_get_time_us();
			if (now > u1 && (now - u1) >= want_us) break;
			if (now > u1 && (now - u1) >= max_wait_us) return;
			asm volatile("pause");
		}

		uint64_t t2 = read_tsc();
		uint64_t u2 = apic_timer_get_time_us();
		uint64_t dt_usec = (u2 > u1) ? (u2 - u1) : 0;
		uint64_t dt_tsc = (t2 > t1) ? (t2 - t1) : 0;
		if (dt_usec > 0 && dt_tsc > 0) {
			klog_tsc_per_us = dt_tsc / dt_usec;
			klog_tsc_base = t2;
			klog_time_base_usec = u2;
			kprintf("klog: calibrated tsc_per_us=%llu\n", (unsigned long long)klog_tsc_per_us);
		}
		return;
	}

	/* PIT fallback (e.g. VirtualBox): APIC stopped but timer_ticks still advance from IRQ0. */
	if (pit_get_frequency() == 0) return;

	const uint64_t want_ms = 10;
	uint64_t tick1 = timer_ticks;
	uint64_t t1 = read_tsc();
	uint64_t want_ticks = (pit_get_frequency() * want_ms + 999) / 1000;
	if (want_ticks == 0) want_ticks = 1;
	uint64_t spins = 0;
	while (timer_ticks - tick1 < want_ticks) {
		if (++spins > 5000000000ull) return;
		asm volatile("pause");
	}
	uint64_t t2 = read_tsc();
	uint64_t tick2 = timer_ticks;
	uint64_t dt_ticks = tick2 - tick1;
	uint32_t pf = pit_get_frequency();
	uint64_t dt_usec = (pf > 0 && dt_ticks > 0) ? (dt_ticks * 1000000ull) / (uint64_t)pf : 0;
	uint64_t dt_tsc = (t2 > t1) ? (t2 - t1) : 0;
	if (dt_usec > 0 && dt_tsc > 0) {
		klog_tsc_per_us = dt_tsc / dt_usec;
		klog_tsc_base = t2;
		klog_time_base_usec = pit_get_time_ms() * 1000;
		kprintf("klog: calibrated tsc_per_us=%llu (PIT)\n", (unsigned long long)klog_tsc_per_us);
	}
}

static uint64_t klog_get_time_us(void) {
	if (klog_tsc_per_us != 0 && klog_tsc_base != 0) {
		uint64_t now_tsc = read_tsc();
		uint64_t dt_tsc = (now_tsc > klog_tsc_base) ? (now_tsc - klog_tsc_base) : 0;
		uint64_t dt_us = klog_tsc_per_us ? (dt_tsc / klog_tsc_per_us) : 0;
		return klog_time_base_usec + dt_us;
	}
	if (apic_timer_is_running())
		return apic_timer_get_time_us();
	return pit_get_time_ms() * 1000;
}

static void klog_early_append(const char *p, size_t n) {
	if (!p || n == 0) return;
	if (klog_early_used + n > KLOG_EARLY_SZ) {
		static int once;
		if (!once) {
			once = 1;
			kprintf("klog: early buffer full; dropping further pre-init lines\n");
		}
		return;
	}
	memcpy(klog_early + klog_early_used, p, n);
	klog_early_used += n;
}

/* Caller must hold klog_lock + irq disabled. */
static void klog_flush_early_to_file(void) {
	if (klog_early_used == 0) return;
	struct fs_file *f = fs_create_file("/var/log/kernel");
	if (!f)
		f = fs_open("/var/log/kernel");
	if (!f)
		return;
	(void)fs_write(f, klog_early, klog_early_used, 0);
	fs_file_free(f);
	klog_early_used = 0;
}

void klog_init(void) {
	unsigned long irqf;
	acquire_irqsave(&klog_lock, &irqf);
	if (klog_inited) {
		release_irqrestore(&klog_lock, irqf);
		return;
	}
	(void)ramfs_mkdir("/var");
	(void)ramfs_mkdir("/var/log");
	klog_flush_early_to_file();
	klog_inited = 1;
	release_irqrestore(&klog_lock, irqf);
}

void klogprintf(const char *fmt, ...) {
	unsigned long irqf;
	acquire_irqsave(&klog_lock, &irqf);

	char msg[KLOG_MSG_MAX];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(msg, sizeof msg, fmt, ap);
	va_end(ap);
	if (n < 0) {
		release_irqrestore(&klog_lock, irqf);
		return;
	}
	size_t len = (size_t)n;
	if (len >= sizeof msg)
		len = sizeof msg - 1;
	if (len == 0 || msg[len - 1] != '\n') {
		if (len + 1 < sizeof msg)
			msg[len++] = '\n';
		else if (len > 0)
			msg[len - 1] = '\n';
	}

	char ts[KLOG_TS_MAX];
	uint64_t usec = klog_get_time_us();
	uint64_t secs = usec / 1000000;
	uint64_t micros = usec % 1000000;
	int tn = snprintf(ts, sizeof ts, "[%5llu.%06llu] ",
			  (unsigned long long)secs, (unsigned long long)micros);
	size_t tslen = 0;
	if (tn > 0) {
		if ((size_t)tn < sizeof ts)
			tslen = (size_t)tn;
		else
			tslen = sizeof ts - 1u;
	}

	size_t outlen = tslen + len;
	if (outlen + 1 > sizeof klog_out) {
		size_t room = sizeof klog_out - tslen - 1u;
		if (room > len)
			room = len;
		memcpy(klog_out, ts, tslen);
		memcpy(klog_out + tslen, msg, room);
		outlen = tslen + room;
	} else {
		memcpy(klog_out, ts, tslen);
		memcpy(klog_out + tslen, msg, len);
	}
	klog_out[outlen] = '\0';

	klog_console_write_sync_tty(klog_out, outlen);

	if (!klog_inited) {
		klog_early_append(klog_out, outlen);
#ifdef QEMU_LOG_ENABLE
		qemu_debug_printf("%s", klog_out);
#endif
		release_irqrestore(&klog_lock, irqf);
		return;
	}

	struct fs_file *f = fs_open("/var/log/kernel");
	if (!f)
		f = fs_create_file("/var/log/kernel");
	if (f) {
		size_t off = (size_t)f->size;
		struct stat st;
		if (vfs_fstat(f, &st) == 0 && st.st_size >= 0)
			off = (size_t)st.st_size;
		(void)fs_write(f, klog_out, outlen, off);
		fs_file_free(f);
	}

#ifdef QEMU_LOG_ENABLE
	qemu_debug_printf("%s", klog_out);
#endif
	release_irqrestore(&klog_lock, irqf);
}
