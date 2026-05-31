/*
 * AxonOS userspace regression harness (static ELF).
 * Build: gcc -O2 -static -Wall -Wextra -o axon-harness tools/axon-harness.c
 * Install: cp axon-harness /path/to/initfs/usr/sbin/axon-harness
 */
#include <stdint.h>
#include <stddef.h>

static int g_pass, g_fail, g_skip;
static int g_verbose = 1;

static long sys0(long n) {
	long ret;
	__asm__ volatile ("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
	return ret;
}
static long sys1(long n, long a1) {
	long ret;
	__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
	return ret;
}
static long sys2(long n, long a1, long a2) {
	long ret;
	__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
	return ret;
}
static long sys3(long n, long a1, long a2, long a3) {
	long ret;
	__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3)
		: "rcx", "r11", "memory");
	return ret;
}
static long sys6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
	long ret;
	register long r10 asm("r10") = a4;
	register long r8 asm("r8") = a5;
	register long r9 asm("r9") = a6;
	__asm__ volatile ("syscall"
		: "=a"(ret)
		: "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
		: "rcx", "r11", "memory");
	return ret;
}

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_fork 57
#define SYS_execve 59
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_getpid 39
#define SYS_brk 12
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_mprotect 10
#define SYS_gettid 186
#define SYS_clone3 435
#define SYS_nanosleep 35

struct timespec_h { long tv_sec; long tv_nsec; };

#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define PROT_READ 1
#define PROT_WRITE 2
#define O_RDONLY 0
#define ENOENT 2
#define ENOEXEC 8
#define ENOMEM 12

static void uwrite(const char *s) {
	const char *p = s;
	while (*p) p++;
	sys3(SYS_write, 1, (long)s, (long)(p - s));
}

static void uwrite_hex64(const char *pfx, unsigned long long v) {
	char buf[32];
	char *e = buf + sizeof(buf);
	*--e = '\n';
	if (!v) *--e = '0';
	while (v && e > buf) { *--e = "0123456789abcdef"[v & 15]; v >>= 4; }
	uwrite(pfx);
	while (*e) sys3(SYS_write, 1, (long)e++, 1);
}

static void uwrite_errno(const char *pfx, long rc) {
	uwrite_hex64(pfx, (unsigned long long)rc);
}

static int streq(const char *a, const char *b) {
	while (*a && *a == *b) { a++; b++; }
	return *a == *b;
}

static int filter_match(const char *name, const char *flt) {
	if (!flt || !flt[0]) return 1;
	return streq(name, flt);
}

static void pass(const char *name) {
	g_pass++;
	uwrite("PASS ");
	uwrite(name);
	uwrite("\n");
}

static void fail(const char *name, const char *detail) {
	g_fail++;
	uwrite("FAIL ");
	uwrite(name);
	if (detail && detail[0]) {
		uwrite(" — ");
		uwrite(detail);
	}
	uwrite("\n");
}

static void skip(const char *name, const char *why) {
	g_skip++;
	uwrite("SKIP ");
	uwrite(name);
	if (why && why[0]) {
		uwrite(" — ");
		uwrite(why);
	}
	uwrite("\n");
}

static volatile int g_fork_probe;

static void test_basic_syscalls(void) {
	long pid = sys0(SYS_getpid);
	if (pid > 0) pass("getpid positive");
	else fail("getpid positive", "pid<=0");
}

static void test_brk_grow(void) {
	long b0 = sys1(SYS_brk, 0);
	long b1 = sys1(SYS_brk, b0 + 0x20000);
	if (b1 == b0 + 0x20000) pass("brk grow 128KiB");
	else fail("brk grow 128KiB", "brk did not advance");
	*(volatile char *)(uintptr_t)b0 = 42;
	if (*(volatile char *)(uintptr_t)b0 == 42) pass("brk store/load");
	else fail("brk store/load", "byte mismatch");
}

static void test_mmap_anon(void) {
	long p = sys6(SYS_mmap, 0, 0x10000, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p > 0 && p < 0x10000000L) pass("mmap anon 64KiB");
	else { fail("mmap anon 64KiB", "bad addr"); return; }
	*(volatile int *)(uintptr_t)p = 0x12345678;
	if (*(volatile int *)(uintptr_t)p == 0x12345678) pass("mmap R/W");
	else fail("mmap R/W", "store failed");
	if (sys2(SYS_munmap, p, 0x10000) == 0) pass("munmap anon");
	else fail("munmap anon", "syscall failed");
}

static void test_mmap_large(void) {
	long sz = 4L * 1024 * 1024;
	long p = sys6(SYS_mmap, 0, sz, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p > 0) {
		*(volatile char *)(uintptr_t)p = 1;
		*(volatile char *)(uintptr_t)(p + sz - 4096) = 2;
		pass("mmap 4MiB touch ends");
		sys2(SYS_munmap, p, sz);
	} else fail("mmap 4MiB", "ENOMEM or bad addr");
}

static void test_mprotect(void) {
	long p = sys6(SYS_mmap, 0, 0x2000, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p <= 0) { skip("mprotect", "mmap failed"); return; }
	if (sys3(SYS_mprotect, p, 0x2000, PROT_READ) == 0) pass("mprotect RO");
	else fail("mprotect RO", "syscall error");
	if (sys3(SYS_mprotect, p, 0x2000, PROT_READ | PROT_WRITE) == 0) pass("mprotect RW restore");
	else fail("mprotect RW restore", "syscall error");
	sys2(SYS_munmap, p, 0x2000);
}

static void test_fork_basic(void) {
	g_fork_probe = 0;
	long pid = sys0(SYS_fork);
	if (pid < 0) {
		fail("fork", "syscall failed");
		uwrite_errno("  rc=0x", pid);
		return;
	}
	if (pid == 0) { g_fork_probe = 77; sys1(SYS_exit, 0); }
	int status = 0;
	long w = sys3(SYS_wait4, pid, (long)(uintptr_t)&status, 0);
	if (w == pid && g_fork_probe == 0) pass("fork/wait child exit");
	else fail("fork/wait", "parent state wrong");
}

static volatile int g_isolation_magic = 0xBEEF0001;

static void test_fork_memory_isolation(void) {
	g_isolation_magic = 0xBEEF0001;
	long pid = sys0(SYS_fork);
	if (pid < 0) {
		fail("fork isolation", "fork failed");
		uwrite_errno("  rc=0x", pid);
		return;
	}
	if (pid == 0) { g_isolation_magic = 0xCAFEBABE; sys1(SYS_exit, 0); }
	int st = 0;
	(void)sys3(SYS_wait4, pid, (long)(uintptr_t)&st, 0);
	if (g_isolation_magic == 0xBEEF0001) pass("fork memory isolation");
	else fail("fork memory isolation", "parent saw child write");
}

static void test_fork_stress(void) {
	int ok = 1;
	for (int i = 0; i < 8; i++) {
		long pid = sys0(SYS_fork);
		if (pid < 0) {
			uwrite_errno("  stress fork rc=0x", pid);
			ok = 0;
			break;
		}
		if (pid == 0) sys1(SYS_exit, (long)i);
		int st = 0;
		if (sys3(SYS_wait4, pid, (long)(uintptr_t)&st, 0) != pid) ok = 0;
	}
	if (ok) pass("fork stress 8x");
	else fail("fork stress 8x", "fork/wait chain failed");
}

static void test_stack_alignment(void) {
	uintptr_t sp;
	__asm__ volatile ("mov %%rsp, %0" : "=r"(sp));
	/* Inside a called function RSP≡8 (mod 16); aligned for the next call when (rsp+8)%16==0. */
	if (((sp + 8) & 0xF) == 0) pass("stack 16-byte aligned");
	else {
		fail("stack 16-byte aligned", "misaligned RSP");
		uwrite_hex64("  rsp=0x", (unsigned long long)sp);
		uwrite_hex64("  (rsp+8)&f=0x", (unsigned long long)((sp + 8) & 0xF));
	}
}

static void test_gettid(void) {
	long a = sys0(SYS_gettid);
	long b = sys0(SYS_getpid);
	if (a > 0) pass("gettid");
	else fail("gettid", "bad value");
	if (a == b) pass("gettid==getpid (single-thread)");
	else skip("gettid==getpid", "may differ with threads");
}

struct clone3_args {
	uint64_t flags;
	uint64_t pidfd;
	uint64_t child_tid;
	uint64_t parent_tid;
	uint64_t exit_signal;
	uint64_t stack;
	uint64_t stack_size;
	uint64_t tls;
	uint64_t set_tid;
	uint64_t cgroup;
};

static void test_clone3_thread(void) {
	static volatile int thread_done;
	static volatile int thread_ok;
	thread_done = 0;
	thread_ok = 0;
	char stack[65536] __attribute__((aligned(16)));
	uintptr_t sp = (uintptr_t)(stack + sizeof(stack));
	sp &= ~(uintptr_t)0xFULL;
	struct clone3_args cl = { 0 };
	cl.flags = 0x00000100ULL;
	cl.stack = sp;
	cl.stack_size = sizeof(stack);
	long tid = sys2(SYS_clone3, (long)(uintptr_t)&cl, (long)sizeof(cl));
	if (tid < 0) {
		skip("clone3 thread", "clone3 failed");
		uwrite_hex64("  rc=0x", (unsigned long long)tid);
		return;
	}
	if (tid == 0) {
		thread_ok = 1;
		thread_done = 1;
		sys1(SYS_exit, 0);
	}
	for (int spin = 0; spin < 5000 && !thread_done; spin++) {
		struct timespec_h ts = { 0, 1000000L };
		(void)sys2(SYS_nanosleep, (long)(uintptr_t)&ts, 0);
	}
	if (thread_ok && thread_done) pass("clone3 thread");
	else {
		fail("clone3 thread", "child did not run");
		uwrite_hex64("  done=", (unsigned long long)thread_done);
		uwrite_hex64("  ok=", (unsigned long long)thread_ok);
	}
}

static void test_open_read(void) {
	long fd = sys2(SYS_open, (long)(uintptr_t)"/usr/sbin/axon-harness", O_RDONLY);
	if (fd >= 0) {
		char buf[4];
		long n = sys3(SYS_read, fd, (long)(uintptr_t)buf, 4);
		sys1(SYS_close, fd);
		if (n == 4 && buf[0] == 0x7f && buf[1] == 'E') pass("open/read ELF magic");
		else fail("open/read ELF magic", "bad header");
	} else skip("open/read self", "not installed yet");
}

static void test_execve_enoexec_dynamic(void) {
	const char *argv[] = { "/bin/false", 0 };
	const char *envp[] = { 0 };
	long r = sys3(SYS_execve, (long)(uintptr_t)"/lib/ld-linux-x86-64.so.2",
		(long)(uintptr_t)argv, (long)(uintptr_t)envp);
	if (r == (long)-ENOEXEC) pass("execve dynamic ENOEXEC");
	else if (r == (long)-ENOENT) skip("execve dynamic", "no ld-linux in initfs");
	else {
		fail("execve dynamic ENOEXEC", "unexpected errno");
		uwrite_hex64("  rc=0x", (unsigned long long)r);
	}
}

static void test_execve_enoent(void) {
	const char *argv[] = { "/no/such/file", 0 };
	const char *envp[] = { 0 };
	long r = sys3(SYS_execve, (long)(uintptr_t)argv[0], (long)(uintptr_t)argv, (long)(uintptr_t)envp);
	if (r == (long)-ENOENT) pass("execve missing file error");
	else fail("execve missing file error", "unexpected rc");
}

static void run_one(const char *name, void (*fn)(void), const char *flt) {
	if (!filter_match(name, flt)) return;
	if (g_verbose) { uwrite("RUN  "); uwrite(name); uwrite("\n"); }
	fn();
}

int main(int argc, char **argv) {
	const char *flt = 0;
	for (int i = 1; i < argc; i++) {
		if (streq(argv[i], "-v")) {
			g_verbose = 1;
		} else if (streq(argv[i], "-q")) {
			g_verbose = 0;
		} else if (argv[i][0] != '-') {
			flt = argv[i];
		}
	}
	uwrite("AxonOS axon-harness\n");
	run_one("basic", test_basic_syscalls, flt);
	run_one("brk", test_brk_grow, flt);
	run_one("mmap", test_mmap_anon, flt);
	run_one("mmap-large", test_mmap_large, flt);
	run_one("mprotect", test_mprotect, flt);
	run_one("fork", test_fork_basic, flt);
	run_one("isolation", test_fork_memory_isolation, flt);
	run_one("fork-stress", test_fork_stress, flt);
	run_one("stack", test_stack_alignment, flt);
	run_one("tid", test_gettid, flt);
	run_one("clone3", test_clone3_thread, flt);
	run_one("open", test_open_read, flt);
	run_one("execve-enoent", test_execve_enoent, flt);
	run_one("execve-dyn", test_execve_enoexec_dynamic, flt);
	uwrite("\nSummary: PASS=");
	/* minimal decimal print */
	{
		char n[16]; int v = g_pass, i = 0;
		if (!v) n[i++] = '0';
		while (v) { n[i++] = (char)('0' + (v % 10)); v /= 10; }
		while (i--) sys3(SYS_write, 1, (long)(uintptr_t)&n[i], 1);
	}
	uwrite(" FAIL=");
	{
		char n[16]; int v = g_fail, i = 0;
		if (!v) n[i++] = '0';
		while (v) { n[i++] = (char)('0' + (v % 10)); v /= 10; }
		while (i--) sys3(SYS_write, 1, (long)(uintptr_t)&n[i], 1);
	}
	uwrite("\n");
	return g_fail ? 1 : 0;
}
