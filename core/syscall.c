#include <axonos.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <thread.h>
#include <fs.h>
#include <mmio.h>
#include <heap.h>
#include <syscall.h>
#include <gdt.h>
#include <paging.h>
#include <exec.h>
#include <pit.h>
#include <ext2.h>
#include <devfs.h>

extern void kprintf(const char *fmt, ...);

/* Saved user RSP for syscall_entry64 (single-core, single-syscall-in-flight). */
uint64_t syscall_user_rsp_saved = 0;
/* Set to non-zero when user called exit/exit_group; handled in syscall_entry64. */
uint64_t syscall_exit_to_shell_flag = 0;


extern void ring0_shell(void);

__attribute__((noreturn)) void syscall_return_to_shell(void) {
    syscall_exit_to_shell_flag = 0;
    thread_set_current_user(NULL);
    ring0_shell();
    for (;;) { asm volatile("sti; hlt" ::: "memory"); }
}

extern void syscall_entry64(void);

static inline uint64_t msr_read_u64(uint32_t msr) {
    uint32_t lo = 0, hi = 0;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}
static inline void msr_write_u64(uint32_t msr, uint64_t v) {
    uint32_t lo = (uint32_t)(v & 0xFFFFFFFFu);
    uint32_t hi = (uint32_t)(v >> 32);
    asm volatile("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

enum {
    MSR_EFER  = 0xC0000080u,
    MSR_STAR  = 0xC0000081u,
    MSR_LSTAR = 0xC0000082u,
    MSR_FMASK = 0xC0000084u,
    MSR_FS_BASE = 0xC0000100u,
};

/* Helper: copy up to `max` bytes from user pointer `uptr` into newly allocated buffer.
   Returns allocated buffer (must be kfreed) and sets out_copied. On error returns NULL. */
static void *copy_from_user_safe(const void *uptr, size_t count, size_t max, size_t *out_copied) {
    if (!uptr || count == 0) { if (out_copied) *out_copied = 0; return NULL; }
    size_t to_copy = count < max ? count : max;
    void *buf = kmalloc(to_copy);
    if (!buf) { if (out_copied) *out_copied = 0; return NULL; }
    /* Simple safety: only copy user addresses below 4GiB (identity mapped) */
    if ((uintptr_t)uptr + to_copy > (uintptr_t)MMIO_IDENTITY_LIMIT) {
        kfree(buf); if (out_copied) *out_copied = 0; return NULL;
    }
    memcpy(buf, uptr, to_copy);
    if (out_copied) *out_copied = to_copy;
    return buf;
}

/* Minimal errno set (Linux). glibc expects negative errno in RAX on failure. */
#define EPERM   1
#define ENOENT  2
#define EBADF   9
#define EFAULT  14
#define EINVAL  22
#define ENOTTY  25
#define ESRCH   3
#define ENOSYS  38
#define ENOMEM  12
#define ERANGE  34
#define EMFILE  24
/* filename too long */
#define ENAMETOOLONG 36
static uint64_t last_syscall_debug = 0;
static inline uint64_t ret_err(int e) {
    /* Log ENOSYS occurrences for the user shell (tid==3) to help musl compatibility debugging. */
    thread_t *t = thread_get_current_user();
    if (!t) t = thread_current();
    if (e == ENOSYS && t && (t->tid == 3)) {
        qemu_debug_printf("ret_err: ENOSYS returned for pid=%u syscall=%u\n",
                (unsigned long long)(t->tid ? t->tid : 1),
                (unsigned long long)last_syscall_debug);
    }
    return (uint64_t)(-(int64_t)e);
}

static void resolve_user_path(thread_t *cur, const char *path_u, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    out[0] = '\0';
    if (!path_u || !path_u[0]) {
        strncpy(out, "/", out_cap);
        out[out_cap - 1] = '\0';
        return;
    }
    if (path_u[0] == '/') {
        strncpy(out, path_u, out_cap);
        out[out_cap - 1] = '\0';
        return;
    }
    const char *cwd = (cur && cur->cwd[0]) ? cur->cwd : "/";
    if (strcmp(cwd, "/") == 0) {
        snprintf(out, out_cap, "/%s", path_u);
    } else {
        snprintf(out, out_cap, "%s/%s", cwd, path_u);
    }
}

static int copy_to_user_safe(void *uptr, const void *kptr, size_t n) {
    if (!uptr || !kptr || n == 0) return -1;
    if ((uintptr_t)uptr + n > (uintptr_t)MMIO_IDENTITY_LIMIT) return -1;
    memcpy(uptr, kptr, n);
    return 0;
}

static int copy_from_user_raw(void *kdst, const void *usrc, size_t n) {
    if (!kdst || !usrc || n == 0) return -1;
    if ((uintptr_t)usrc + n > (uintptr_t)MMIO_IDENTITY_LIMIT) return -1;
    memcpy(kdst, usrc, n);
    return 0;
}

/* Minimal tty state for job control-ish ioctls (single session). */
static uint64_t user_pgrp = 1;

/* Minimal signal emulation (we do not actually deliver signals yet).
   We only keep per-signal "handlers" so libc/busybox doesn't abort early. */
typedef void (*user_sighandler_t)(int);
static user_sighandler_t user_sig_handlers[65]; /* 1..64 */
static uint64_t user_sig_mask = 0;

/* Simple getrandom() state (non-crypto). */
static uint32_t user_rand_state = 0xA53C9E11u;

/* Very small user VM allocator (identity-mapped).
   We keep it below the user stack region and below the kernel heap floor. */
static uintptr_t user_mmap_next = 0;
static uintptr_t user_brk_base = 0;
static uintptr_t user_brk_cur = 0;

static inline uintptr_t align_up_u(uintptr_t v, uintptr_t a) { return (v + (a - 1)) & ~(a - 1); }

static int mark_user_identity_range_2m_sys(uint64_t va_begin, uint64_t va_end) {
    extern uint64_t page_table_l4[];
    if (va_end < va_begin) return -1;
    uint64_t begin = va_begin & ~((uint64_t)(PAGE_SIZE_2M - 1));
    uint64_t end = (va_end + PAGE_SIZE_2M - 1) & ~((uint64_t)(PAGE_SIZE_2M - 1));
    for (uint64_t va = begin; va < end; va += PAGE_SIZE_2M) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        uint64_t *l4 = (uint64_t*)page_table_l4;
        if (!(l4[l4i] & PG_PRESENT)) return -1;
        l4[l4i] |= PG_US;
        uint64_t *l3 = (uint64_t*)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) return -1;
        l3[l3i] |= PG_US;
        uint64_t l3e = l3[l3i];
        if (l3e & PG_PS_2M) { invlpg((void*)(uintptr_t)va); continue; }
        uint64_t *l2 = (uint64_t*)(uintptr_t)(l3e & ~0xFFFULL);
        if (!(l2[l2i] & PG_PRESENT)) return -1;
        l2[l2i] |= PG_US;
        invlpg((void*)(uintptr_t)va);
    }
    return 0;
}

/* Common syscall dispatcher used by both int0x80 and SYSCALL.
   Calling convention follows Linux x86_64: num + up to 6 args. */  
uint64_t syscall_do(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    thread_t *cur = thread_get_current_user();
    if (!cur) cur = thread_current();
    if (!cur) return ret_err(EPERM);

    /* record last syscall for debug logging of ENOSYS */
    last_syscall_debug = num;
    if (num != 1) qemu_debug_printf("SYSCALL: num=%u\n", num);

    switch (num) {
        case SYS_set_tid_address: {
            /* set_tid_address(int *tidptr): used by glibc to set clear_child_tid. */
            uint64_t tidptr = a1;
            if (tidptr != 0) {
                if (tidptr >= (uint64_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                cur->clear_child_tid = tidptr;
            }
            return (uint64_t)(cur->tid ? cur->tid : 1);
        }
        case SYS_set_robust_list:
            /* set_robust_list(head, len): accept (no robust futex handling yet) */
            (void)a1; (void)a2;
            return 0;
        case SYS_rseq:
            /* rseq is optional optimization. Tell libc it's not available. */
            (void)a1; (void)a2; (void)a3; (void)a4;
            return ret_err(ENOSYS);
        case SYS_prlimit64: {
            /* prlimit64(pid, resource, new_limit, old_limit)
               Minimal: return conservative limits for current process only (pid==0 or self).
               We ignore new_limit for now. */
            uint64_t pid = a1;
            int resource = (int)a2;
            const void *new_u = (const void*)(uintptr_t)a3;
            void *old_u = (void*)(uintptr_t)a4;
            (void)new_u;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (!(pid == 0 || pid == self)) return ret_err(ESRCH);

            /* Linux rlimit64 */
            struct rlimit64_k { uint64_t rlim_cur; uint64_t rlim_max; } rl;
            enum {
                RLIMIT_STACK = 3,
                RLIMIT_NOFILE = 7,
            };
            if (resource == RLIMIT_STACK) {
                rl.rlim_cur = 8ULL * 1024ULL * 1024ULL;
                rl.rlim_max = 8ULL * 1024ULL * 1024ULL;
            } else if (resource == RLIMIT_NOFILE) {
                rl.rlim_cur = (uint64_t)THREAD_MAX_FD;
                rl.rlim_max = (uint64_t)THREAD_MAX_FD;
            } else {
                /* unknown resource: report "infinite" */
                rl.rlim_cur = ~0ULL;
                rl.rlim_max = ~0ULL;
            }
            if (old_u) {
                if (copy_to_user_safe(old_u, &rl, sizeof(rl)) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_readlink: {
            /* readlink(pathname, buf, bufsiz) */
            const char *path = (const char*)(uintptr_t)a1;
            char *buf = (char*)(uintptr_t)a2;
            size_t bufsiz = (size_t)a3;
            if (!path || !buf) return ret_err(EFAULT);
            if ((uintptr_t)path >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)buf + bufsiz > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);

            /* Provide /proc/self/exe for libc/busybox: point to current "process name". */
            const char *target = NULL;
            if (strcmp(path, "/proc/self/exe") == 0) {
                /* thread name often contains the executed path passed to execve */
                target = cur->name[0] ? cur->name : "/bin/busybox";
            } else {
                return ret_err(ENOENT);
            }
            size_t L = strlen(target);
            if (bufsiz == 0) return ret_err(EINVAL);
            if (L > bufsiz) L = bufsiz;
            memcpy(buf, target, L);
            return (uint64_t)L; /* note: no NUL terminator */
        }
        case SYS_getrandom: {
            void *bufp = (void*)(uintptr_t)a1;
            size_t len = (size_t)a2;
            (void)a3; /* flags */
            if (!bufp) return ret_err(EFAULT);
            if ((uintptr_t)bufp + len > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            uint8_t *p = (uint8_t*)bufp;
            for (size_t i = 0; i < len; i++) {
                /* xorshift32 */
                user_rand_state ^= user_rand_state << 13;
                user_rand_state ^= user_rand_state >> 17;
                user_rand_state ^= user_rand_state << 5;
                p[i] = (uint8_t)(user_rand_state & 0xFF);
            }
            return (uint64_t)len;
        }
        case SYS_clock_gettime: {
            int clk = (int)a1;
            void *tp = (void*)(uintptr_t)a2;
            if (!tp) return ret_err(EFAULT);
            if ((uintptr_t)tp + sizeof(int64_t) * 2 > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            /* We only provide monotonic-ish time since boot. */
            enum { CLOCK_REALTIME = 0, CLOCK_MONOTONIC = 1 };
            if (!(clk == CLOCK_REALTIME || clk == CLOCK_MONOTONIC)) return ret_err(EINVAL);
            uint64_t ms = pit_get_time_ms();
            int64_t sec = (int64_t)(ms / 1000ULL);
            int64_t nsec = (int64_t)((ms % 1000ULL) * 1000000ULL);
            /* struct timespec { long tv_sec; long tv_nsec; } on x86_64 */
            ((int64_t*)tp)[0] = sec;
            ((int64_t*)tp)[1] = nsec;
            return 0;
        }
        case SYS_uname: {
            void *up = (void*)(uintptr_t)a1;
            if (!up) return ret_err(EFAULT);
            /* Linux: struct utsname has 6 fields of 65 bytes each. */
            struct utsname_k {
                char sysname[65];
                char nodename[65];
                char release[65];
                char version[65];
                char machine[65];
                char domainname[65];
            } u;
            memset(&u, 0, sizeof(u));
            /* Keep it simple and stable. */
            snprintf(u.sysname, sizeof(u.sysname), "%s", OS_NAME);
            snprintf(u.nodename, sizeof(u.nodename), "axon");
            snprintf(u.release, sizeof(u.release), "%s", OS_VERSION);
            snprintf(u.version, sizeof(u.version), "AxonOS");
            snprintf(u.machine, sizeof(u.machine), "x86_64");
            snprintf(u.domainname, sizeof(u.domainname), "local");
            if (copy_to_user_safe(up, &u, sizeof(u)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_getcwd: {
            char *bufp = (char*)(uintptr_t)a1;
            size_t size = (size_t)a2;
            const char *cwd = (cur && cur->cwd[0]) ? cur->cwd : "/";
            size_t need = strlen(cwd) + 1;
            if (!bufp) return ret_err(EFAULT);
            if (size < need) return ret_err(EINVAL);
            if ((uintptr_t)bufp + need > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            memcpy(bufp, cwd, need);
            return (uint64_t)need;
        }
        case SYS_chdir: {
            const char *path_u = (const char*)(uintptr_t)a1;
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct fs_file *f = fs_open(path);
            if (!f) return ret_err(ENOENT);
            int is_dir = (f->type == FS_TYPE_DIR);
            fs_file_free(f);
            if (!is_dir) return ret_err(EINVAL);
            size_t n = strlen(path);
            while (n > 1 && path[n - 1] == '/') path[--n] = '\0';
            strncpy(cur->cwd, path, sizeof(cur->cwd));
            cur->cwd[sizeof(cur->cwd) - 1] = '\0';
            return 0;
        }
        case SYS_writev: {
            int fd = (int)a1;
            const void *iov_u = (const void*)(uintptr_t)a2;
            int iovcnt = (int)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!iov_u) return ret_err(EFAULT);
            if (iovcnt <= 0 || iovcnt > 64) return ret_err(EINVAL);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);

            struct iovec_k { uint64_t base; uint64_t len; };
            struct iovec_k iov[64];
            size_t bytes = (size_t)iovcnt * sizeof(iov[0]);
            if (copy_from_user_raw(iov, iov_u, bytes) != 0) return ret_err(EFAULT);

            uint64_t total = 0;
            for (int i = 0; i < iovcnt; i++) {
                const void *base = (const void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                /* Clamp per-chunk to avoid huge kmalloc; write in pieces. */
                size_t off = 0;
                while (off < len) {
                    size_t chunk = len - off;
                    if (chunk > 4096) chunk = 4096;
                    size_t copied = 0;
                    void *tmp = copy_from_user_safe((const uint8_t*)base + off, chunk, 4096, &copied);
                    if (!tmp) return ret_err(EFAULT);
                    ssize_t wr = fs_write(f, tmp, copied, f->pos);
                    kfree(tmp);
                    if (wr <= 0) return (total > 0) ? total : ret_err(EINVAL);
                    f->pos += (size_t)wr;
                    total += (uint64_t)wr;
                    off += (size_t)wr;
                    if ((size_t)wr < copied) break;
                }
            }
            return total;
        }
        case SYS_getpid:
            return (uint64_t)(cur->tid ? cur->tid : 1);
        case SYS_getppid:
            return 1;
        case SYS_gettid:
            return (uint64_t)(cur->tid ? cur->tid : 1);
        case SYS_getuid:
        case SYS_geteuid:
            return (uint64_t)cur->euid;
        case SYS_getgid:
        case SYS_getegid:
            return (uint64_t)cur->egid;
        case SYS_setsid:
            user_pgrp = (uint64_t)(cur->tid ? cur->tid : 1);
            return user_pgrp;
        case SYS_getpgrp:
            return user_pgrp;
        case SYS_setpgid:
            /* Minimal setpgid implementation:
               If pid==0 use current tid; if pgid==0 use pid.
               Update global user_pgrp for simplicity (single pgrp model). */
            {
                int pid = (int)a1;
                int pgid = (int)a2;
                uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
                if (pid == 0) pid = (int)self;
                if (pgid == 0) pgid = pid;
                if ((uint64_t)pid != self) {
                    /* we only support changing current process group's pgid for now */
                    kprintf("sys_setpgid: pid=%d pgid=%d -> ESRCH (only current pid supported)\n", pid, pgid);
                    return ret_err(ESRCH);
                }
                if (pgid != 0) user_pgrp = (uint64_t)pgid;
                kprintf("sys_setpgid: pid=%d pgid=%d -> OK (user_pgrp=%llu)\n", pid, pgid, (unsigned long long)user_pgrp);
                return 0;
            }
        case SYS_tgkill: {
            /* tgkill(tgid, tid, sig): used by glibc for raise()/pthread_kill()/abort().
               We do not implement full signal delivery yet, but we MUST make SIGABRT
               actually terminate the process; otherwise glibc falls back to "hlt/ud2"
               in userspace, which triggers #GP and looks like a hang/crash.
               For other signals we currently treat it as a no-op for self. */
            uint64_t tgid = a1;
            uint64_t tid  = a2;
            uint64_t sig  = a3;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (tgid == self && tid == self) {
                if (sig == 6 /* SIGABRT */) {
                    kprintf("sys_tgkill: pid=%llu self-targeted SIGABRT received; ignoring auto-exit for now\n",
                            (unsigned long long)self);
                    /* Previously we forced exit to avoid userspace UD2; now treat as no-op to avoid premature shell exit. */
                    return 0;
                }
                return 0;
            }
            return ret_err(ESRCH);
        }
        case 62: { /* kill(pid, sig) */
            int pid = (int)a1;
            int sig = (int)a2;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (pid > 0) {
                thread_t *t = thread_get(pid);
                if (!t) return ret_err(ESRCH);
                /* sig==0 used for existence check */
                if (sig == 0) return 0;
                /* We don't deliver signals yet; accept SIGABRT to exit */
                if (sig == 6 /* SIGABRT */) {
                    kprintf("sys_kill: pid=%d sig=SIGABRT received for pid=%d; ignoring auto-exit\n", sig, pid);
                    return 0;
                }
                return 0;
            } else if (pid == 0) {
                /* broadcast to process group: accept */
                (void)sig;
                return 0;
            } else {
                /* other semantics (negative pids) not supported */
                return ret_err(EINVAL);
            }
        }
        case 32: { /* dup(oldfd) */
            int oldfd = (int)a1;
            if (oldfd < 0 || oldfd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[oldfd];
            if (!f) return ret_err(EBADF);
            for (int i = 0; i < THREAD_MAX_FD; i++) {
                if (cur->fds[i] == NULL) {
                    cur->fds[i] = f;
                    if (f->refcount <= 0) f->refcount = 1;
                    else f->refcount++;
                    return (uint64_t)i;
                }
            }
            return ret_err(EMFILE);
        }
        case 33: { /* access(pathname, mode) */
            const char *path_u = (const char*)(uintptr_t)a1;
            int mode = (int)a2;
            (void)mode;
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct stat st;
            if (vfs_stat(path, &st) != 0) return ret_err(ENOENT);
            /* Minimal: if file exists, report accessible (no permissions model yet) */
            return 0;
        }
        case 269: /* faccessat(dirfd, pathname, mode, flags) */
        case 439: /* faccessat2(dirfd, pathname, mode, flags, ...) */
        {
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            int mode = (int)a3;
            int flags = (int)a4;
            (void)mode; (void)flags;
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[512];
            if (path_u[0] == '/') {
                /* absolute */
                strncpy(path, path_u, sizeof(path));
                path[sizeof(path)-1] = '\0';
            } else {
                /* relative: if dirfd == AT_FDCWD (-100) use cwd, else try to use fd's path */
                const int AT_FDCWD = -100;
                if (dirfd == AT_FDCWD) {
                    resolve_user_path(cur, path_u, path, sizeof(path));
                } else if (dirfd >= 0 && dirfd < THREAD_MAX_FD && cur->fds[dirfd]) {
                    const char *base = cur->fds[dirfd]->path ? cur->fds[dirfd]->path : "/";
                    size_t bl = strlen(base);
                    if (bl + 1 + strlen(path_u) + 1 > sizeof(path)) return ret_err(ENAMETOOLONG);
                    /* if base is not a directory path, strip filename to parent */
                    char basecopy[512];
                    strncpy(basecopy, base, sizeof(basecopy));
                    basecopy[sizeof(basecopy)-1] = '\0';
                    /* ensure ends with slash */
                    if (basecopy[bl-1] != '/') {
                        /* try to find last slash */
                        char *s = strrchr(basecopy, '/');
                        if (s) *(s+1) = '\0';
                        else { basecopy[0] = '/'; basecopy[1] = '\0'; }
                    }
                    snprintf(path, sizeof(path), "%s%s", basecopy, path_u);
                } else {
                    /* fallback to cwd */
                    resolve_user_path(cur, path_u, path, sizeof(path));
                }
            }
            struct stat st;
            if (vfs_stat(path, &st) != 0) return ret_err(ENOENT);
            return 0;
        }
        case 72: { /* fcntl(fd, cmd, arg) - minimal support */
            int fd = (int)a1;
            int cmd = (int)a2;
            int arg = (int)a3;
            enum {
                F_DUPFD = 0,
                F_GETFD = 1,
                F_SETFD = 2,
                F_GETFL = 3,
                F_SETFL = 4,
            };
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (cmd == F_GETFD) {
                /* return flags (no FD_CLOEXEC support) */
                return 0;
            } else if (cmd == F_SETFD) {
                /* accept silently */
                (void)arg;
                return 0;
            } else if (cmd == F_GETFL) {
                /* return file status flags (blocking) */
                return 0;
            } else if (cmd == F_SETFL) {
                /* accept (e.g., O_NONBLOCK) but we don't implement it fully */
                (void)arg;
                return 0;
            } else if (cmd == F_DUPFD) {
                /* simple duplicate to next available fd */
                for (int i = 0; i < THREAD_MAX_FD; i++) {
                    if (cur->fds[i] == NULL) {
                        cur->fds[i] = f;
                        if (f->refcount <= 0) f->refcount = 1;
                        else f->refcount++;
                        return (uint64_t)i;
                    }
                }
                return ret_err(EMFILE);
            }
            return ret_err(EINVAL);
        }
        case 270: {
            /* Minimal no-op for syscall 270 to satisfy musl checks (accept and return 0). */
            return 0;
        }
        case 121: { /* getpgid(pid) */
            int pid = (int)a1;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (pid == 0) {
                return (uint64_t)user_pgrp;
            }
            if ((uint64_t)pid == self) return (uint64_t)user_pgrp;
            /* We only support querying current process for now */
            return ret_err(ESRCH);
        }
        case SYS_rt_sigaction: {
            /* rt_sigaction(int signum, const struct sigaction *act,
                            struct sigaction *oldact, size_t sigsetsize) */
            int signum = (int)a1;
            const void *act_u = (const void*)(uintptr_t)a2;
            void *old_u = (void*)(uintptr_t)a3;
            size_t sigsetsize = (size_t)a4;
            if (signum <= 0 || signum >= (int)(sizeof(user_sig_handlers)/sizeof(user_sig_handlers[0]))) return ret_err(EINVAL);

            /* Linux kernel ABI for rt_sigaction on x86_64:
               struct {
                 void (*handler)(int);
                 unsigned long flags;
                 void (*restorer)(void);
                 sigset_t mask;   // size = sigsetsize (glibc usually passes 8)
               }
               Total size = 24 + sigsetsize.
               Important: do NOT over-copy here; glibc may pass a tiny 32-byte object. */
            if (sigsetsize == 0 || sigsetsize > 128) return ret_err(EINVAL);
            const size_t act_sz = 24 + sigsetsize;
            struct k_sa {
                uint64_t handler;
                uint64_t flags;
                uint64_t restorer;
                uint8_t  mask[128];
            } sa;

            if (old_u) {
                memset(&sa, 0, sizeof(sa));
                sa.handler = (uint64_t)(uintptr_t)user_sig_handlers[signum];
                if (copy_to_user_safe(old_u, &sa, act_sz) != 0) return ret_err(EFAULT);
            }
            if (act_u) {
                memset(&sa, 0, sizeof(sa));
                if (copy_from_user_raw(&sa, act_u, act_sz) != 0) return ret_err(EFAULT);
                user_sig_handlers[signum] = (user_sighandler_t)(uintptr_t)sa.handler;
            }
            return 0;
        }
        case SYS_rt_sigprocmask: {
            /* rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset, size_t sigsetsize)
               Keep a single 64-bit mask; accept common calls from libc. */
            int how = (int)a1;
            const void *set_u = (const void*)(uintptr_t)a2;
            void *old_u = (void*)(uintptr_t)a3;
            (void)a4;

            if (old_u) {
                uint64_t old = user_sig_mask;
                if (copy_to_user_safe(old_u, &old, sizeof(old)) != 0) return ret_err(EFAULT);
            }
            if (set_u) {
                uint64_t setv = 0;
                if (copy_from_user_raw(&setv, set_u, sizeof(setv)) != 0) return ret_err(EFAULT);
                if (how == 0 /* SIG_BLOCK */) user_sig_mask |= setv;
                else if (how == 1 /* SIG_UNBLOCK */) user_sig_mask &= ~setv;
                else if (how == 2 /* SIG_SETMASK */) user_sig_mask = setv;
                else return ret_err(EINVAL);
            }
            return 0;
        }
        case SYS_ioctl: {
            int fd = (int)a1;
            uint64_t req = a2;
            void *argp = (void*)(uintptr_t)a3;
            /* Map negative fds to fd 0 (controlling/stdin) to be tolerant of libc behavior. */
            if (fd < 0) {
                qemu_debug_printf("sys_ioctl: pid=%llu got negative fd=%d, mapping to fd 0\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1), fd);
                fd = 0;
            }
            qemu_debug_printf("sys_ioctl: pid=%llu fd=%d req=0x%llx arg=%p\n",
                    (unsigned long long)(cur->tid ? cur->tid : 1), fd, (unsigned long long)req, argp);
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (!devfs_is_tty_file(f)) {
                /* Debug: report unexpected ioctl target (not a tty) to kernel log */
                qemu_debug_printf("ioctl: fd=%d not a tty (path=%s, driver_priv=%p) req=0x%llx\n",
                        fd, f->path ? f->path : "(null)", f->driver_private, (unsigned long long)req);
                return ret_err(ENOTTY);
            }

            /* Common ioctl numbers on Linux x86_64 */
            enum {
                TCGETS    = 0x5401,
                TCSETS    = 0x5402,
                TCSETSW   = 0x5403,
                TCSETSF   = 0x5404,
                TIOCSCTTY = 0x540E,
                TIOCGPGRP = 0x540F,
                TIOCSPGRP = 0x5410,
                TIOCGWINSZ= 0x5413,
                TIOCSWINSZ= 0x5414,
            };

            /* no ioctl tracing in release builds */

            /* Kernel ABI structs (minimal) */
            struct winsize { uint16_t ws_row, ws_col, ws_xpixel, ws_ypixel; };
            typedef uint32_t tcflag_t;
            typedef uint8_t  cc_t;
            typedef uint32_t speed_t;
            struct termios_k {
                tcflag_t c_iflag;
                tcflag_t c_oflag;
                tcflag_t c_cflag;
                tcflag_t c_lflag;
                cc_t c_line;
                cc_t c_cc[19];
                speed_t c_ispeed;
                speed_t c_ospeed;
            };

            if (req == TIOCGWINSZ) {
                if (!argp) return ret_err(EFAULT);
                struct winsize ws = { .ws_row = 25, .ws_col = 80, .ws_xpixel = 0, .ws_ypixel = 0 };
                if (copy_to_user_safe(argp, &ws, sizeof(ws)) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (req == TIOCSWINSZ) {
                /* accept setting window size silently */
                if (!argp) return ret_err(EFAULT);
                /* optionally we could copy_from_user and store winsize, but accept for now */
                qemu_debug_printf("ioctl: TIOCSWINSZ on fd=%d\n", fd);
                return 0;
            }
            if (req == TIOCSCTTY) {
                /* Make ioctl(TIOCSCTTY) attach this thread to the tty as controlling tty.
                   If attaching is not possible, accept silently. */
                qemu_debug_printf("ioctl: TIOCSCTTY on fd=%d (arg=%p)\n", fd, argp);
                {
                    thread_t *curth = thread_current();
                    if (curth) {
                        /* try to attach current thread to this tty */
                        (void)devfs_tty_attach_thread(f, curth);
                    }
                }
                return 0;
            }
            if (req == TIOCGPGRP) {
                if (!argp) return ret_err(EFAULT);
                /* Try to return tty-specific foreground pgrp, fallback to global user_pgrp */
                int pgrp = devfs_tty_get_fg_pgrp(f);
                if (pgrp < 0) pgrp = (int)(user_pgrp);
                qemu_debug_printf("ioctl: TIOCGPGRP on fd=%d -> returning pgrp=%d\n", fd, pgrp);
                uint32_t pu = (uint32_t)pgrp;
                if (copy_to_user_safe(argp, &pu, sizeof(pu)) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (req == TIOCSPGRP) {
                if (!argp) return ret_err(EFAULT);
                uint32_t p = 0;
                if (copy_from_user_raw(&p, argp, sizeof(p)) != 0) return ret_err(EFAULT);
                qemu_debug_printf("ioctl: TIOCSPGRP on fd=%d -> set pgrp=%u\n", fd, p);
                /* Try to set tty-specific foreground pgrp; fall back to global user_pgrp */
                if (devfs_tty_set_fg_pgrp(f, (int)p) != 0) {
                    if (p != 0) user_pgrp = (uint64_t)p;
                }
                return 0;
            }
            if (req == TCGETS) {
                if (!argp) return ret_err(EFAULT);
                struct termios_k tio;
                memset(&tio, 0, sizeof(tio));
                /* A very typical cooked tty: ICANON|ECHO|ISIG, ICRNL, OPOST */
                tio.c_iflag = 0x00000100u /* ICRNL */ | 0x00000010u /* IXON-ish placeholder */;
                tio.c_oflag = 0x00000001u /* OPOST */;
                tio.c_cflag = 0x000000B0u; /* 8N1-ish placeholder */
                tio.c_lflag = 0x00000002u /* ICANON */ | 0x00000008u /* ECHO */ | 0x00000001u /* ISIG */;
                tio.c_line = 0;
                /* VMIN/VTIME positions differ across ABIs; leave c_cc[] zeroed */
                tio.c_ispeed = 9600;
                tio.c_ospeed = 9600;
                /* IMPORTANT:
                   libc implementations don't all agree on sizeof(struct termios) (NCCS differs).
                   If userspace allocated a smaller object on stack and we blindly copy a bigger
                   struct, we'd overwrite the stack canary and trigger "*** stack smashing detected ***".
                   To be safe, copy only the fixed header part (flags) which is enough for isatty/setup. */
                size_t safe_sz = 32;
                if (safe_sz > sizeof(tio)) safe_sz = sizeof(tio);
                if (copy_to_user_safe(argp, &tio, safe_sz) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (req == TCSETS || req == TCSETSW || req == TCSETSF) {
                /* accept silently */
                return 0;
            }
                qemu_debug_printf("ioctl: unknown req=0x%llx on fd=%d\n", (unsigned long long)req, fd);
            return ret_err(EINVAL);
        }
        case SYS_write: {
            int fd = (int)a1;
            const void *bufp = (const void*)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            size_t copied = 0;
            void *tmp = copy_from_user_safe(bufp, cnt, 4096, &copied);
            if (!tmp) return ret_err(EFAULT);

            ssize_t wr = fs_write(f, tmp, copied, f->pos);
            if (wr > 0) f->pos += (size_t)wr;
            kfree(tmp);
            return (wr >= 0) ? (uint64_t)wr : ret_err(EINVAL);
        }
        case SYS_read: {
            int fd = (int)a1;
            void *bufp = (void*)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            size_t to_read = cnt < 4096 ? cnt : 4096;
            void *tmp = kmalloc(to_read);
            if (!tmp) return ret_err(ENOMEM);
            ssize_t rr = fs_read(f, tmp, to_read, f->pos);
            /* Debug: log stdin reads to detect immediate EOF causing shell to exit */
            if (fd == 0) {
                if (rr <= 0) {
                    qemu_debug_printf("USER READ stdin: rr=%lld\n", (long long)rr);
                } else {
                    size_t probe = rr < 64 ? (size_t)rr : 64;
                    char *dbg = (char*)kmalloc(probe + 1);
                    if (dbg) {
                        for (size_t i = 0; i < probe; i++) {
                            char c = ((char*)tmp)[i];
                            dbg[i] = (c >= 32 && c < 127) ? c : '.';
                        }
                        dbg[probe] = '\\0';
                        qemu_debug_printf("USER READ stdin: got %lld bytes: %s\n", (long long)rr, dbg);
                        kfree(dbg);
                    }
                }
            }
            if (rr > 0) {
                if ((uintptr_t)bufp + (size_t)rr <= (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    memcpy(bufp, tmp, (size_t)rr);
                    f->pos += (size_t)rr;
                    kfree(tmp);
                    return (uint64_t)rr;
                }
                kfree(tmp);
                return ret_err(EFAULT);
            }
            kfree(tmp);
            return (rr >= 0) ? (uint64_t)rr : ret_err(EINVAL);
        }
        case SYS_open: {
            const char *path_u = (const char*)(uintptr_t)a1;
            (void)a2;
            (void)a3;
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct fs_file *f = fs_open(path);
            if (!f) return ret_err(ENOENT);
            int fd = thread_fd_alloc(f);
            if (fd < 0) { fs_file_free(f); return ret_err(EBADF); }
            return (uint64_t)(unsigned)fd;
        }
        case SYS_openat: {
            /* openat(dirfd, pathname, flags, mode) */
            const char *path_u = (const char*)(uintptr_t)a2;
            (void)a1; (void)a3; (void)a4;
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct fs_file *f = fs_open(path);
            if (!f) return ret_err(ENOENT);
            int fd = thread_fd_alloc(f);
            if (fd < 0) { fs_file_free(f); return ret_err(EBADF); }
            return (uint64_t)(unsigned)fd;
        }
        case SYS_close: {
            int fd = (int)a1;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            int r = thread_fd_close(fd);
            return (r == 0) ? 0ULL : ret_err(EBADF);
        }
        case SYS_stat:
        case SYS_lstat: {
            const char *path_u = (const char*)(uintptr_t)a1;
            void *st_u = (void*)(uintptr_t)a2;
            if (!path_u || !st_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)st_u + sizeof(struct stat) > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct stat st;
            if (vfs_stat(path, &st) != 0) return ret_err(ENOENT);
            if (copy_to_user_safe(st_u, &st, sizeof(st)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_fstat: {
            int fd = (int)a1;
            void *st_u = (void*)(uintptr_t)a2;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!st_u) return ret_err(EFAULT);
            if ((uintptr_t)st_u + sizeof(struct stat) > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            struct stat st;
            if (vfs_fstat(f, &st) != 0) return ret_err(EINVAL);
            if (copy_to_user_safe(st_u, &st, sizeof(st)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_newfstatat: {
            /* newfstatat(dirfd, pathname, statbuf, flags) */
            const char *path_u = (const char*)(uintptr_t)a2;
            void *st_u = (void*)(uintptr_t)a3;
            (void)a1; (void)a4;
            if (!path_u || !st_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)st_u + sizeof(struct stat) > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct stat st;
            if (vfs_stat(path, &st) != 0) return ret_err(ENOENT);
            if (copy_to_user_safe(st_u, &st, sizeof(st)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_lseek: {
            int fd = (int)a1;
            int64_t off = (int64_t)a2;
            int whence = (int)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            off_t newpos = 0;
            if (whence == 0) newpos = (off_t)off;
            else if (whence == 1) newpos = (off_t)((int64_t)f->pos + off);
            else if (whence == 2) newpos = (off_t)((int64_t)f->size + off);
            else return ret_err(EINVAL);
            if (newpos < 0) return ret_err(EINVAL);
            f->pos = newpos;
            return (uint64_t)(uint64_t)f->pos;
        }
        case SYS_getdents64: {
            int fd = (int)a1;
            void *dirp_u = (void*)(uintptr_t)a2;
            size_t count = (size_t)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!dirp_u) return ret_err(EFAULT);
            if (count < 32) return ret_err(EINVAL);
            if ((uintptr_t)dirp_u + count > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (f->type != FS_TYPE_DIR) return ret_err(EINVAL);

            uint8_t kbuf[1024];
            ssize_t rr = fs_readdir_next(f, kbuf, sizeof(kbuf));
            if (rr <= 0) return 0;

            size_t in_off = 0;
            size_t out_off = 0;
            while (in_off + 8 <= (size_t)rr) {
                struct ext2_dir_entry *de = (struct ext2_dir_entry*)(kbuf + in_off);
                if (de->rec_len < 8) break;
                if (in_off + de->rec_len > (size_t)rr) break;
                if (de->name_len > de->rec_len - 8) break;

                const char *nm = (const char*)(kbuf + in_off + 8);
                size_t nlen = (size_t)de->name_len;

                /* linux_dirent64 header (19 bytes) + name + NUL, aligned to 8 */
                size_t reclen = 19 + nlen + 1;
                reclen = (reclen + 7) & ~7u;
                if (out_off + reclen > count) break;

                uint8_t *out = (uint8_t*)dirp_u + out_off;
                *(uint64_t*)(out + 0) = (uint64_t)de->inode;
                *(int64_t*)(out + 8) = (int64_t)f->pos; /* best-effort */
                *(uint16_t*)(out + 16) = (uint16_t)reclen;
                out[18] = (uint8_t)de->file_type;
                memcpy(out + 19, nm, nlen);
                out[19 + nlen] = '\0';
                for (size_t z = 19 + nlen + 1; z < reclen; z++) out[z] = 0;

                out_off += reclen;
                in_off += de->rec_len;
            }
            return (uint64_t)out_off;
        }
        case SYS_arch_prctl: {
            /* Linux x86_64 arch_prctl */
            const uint64_t code = a1;
            const uint64_t addr = a2;
            enum { ARCH_SET_GS = 0x1001, ARCH_SET_FS = 0x1002, ARCH_GET_FS = 0x1003, ARCH_GET_GS = 0x1004 };
            if (code == ARCH_SET_FS) {
                if (addr >= (uint64_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                /* Fix for early "stack smashing detected" in glibc:
                   If userspace executed stack-protected frames BEFORE TLS (FS base) was set,
                   then changing FS base later makes the epilogue compare against a different
                   guard at fs:0x28 -> abort().
                   Keep the guard stable by copying old fs:0x28 into new TLS fs:0x28. */
                uint64_t old_fs = msr_read_u64(MSR_FS_BASE);
                uint64_t old_guard = 0;
                if (old_fs + 0x30 < (uint64_t)MMIO_IDENTITY_LIMIT) {
                    old_guard = *(volatile uint64_t*)(uintptr_t)(old_fs + 0x28);
                } else if (0x30 < (uint64_t)MMIO_IDENTITY_LIMIT) {
                    /* common boot case: old_fs==0 */
                    old_guard = *(volatile uint64_t*)(uintptr_t)0x28;
                }

                cur->user_fs_base = addr;
                msr_write_u64(MSR_FS_BASE, addr);

                if (addr + 0x30 < (uint64_t)MMIO_IDENTITY_LIMIT) {
                    *(volatile uint64_t*)(uintptr_t)(addr + 0x28) = old_guard;
                }
                return 0;
            } else if (code == ARCH_GET_FS) {
                if (addr >= (uint64_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                *(uint64_t*)(uintptr_t)addr = cur->user_fs_base;
                return 0;
            } else if (code == ARCH_SET_GS || code == ARCH_GET_GS) {
                return ret_err(ENOSYS);
            }
            return ret_err(EINVAL);
        }
        case SYS_brk: {
            /* Simple brk: bump within a safe range in identity-mapped low memory. */
            uintptr_t req = (uintptr_t)a1;
            if (user_brk_base == 0) {
                /* initialize lazy: place brk after 8MiB by default */
                user_brk_base = 8u * 1024u * 1024u;
                user_brk_cur = user_brk_base;
            }
            if (req == 0) return (uint64_t)user_brk_cur;
            req = align_up_u(req, 16);
            /* Don't allow brk to collide with reserved TLS/stack area. */
            uintptr_t top_limit = (uintptr_t)USER_TLS_BASE; /* reserve [USER_TLS_BASE .. USER_STACK_TOP) */
            if (req < user_brk_base || req >= top_limit) return (uint64_t)user_brk_cur;
            /* mark and zero new range */
            if (req > user_brk_cur) {
                if (mark_user_identity_range_2m_sys((uint64_t)user_brk_cur, (uint64_t)req) != 0) return ret_err(EFAULT);
                memset((void*)user_brk_cur, 0, req - user_brk_cur);
            }
            user_brk_cur = req;
            return (uint64_t)user_brk_cur;
        }
        case SYS_mmap: {
            /* mmap(addr,len,prot,flags,fd,off) - only anonymous/private supported */
            (void)a1; /* addr hint ignored */
            size_t len = (size_t)a2;
            int prot = (int)a3;
            int flags = (int)a4;
            (void)prot;
            (void)a5; (void)a6;
            if (len == 0) return ret_err(EINVAL);
            len = (size_t)align_up_u((uintptr_t)len, 4096);
            enum { MAP_FIXED = 0x10, MAP_ANONYMOUS = 0x20, MAP_PRIVATE = 0x02 };
            if (flags & MAP_FIXED) return ret_err(EINVAL);
            if (!(flags & MAP_ANONYMOUS) || !(flags & MAP_PRIVATE)) return ret_err(ENOSYS);
            if (user_mmap_next == 0) user_mmap_next = 32u * 1024u * 1024u; /* 32MiB */
            uintptr_t addr = align_up_u(user_mmap_next, 4096);
            uintptr_t top_limit = (uintptr_t)USER_TLS_BASE;
            if (addr + len >= top_limit) return ret_err(ENOMEM);
            if (mark_user_identity_range_2m_sys((uint64_t)addr, (uint64_t)(addr + len)) != 0) return ret_err(EFAULT);
            memset((void*)addr, 0, len);
            user_mmap_next = addr + len;
            return (uint64_t)addr;
        }
        case SYS_munmap:
            return 0;
        case SYS_mprotect:
            return 0;
        case SYS_exit: {
            (void)a1;
            kprintf("sys_exit: pid=%llu called exit(code=%llu)\n",
                    (unsigned long long)(cur->tid ? cur->tid : 1),
                    (unsigned long long)a1);
            thread_stop((int)cur->tid);
            syscall_exit_to_shell_flag = 1;
            return 0;
        }
        case SYS_exit_group: {
            (void)a1;
            kprintf("sys_exit_group: pid=%llu called exit_group(code=%llu)\n",
                    (unsigned long long)(cur->tid ? cur->tid : 1),
                    (unsigned long long)a1);
            thread_stop((int)cur->tid);
            syscall_exit_to_shell_flag = 1;
            return 0;
        }
        default:
            /* Log unknown syscall with full args for easier diagnosis */
            qemu_debug_printf("UNKNOWN SYSCALL: %u num=%u args=%u,%u,%u,%u,%u,%u\n",
                    (unsigned long long)(cur->tid ? cur->tid : 1),
                    (unsigned long long)num,
                    (unsigned long long)a1, (unsigned long long)a2, (unsigned long long)a3,
                    (unsigned long long)a4, (unsigned long long)a5, (unsigned long long)a6);
            (void)a4; (void)a5; (void)a6;
            return ret_err(ENOSYS);
    }
}

void isr_syscall(cpu_registers_t* regs) {
    if (!regs) return;
    regs->rax = syscall_do(regs->rax, regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r9, regs->r8);
    /* If userspace called exit/exit_group via int0x80 path, do not iret back to ring3. */
    if (syscall_exit_to_shell_flag) {
        syscall_return_to_shell();
    }
}

void syscall_init(void) {
    /* register handler on vector 0x80 */
    idt_set_handler(0x80, isr_syscall);

    /* Enable x86_64 SYSCALL instruction for userland. */
    uint64_t efer = msr_read_u64(MSR_EFER);
    efer |= 1ULL; /* EFER.SCE */
    msr_write_u64(MSR_EFER, efer);
    /* STAR: kernel CS selector in bits 47:32, SS = CS+8 */
    uint64_t star = ((uint64_t)(KERNEL_CS & 0xFFFFu)) << 32;
    msr_write_u64(MSR_STAR, star);
    msr_write_u64(MSR_LSTAR, (uint64_t)(uintptr_t)syscall_entry64);
    /* On SYSCALL entry, clear IF and DF to avoid reentrancy and broken string ops.
       IF bit = 9, DF bit = 10 in RFLAGS. */
    msr_write_u64(MSR_FMASK, (1ULL << 9) | (1ULL << 10));

    kprintf("syscall: int0x80 handler registered; SYSCALL enabled\n");
}


