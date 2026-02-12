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
#include <procfs.h>
#include <sysfs.h>
#include <rtc.h>
#include <spinlock.h>

/* Linux x86_64 struct stat size; ensures st_mode at correct offset for S_ISREG etc. */
#define STAT_COPY_SIZE 144

extern void kprintf(const char *fmt, ...);

/* Helper exported from core/elf.c */
extern uint64_t virt_to_phys(uint64_t va);

/* Saved user RSP for syscall_entry64 (single-core, single-syscall-in-flight). */
uint64_t syscall_user_rsp_saved = 0;
/* Kernel syscall stack top (RSP0) installed by tss_set_rsp0(). Used by syscall_entry64. */
uint64_t syscall_kernel_rsp0 = 0;
/* Saved user RIP for SYSCALL path (RCX at syscall entry). Used by fork/vfork helpers. */
uint64_t syscall_user_return_rip = 0;
/* Saved callee-saved user registers captured by syscall_entry64.
   vfork needs these to resume the parent code path correctly in the child. */
uint64_t syscall_user_saved_rbx = 0;
uint64_t syscall_user_saved_rbp = 0;
uint64_t syscall_user_saved_r12 = 0;
uint64_t syscall_user_saved_r13 = 0;
uint64_t syscall_user_saved_r14 = 0;
uint64_t syscall_user_saved_r15 = 0;
/* Caller-saved regs snapshot (some libc/syscall stubs may rely on these immediately after SYSCALL). */
uint64_t syscall_user_saved_rdi = 0;
uint64_t syscall_user_saved_rsi = 0;
uint64_t syscall_user_saved_rdx = 0;
uint64_t syscall_user_saved_r8  = 0;
uint64_t syscall_user_saved_r9  = 0;
uint64_t syscall_user_saved_r10 = 0;
uint64_t syscall_user_saved_rcx = 0;
uint64_t syscall_user_saved_r11 = 0;
/* Set to non-zero when user called exit/exit_group; handled in syscall_entry64. */
uint64_t syscall_exit_to_shell_flag = 0;
/* When non-zero, assembly entry will skip overwriting saved rax slot so trampoline-patched
   values remain in the syscall stack. apply_exec_trampoline sets this before returning. */
uint64_t syscall_exec_trampoline_active = 0;
/* per-thread saved values copied from syscall_entry64 globals at syscall start */

__attribute__((noreturn)) void syscall_return_to_shell(void) {
    syscall_exit_to_shell_flag = 0;
    thread_set_current_user(NULL);
    for (;;) { asm volatile("sti; hlt" ::: "memory"); }
}

extern void syscall_entry64(void);
/* helper entry for kernel-created user threads (defined in cpu/thread.c) */
extern void user_thread_entry(void);

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

/* Debug helper: dump kernel syscall stack region around syscall_kernel_rsp0 */
static void debug_dump_kernel_syscall_stack(void) {
    extern uint64_t syscall_kernel_rsp0;
    uint64_t base = (uint64_t)syscall_kernel_rsp0;
    if (base == 0) return;
    if (base >= (uint64_t)MMIO_IDENTITY_LIMIT) return;
}

/* Apply per-thread exec trampoline by patching kernel syscall stack saved return RIP
   and adjusting saved user RSP. Returns 0 on success, -1 on failure. */
static int apply_exec_trampoline(thread_t *t) {
    if (!t || !t->exec_trampoline_flag) return -1;
    extern uint64_t syscall_kernel_rsp0;
    if ((uintptr_t)syscall_kernel_rsp0 == 0) return -1;
    
    uintptr_t base = (uintptr_t)syscall_kernel_rsp0;
    uintptr_t rcx_slot = base + 104; /* saved rcx (user RIP) */
    uintptr_t rax_slot = base + 112; /* saved rax slot */

    /* safety: ensure writing within identity map */
    if (rcx_slot + 8 > (uintptr_t)MMIO_IDENTITY_LIMIT) return -1;
    if (rax_slot + 8 > (uintptr_t)MMIO_IDENTITY_LIMIT) return -1;

    /* Write the desired return RIP into saved rcx slot so iret will use it */
    *(uint64_t*)(uintptr_t)rcx_slot = (uint64_t)t->exec_trampoline_rip;

    /* Set global saved user rsp so assembly builds IRET frame with this RSP */
    syscall_user_rsp_saved = t->exec_trampoline_rsp;

    /* Also set saved rax so final popped rax becomes our chosen value */
    *(uint64_t*)(uintptr_t)rax_slot = (uint64_t)t->exec_trampoline_rax;

    /* memory barrier */
    asm volatile("mfence" ::: "memory");

    /* clear flag (we consumed it) */
    t->exec_trampoline_flag = 0;

    /* notify assembly entry to preserve patched slots */
    syscall_exec_trampoline_active = 1;

    return 0;
}

/* Snapshot user registers from syscall entry stack frame into current thread.
   Frame layout matches syscall_entry64 push order (rsp points to saved r15). */
void syscall_snapshot_user_regs(uint64_t *frame) {
    if (!frame) return;
    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3) {
        cur = thread_get_current_user();
        if (!cur) return;
    }
    cur->saved_syscall_frame = frame;
    /* Indexes into frame */
    cur->saved_user_r15 = frame[0];
    cur->saved_user_r14 = frame[1];
    cur->saved_user_r13 = frame[2];
    cur->saved_user_r12 = frame[3];
    cur->saved_user_r11 = frame[4];
    cur->saved_user_r10 = frame[5];
    cur->saved_user_r9  = frame[6];
    cur->saved_user_r8  = frame[7];
    cur->saved_user_rdi = frame[8];
    cur->saved_user_rsi = frame[9];
    cur->saved_user_rbp = frame[10];
    cur->saved_user_rbx = frame[11];
    cur->saved_user_rdx = frame[12];
    cur->saved_user_rcx = frame[13];
    cur->saved_user_rip = frame[13];
    /* saved rax is frame[14] */
    cur->saved_user_rsp = frame[15]; /* pushed before regs */
}

static void rebuild_syscall_frame(thread_t *t) {
    if (!t || !t->saved_syscall_frame) return;
    uintptr_t base = (uintptr_t)t->saved_syscall_frame;
    if (base + (16u * 8u) > (uintptr_t)MMIO_IDENTITY_LIMIT) return;
    uint64_t *frame = t->saved_syscall_frame;
    frame[0]  = t->saved_user_r15;
    frame[1]  = t->saved_user_r14;
    frame[2]  = t->saved_user_r13;
    frame[3]  = t->saved_user_r12;
    frame[4]  = t->saved_user_r11;
    frame[5]  = t->saved_user_r10;
    frame[6]  = t->saved_user_r9;
    frame[7]  = t->saved_user_r8;
    frame[8]  = t->saved_user_rdi;
    frame[9]  = t->saved_user_rsi;
    frame[10] = t->saved_user_rbp;
    frame[11] = t->saved_user_rbx;
    frame[12] = t->saved_user_rdx;
    frame[13] = t->saved_user_rcx;
    /* leave frame[14] (saved rax) to be overwritten by syscall_entry64 */
    frame[15] = t->saved_user_rsp;
}

/* Keep stack layout consistent with core/elf.c user_stack_top_for_tid().
   Duplicated here because elf.c helper is static. */
static uintptr_t user_stack_top_for_tid_like_exec(uint64_t tid) {
    const uintptr_t top = (uintptr_t)USER_STACK_TOP;
    const uintptr_t stride = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + (uintptr_t)(64 * 1024);
    const uint64_t slot = tid + 1ULL;
    if (stride == 0) return top;
    if (slot > (uint64_t)((uintptr_t)-1) / (uint64_t)stride) return top;
    const uintptr_t off = (uintptr_t)(slot * (uint64_t)stride);
    const uintptr_t min_room = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + 0x10000u;
    if (top <= min_room) return top;
    if (off >= (top - min_room)) return top;
    return top - off;
}

/* Restore parent's userspace stack snapshot for a vfork child.
   In AxonOS we block the parent until the child exits; however the child still
   runs in the same address space and may temporarily modify the parent's stack
   frames above the saved RSP. To avoid post-vfork corruption (seen as #GP with
   non-canonical RBP in busybox sh), we snapshot that region in SYS_vfork and
   restore it right before waking the parent on SYS_exit/SYS_exit_group. */
static void vfork_restore_parent_stack(thread_t *child) {
    if (!child) return;
    if (!child->vfork_parent_stack_backup) return;
    uintptr_t dst = (uintptr_t)child->vfork_parent_saved_rsp;
    uint64_t len64 = child->vfork_parent_stack_backup_len;
    if (dst != 0 && len64 != 0) {
        uintptr_t end = dst + (uintptr_t)len64;
        if (end > dst && end <= (uintptr_t)MMIO_IDENTITY_LIMIT) {
            memcpy((void*)dst, child->vfork_parent_stack_backup, (size_t)len64);
        } else {
            /* bad dst/len */
        }
    }
    /* TEMPORARY DIAGNOSTIC:
       Do NOT free the backup buffer yet.
       We observed post-vfork #GP with corrupted user registers (RBP/RDI), which strongly
       suggests the *kernel syscall frame* on the parent's kernel stack got overwritten.
       Since kernel stacks and this backup are both heap allocations, a buggy kfree/merge
       path can corrupt adjacent allocations and smash the parent's kernel stack.
       Leaking this buffer avoids exercising that path and helps confirm allocator corruption. */
    //kfree(child->vfork_parent_stack_backup);
    child->vfork_parent_stack_backup = NULL;
    child->vfork_parent_saved_rsp = 0;
    child->vfork_parent_stack_backup_len = 0;
}

/* forward for user brk state used in vfork restore */
static uintptr_t user_brk_cur;

static void vfork_restore_parent_memory(thread_t *child) {
    if (!child) return;
    if (!child->vfork_parent_mem_backup) return;
    uintptr_t base = (uintptr_t)child->vfork_parent_mem_backup_base;
    uint64_t len64 = child->vfork_parent_mem_backup_len;
    if (base != 0 && len64 != 0) {
        uintptr_t end = base + (uintptr_t)len64;
        if (end > base && end <= (uintptr_t)MMIO_IDENTITY_LIMIT) {
            memcpy((void*)base, child->vfork_parent_mem_backup, (size_t)len64);
            thread_t *pt = NULL;
            if (child->vfork_parent_tid >= 0) pt = thread_get(child->vfork_parent_tid);
            if (pt) {
                pt->user_brk_cur = (uintptr_t)child->vfork_parent_brk_saved;
            } else {
                user_brk_cur = (uintptr_t)child->vfork_parent_brk_saved;
            }
        } else {
            /* bad base/len */
        }
    }
    kfree(child->vfork_parent_mem_backup);
    child->vfork_parent_mem_backup = NULL;
    child->vfork_parent_mem_backup_len = 0;
    child->vfork_parent_mem_backup_base = 0;
    child->vfork_parent_brk_saved = 0;
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
    /* Basic bounds check: ensure entirely within identity mapped user region. */
    if ((uintptr_t)uptr + to_copy > (uintptr_t)MMIO_IDENTITY_LIMIT) {
        if (out_copied) *out_copied = 0;
        return NULL;
    }
    void *buf = kmalloc(to_copy);
    if (!buf) { if (out_copied) *out_copied = 0; return NULL; }
    /* Simple memcpy: assume identity-mapped user memory is accessible from kernel.
       This mirrors previous behavior; more advanced checks caused double-faults. */
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
#define ENOEXEC 8
/* no child processes */
#define ECHILD  10
/* filename too long */
#define ENAMETOOLONG 36
#define EAGAIN  11
#define EINTR   4
#define EPIPE   32
#define EIO     5
#define EEXIST  17
#define ENOTDIR 20

/* Pipe: kernel buffer + two fd ends. driver_private = pipe_t*, fs_private = 0 read / 1 write */
#define PIPE_BUF_SIZE 4096
typedef struct pipe {
    uint8_t *buf;
    size_t size;
    size_t head;   /* write position */
    size_t tail;   /* read position */
    int refcount;  /* 2 when both ends open */
    int reader_waiter_tid;
    int writer_waiter_tid;
    spinlock_t lock;
} pipe_t;

static ssize_t pipe_read_bytes(pipe_t *p, void *buf, size_t cnt, thread_t *cur);
static ssize_t pipe_write_bytes(pipe_t *p, const void *buf, size_t cnt, thread_t *cur);

void pipe_release_end(struct fs_file *f) {
    if (!f || f->type != FS_TYPE_PIPE || !f->driver_private) return;
    pipe_t *p = (pipe_t *)f->driver_private;
    unsigned long fl = 0;
    acquire_irqsave(&p->lock, &fl);
    p->refcount--;
    int ref = p->refcount;
    /* Wake waiter on the other end so they see EOF or EPIPE */
    if (p->reader_waiter_tid >= 0) { thread_unblock(p->reader_waiter_tid); p->reader_waiter_tid = -1; }
    if (p->writer_waiter_tid >= 0) { thread_unblock(p->writer_waiter_tid); p->writer_waiter_tid = -1; }
    release_irqrestore(&p->lock, fl);
    if (ref == 0) {
        kfree(p->buf);
        kfree(p);
    }
}

static ssize_t pipe_read_bytes(pipe_t *p, void *buf, size_t cnt, thread_t *cur) {
    if (!p || !buf || cnt == 0) return -EINVAL;
    unsigned long fl = 0;
    for (;;) {
        acquire_irqsave(&p->lock, &fl);
        size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
        if (used > 0) {
            size_t n = used < cnt ? used : cnt;
            size_t tail = p->tail;
            release_irqrestore(&p->lock, fl);
            size_t first = (tail + n <= p->size) ? n : (p->size - tail);
            memcpy(buf, p->buf + tail, first);
            if (first < n) memcpy((char*)buf + first, p->buf, n - first);
            acquire_irqsave(&p->lock, &fl);
            p->tail = (tail + n) % p->size;
            if (p->writer_waiter_tid >= 0) { thread_unblock(p->writer_waiter_tid); p->writer_waiter_tid = -1; }
            release_irqrestore(&p->lock, fl);
            return (ssize_t)n;
        }
        if (p->refcount < 2) { release_irqrestore(&p->lock, fl); return 0; } /* EOF */
        p->reader_waiter_tid = (int)(cur && cur->tid ? cur->tid : 0);
        release_irqrestore(&p->lock, fl);
        if (p->reader_waiter_tid >= 0) {
            thread_block(p->reader_waiter_tid);
            thread_yield();
        }
    }
}

static ssize_t pipe_write_bytes(pipe_t *p, const void *buf, size_t cnt, thread_t *cur) {
    if (!p || !buf || cnt == 0) return -EINVAL;
    unsigned long fl = 0;
    size_t written = 0;
    const char *src = (const char *)buf;
    while (written < cnt) {
        acquire_irqsave(&p->lock, &fl);
        size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
        size_t free = (p->size - 1) > used ? (p->size - 1 - used) : 0;
        if (free > 0) {
            size_t n = (cnt - written) < free ? (cnt - written) : free;
            size_t head = p->head;
            release_irqrestore(&p->lock, fl);
            for (size_t i = 0; i < n; i++) {
                p->buf[(head + i) % p->size] = src[written + i];
            }
            acquire_irqsave(&p->lock, &fl);
            p->head = (head + n) % p->size;
            written += n;
            if (p->reader_waiter_tid >= 0) { thread_unblock(p->reader_waiter_tid); p->reader_waiter_tid = -1; }
            release_irqrestore(&p->lock, fl);
            continue;
        }
        if (p->refcount < 2) { release_irqrestore(&p->lock, fl); return written > 0 ? (ssize_t)written : -EPIPE; }
        p->writer_waiter_tid = (int)(cur && cur->tid ? cur->tid : 0);
        release_irqrestore(&p->lock, fl);
        if (p->writer_waiter_tid >= 0) {
            thread_block(p->writer_waiter_tid);
            thread_yield();
        }
    }
    return (ssize_t)written;
}

static uint64_t last_syscall_debug = 0;
static inline uint64_t ret_err(int e) {
    /* Log ENOSYS occurrences for the user shell (tid==3) to help musl compatibility debugging. */
    thread_t *t = thread_get_current_user();
    if (!t) t = thread_current();
    return (uint64_t)(-(int64_t)e);
}

/* minimal signal numbers used */
#ifndef SIGCHLD
#define SIGCHLD 17
#endif

static void thread_set_pending_signal(thread_t *t, int signum) {
    if (!t || signum <= 0 || signum > 63) return;
    t->pending_signals |= (1ULL << (signum - 1));
    /* Wake any thread blocked in sigtimedwait so it can observe the signal. */
    if (t->state == THREAD_BLOCKED) {
        thread_unblock((int)(t->tid ? t->tid : 1));
    }
}

static int thread_fetch_pending_signal(thread_t *t, uint64_t mask) {
    if (!t) return 0;
    if (mask == 0) mask = ~0ULL;
    /* Always allow SIGCHLD to wake waits to avoid init deadlocks. */
    mask |= (1ULL << (SIGCHLD - 1));
    for (int sig = 1; sig <= 63; sig++) {
        uint64_t bit = 1ULL << (sig - 1);
        if ((mask & bit) && (t->pending_signals & bit)) {
            t->pending_signals &= ~bit;
            return sig;
        }
    }
    return 0;
}

static int is_init_user(thread_t *t) {
    int init_tid = thread_get_init_user_tid();
    return t && init_tid >= 0 && (int)t->tid == init_tid;
}

static int has_terminated_child(thread_t *t) {
    if (!t) return 0;
    for (int i = 0; i < thread_get_count(); i++) {
        thread_t *c = thread_get_by_index(i);
        if (!c) continue;
        if (c->parent_tid != (int)t->tid) continue;
        if (c->state == THREAD_TERMINATED && c->exit_status != 0x80000000) {
            return 1;
        }
    }
    return 0;
}

static thread_t *find_terminated_child(thread_t *t) {
    if (!t) return NULL;
    for (int i = 0; i < thread_get_count(); i++) {
        thread_t *c = thread_get_by_index(i);
        if (!c) continue;
        if (c->parent_tid != (int)t->tid) continue;
        if (c->state == THREAD_TERMINATED && c->exit_status != 0x80000000) {
            return c;
        }
    }
    return NULL;
}

/* Returns 1 if path contains . or .. components that need normalization. */
static int path_needs_normalize(const char *p) {
    if (!p) return 0;
    if (p[0] == '.' && (p[1] == '\0' || p[1] == '/')) return 1;
    if (p[0] == '.' && p[1] == '.' && (p[2] == '\0' || p[2] == '/')) return 1;
    for (; *p; p++) {
        if (*p == '/' && p[1] == '.' && (p[2] == '\0' || p[2] == '/')) return 1;
        if (*p == '/' && p[1] == '.' && p[2] == '.' && (p[3] == '\0' || p[3] == '/')) return 1;
    }
    return 0;
}

/* Normalize path by resolving . and .. components. Modifies buf in place. */
static void normalize_path(char *buf, size_t cap) {
    if (!buf || cap == 0) return;
    char tmp[512];
    const char *comps[64];
    size_t comp_len[64];
    int n = 0;
    const char *p = buf;
    while (*p && n < (int)(sizeof(comps) / sizeof(comps[0]))) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - start);
        if (len == 0) continue;
        if (len == 1 && start[0] == '.') continue;  /* skip . */
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            if (n > 0) n--;  /* pop .. */
            continue;
        }
        comps[n] = start;
        comp_len[n] = len;
        n++;
    }
    size_t pos = 0;
    tmp[pos++] = '/';
    for (int i = 0; i < n && pos < sizeof(tmp) - 1; i++) {
        if (i > 0) tmp[pos++] = '/';
        for (size_t j = 0; j < comp_len[i] && pos < sizeof(tmp) - 1; j++)
            tmp[pos++] = comps[i][j];
    }
    tmp[pos] = '\0';
    strncpy(buf, tmp, cap - 1);
    buf[cap - 1] = '\0';
}

static void resolve_user_path(thread_t *cur, const char *path_u, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    out[0] = '\0';
    if (!path_u || !path_u[0]) {
        strncpy(out, "/", out_cap);
        out[out_cap - 1] = '\0';
        return;
    }
    const char *cwd = (cur && cur->cwd[0]) ? cur->cwd : "/";
    if (path_u[0] == '/') {
        strncpy(out, path_u, out_cap);
        out[out_cap - 1] = '\0';
        if (path_needs_normalize(out)) normalize_path(out, out_cap);
        return;
    }
    /* "." means current directory. */
    if (strcmp(path_u, ".") == 0) {
        strncpy(out, cwd, out_cap);
        out[out_cap - 1] = '\0';
        return;
    }
    /* ".." means parent directory. */
    if (strcmp(path_u, "..") == 0) {
        if (strcmp(cwd, "/") == 0) {
            strncpy(out, "/", out_cap);
            out[out_cap - 1] = '\0';
        } else {
            const char *slash = strrchr(cwd, '/');
            if (slash && slash > cwd) {
                size_t len = (size_t)(slash - cwd);
                if (len >= out_cap) len = out_cap - 1;
                memcpy(out, cwd, len);
                out[len] = '\0';
            } else {
                strncpy(out, "/", out_cap);
                out[out_cap - 1] = '\0';
            }
        }
        return;
    }
    /* Build full path and normalize (handles ./run, a/./b, a/../b, etc.) */
    if (strcmp(cwd, "/") == 0) {
        snprintf(out, out_cap, "/%s", path_u);
    } else {
        snprintf(out, out_cap, "%s/%s", cwd, path_u);
    }
    if (path_needs_normalize(out)) normalize_path(out, out_cap);
}

/* Resolve path for openat: dirfd base or cwd. Returns 0 on success, negative errno on error. */
static int resolve_user_path_at(thread_t *cur, int dirfd, const char *path_u, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return -EFAULT;
    out[0] = '\0';
    if (!path_u || !path_u[0]) return -ENOENT;
    /* Absolute path: dirfd ignored, use standard resolve */
    if (path_u[0] == '/') {
        resolve_user_path(cur, path_u, out, out_cap);
        return 0;
    }
    /* AT_FDCWD = -100: use current working directory */
    enum { AT_FDCWD = -100 };
    if (dirfd == AT_FDCWD) {
        resolve_user_path(cur, path_u, out, out_cap);
        return 0;
    }
    /* dirfd: resolve relative to that directory */
    if (dirfd < 0 || dirfd >= THREAD_MAX_FD) return -EBADF;
    struct fs_file *f = cur->fds[dirfd];
    if (!f) return -EBADF;
    if (f->type != FS_TYPE_DIR) return -ENOTDIR;
    const char *base = f->path ? f->path : "/";
    size_t bl = strlen(base);
    int has_trailing = (bl > 1 && base[bl - 1] == '/');
    size_t pl = strlen(path_u);
    if (has_trailing) {
        snprintf(out, out_cap, "%s%s", base, path_u);
    } else {
        snprintf(out, out_cap, "%s/%s", base, path_u);
    }
    out[out_cap - 1] = '\0';
    if (path_needs_normalize(out)) normalize_path(out, out_cap);
    return 0;
}

static inline int user_range_ok(const void *uaddr, size_t nbytes);

static int copy_to_user_safe(void *uptr, const void *kptr, size_t n) {
    if (!uptr || !kptr || n == 0) return -1;
    if (!user_range_ok(uptr, n)) return -1;
    memcpy(uptr, kptr, n);
    return 0;
}

static int copy_from_user_raw(void *kdst, const void *usrc, size_t n) {
    if (!kdst || !usrc || n == 0) return -1;
    if (!user_range_ok(usrc, n)) return -1;
    memcpy(kdst, usrc, n);
    return 0;
}

/* Conservative user pointer bounds check for our identity-mapped userspace model.
   NOTE: We intentionally do NOT walk page tables here because virt_to_phys() is not
   reliable with the current paging setup (it often returns 0 for valid addresses).
   This means invalid/unmapped user pointers may still #PF; fixing that properly
   requires a real copy_from_user with fault handling. */
static inline int user_range_ok(const void *uaddr, size_t nbytes) {
    if (!uaddr) return 0;
    if (nbytes == 0) return 1;
    uintptr_t start = (uintptr_t)uaddr;
    uintptr_t end = start + nbytes;
    if (end < start) return 0;
    /* Restrict to user-mapped identity range only.
       This prevents user pointers from targeting kernel heap/stack, which can
       corrupt saved syscall frames and thread structs (seen as #GP after vfork). */
    const uintptr_t user_min = 0x00200000u; /* 2MiB */
    if (start < user_min) return 0;
    if (end > (uintptr_t)USER_STACK_TOP) return 0;
    return 1;
}

static int user_read_u64(const void *uaddr, uint64_t *out) {
    if (!out) return -1;
    if (!user_range_ok(uaddr, sizeof(uint64_t))) return -1;
    /* copy to avoid alignment surprises */
    if (copy_from_user_raw(out, uaddr, sizeof(uint64_t)) != 0) return -1;
    return 0;
}

static size_t user_strnlen_bounded(const char *s, size_t max) {
    if (!s) return 0;
    for (size_t i = 0; i < max; i++) {
        if (!user_range_ok(s + i, 1)) return max;
        if (s[i] == '\0') return i;
    }
    return max;
}

static char *copy_user_cstr(const char *u, size_t maxlen) {
    if (!u) return NULL;
    size_t L = user_strnlen_bounded(u, maxlen - 1);
    if (L >= maxlen) L = maxlen - 1;
    if (!user_range_ok(u, L + 1)) return NULL;
    char *k = (char*)kmalloc(L + 1);
    if (!k) return NULL;
    if (copy_from_user_raw(k, u, L + 1) != 0) { kfree(k); return NULL; }
    k[L] = '\0';
    return k;
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
static inline uintptr_t align_up_u(uintptr_t v, uintptr_t a);
static inline uintptr_t user_tls_base_for_tid_local(uint64_t tid) {
    uintptr_t stack_top = user_stack_top_for_tid_like_exec(tid);
    return (uintptr_t)stack_top - (uintptr_t)USER_STACK_SIZE - (uintptr_t)USER_TLS_SIZE;
}

void syscall_set_user_brk(uintptr_t base) {
    /* Establish initial program break after exec load. */
    if (base < (8u * 1024u * 1024u)) base = 8u * 1024u * 1024u;
    base = align_up_u(base, 4096);
    thread_t *tcur = thread_get_current_user();
    if (!tcur) tcur = thread_current();
    if (tcur) {
        tcur->user_brk_base = base;
        tcur->user_brk_cur = base;
        if (tcur->user_mmap_next && tcur->user_mmap_next < base) {
            tcur->user_mmap_next = align_up_u(base, 4096);
        }
    } else {
        user_brk_base = base;
        user_brk_cur = base;
    }
    if (user_mmap_next && user_mmap_next < base) {
        user_mmap_next = align_up_u(base, 4096);
    }
}

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
        l4[l4i] |= PG_US | PG_RW;
        l4[l4i] &= ~PG_NX;
        uint64_t *l3 = (uint64_t*)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) return -1;
        l3[l3i] |= PG_US | PG_RW;
        l3[l3i] &= ~PG_NX;
        uint64_t l3e = l3[l3i];
        if (l3e & PG_PS_2M) { invlpg((void*)(uintptr_t)va); continue; }
        uint64_t *l2 = (uint64_t*)(uintptr_t)(l3e & ~0xFFFULL);
        if (!(l2[l2i] & PG_PRESENT)) return -1;
        l2[l2i] |= PG_US | PG_RW;
        l2[l2i] &= ~PG_NX;
        uint64_t l2e = l2[l2i];
        if (l2e & PG_PS_2M) {
            invlpg((void*)(uintptr_t)va);
            continue;
        }
        uint64_t *l1 = (uint64_t*)(uintptr_t)(l2e & ~0xFFFULL);
        /* set US and clear NX on L1 entry covering this 4KiB range */
        l1[(va >> 12) & 0x1FF] |= PG_US | PG_RW;
        l1[(va >> 12) & 0x1FF] &= ~PG_NX;
        invlpg((void*)(uintptr_t)va);
    }
    return 0;
}

/* Attempt to find a valid user return RIP from the kernel syscall stack.
   Scans up to `max_qwords` qwords starting at kernel_rsp (virtual pointer)
   and returns first candidate `v` such that:
     - v is within plausible user range
     - virt_to_phys(v) != 0
     - mark_user_identity_range_2m_sys() succeeds for the 2MiB region covering v
   On success writes candidate into *out and returns 0. Otherwise returns -1.
*/
static int find_valid_saved_ret(uint64_t kernel_rsp, uint64_t *out, int max_qwords) {
    if (!out) return -1;
    if (kernel_rsp == 0) return -1;
    for (int i = 0; i < max_qwords; i++) {
        uintptr_t addr = (uintptr_t)(kernel_rsp + (i * 8));
        if (addr + 8 > (uintptr_t)MMIO_IDENTITY_LIMIT) break;
        uint64_t v = *(uint64_t*)(uintptr_t)addr;
        if (v < 0x100000 || v >= (uint64_t)MMIO_IDENTITY_LIMIT) continue;
        if (v == 0xdeadbeefcafebabeULL || v == 0xcafebabedeadbeefULL) continue;
        /* must be backed by a physical frame */
        if (virt_to_phys(v) == 0) continue;
        /* try to mark the containing 2MiB range user-accessible */
        uintptr_t begin = (uintptr_t)v & ~((uintptr_t)PAGE_SIZE_2M - 1);
        uintptr_t end = begin + (uintptr_t)PAGE_SIZE_2M;
        if (mark_user_identity_range_2m_sys((uint64_t)begin, (uint64_t)end) == 0) {
            *out = v;
            return 0;
        }
    }
    return -1;
}

static inline int is_leap_year(int y) {
    return (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
}

/* Convert rtc_datetime_t (year full e.g. 2025) to unix epoch seconds (UTC assumed). */
static uint64_t rtc_datetime_to_epoch(const rtc_datetime_t *dt) {
    if (!dt) return 0;
    int year = (int)dt->year;
    int month = (int)dt->month;
    int day = (int)dt->day;
    int hour = (int)dt->hour;
    int minute = (int)dt->minute;
    int second = (int)dt->second;
    /* Normalize month/year for algorithm: treat March as month 1 */
    if (month <= 2) {
        year -= 1;
        month += 12;
    }
    /* Days since epoch (1970-01-01) using proleptic Gregorian calendar */
    int64_t y = year;
    int64_t m = month;
    int64_t days = 365 * (y - 1970) + (y - 1969) / 4 - (y - 1901) / 100 + (y - 1601) / 400;
    /* month days cumulative for months starting at March=3 .. Feb=14 in this scheme */
    static const int mdays[] = {
        0,31,61,92,122,153,184,214,245,275,306,337, /* not used fully */
    };
    /* Simpler add days from months */
    static const int month_days_norm[] = { 0,31,28,31,30,31,30,31,31,30,31,30,31 };
    for (int mo = 1; mo < month; mo++) {
        days += month_days_norm[mo];
        if (mo == 2 && is_leap_year(year + (month <= 2 ? 1 : 0))) days += 1;
    }
    days += (day - 1);
    uint64_t secs = (uint64_t)days * 86400ULL + (uint64_t)hour * 3600ULL + (uint64_t)minute * 60ULL + (uint64_t)second;
    return secs;
}

/* Minimal signal numbers we use here */
#ifndef SIGHUP
#define SIGHUP 1
#endif
#ifndef SIGCONT
#define SIGCONT 18
#endif

/* Send simple signals to all threads in given pgrp.
   SIGHUP -> mark terminated (default action).
   SIGCONT -> move sleeping/blocked to ready.
*/
static void send_signal_to_pgrp(int pgrp, int signum) {
    int cnt = thread_get_count();
    for (int i = 0; i < cnt; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t) continue;
        if (t->pgid != pgrp) continue;
        if (signum == SIGHUP) {
            if (t->state != THREAD_TERMINATED) {
                t->exit_status = (0 & 0xFF) << 8;
                t->state = THREAD_TERMINATED;
                if (t->waiter_tid >= 0) thread_unblock(t->waiter_tid);
            }
        } else if (signum == SIGCONT) {
            if (t->state == THREAD_SLEEPING || t->state == THREAD_BLOCKED) {
                t->state = THREAD_READY;
            }
        }
    }
}

/* Send SIGHUP to all members of a session (except leader) */
static void send_hup_to_session(int sid) {
    int cnt = thread_get_count();
    for (int i = 0; i < cnt; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t) continue;
        if (t->sid != sid) continue;
        if ((int)t->tid == sid) continue; /* skip leader */
        if (t->state != THREAD_TERMINATED) {
            t->exit_status = (0 & 0xFF) << 8;
            t->state = THREAD_TERMINATED;
            if (t->waiter_tid >= 0) thread_unblock(t->waiter_tid);
        }
    }
    /* Also clear controlling_sid on dev ttys owned by this session */
    devfs_clear_controlling_by_sid(sid);
}


/* Common syscall dispatcher used by both int0x80 and SYSCALL.
   Calling convention follows Linux x86_64: num + up to 6 args. */  
uint64_t syscall_do(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    /* IMPORTANT:
       current_user can be stale if some subsystem (e.g. tty switching) overwrote it.
       Syscalls must be handled for the *currently running* thread. */
    thread_t *cur = thread_current();
    if (!cur || cur->ring != 3) {
        /* fallback */
        cur = thread_get_current_user();
        if (!cur) cur = thread_current();
    }
    if (!cur) return ret_err(EPERM);
    /* saved_user_* are normally captured in syscall_entry64 via syscall_snapshot_user_regs().
       If that path wasn't used (fallback/int0x80), fall back to globals once. */
    if (cur->saved_user_rip == 0) cur->saved_user_rip = syscall_user_return_rip;
    if (cur->saved_user_rsp == 0) cur->saved_user_rsp = syscall_user_rsp_saved;

    /* If return RIP wasn't recorded by entry path, dump kernel syscall stack for diagnosis */
    if (syscall_user_return_rip == 0) {
        debug_dump_kernel_syscall_stack();
    }

    /* record last syscall for debug logging of ENOSYS */
    last_syscall_debug = num;
    if (num != 1) qemu_debug_printf("SYSCALL: num=%u\n", num);

    switch (num) {
        case SYS_clone: {
            /* Minimal compatibility: treat clone() without complex flags as fork(). */
            return syscall_do(SYS_fork, 0, 0, 0, 0, 0, 0);
        }
        case SYS_clone3: {
            /* clone3(cl_args, size) - glibc pthreads passes user stack; must use it or advise_stack_range assert fails */
            const void *cl_args_u = (const void*)(uintptr_t)a1;
            size_t cl_size = (size_t)a2;
            if (!cl_args_u || cl_size < 64 || (uintptr_t)cl_args_u + 64 > (uintptr_t)MMIO_IDENTITY_LIMIT)
                return ret_err(EFAULT);
            uint64_t cl_buf[8];
            if (copy_from_user_raw(cl_buf, cl_args_u, 64) != 0) return ret_err(EFAULT);
            uint64_t flags = cl_buf[0];
            uint64_t child_tid_ptr = cl_buf[2];
            uint64_t parent_tid_ptr = cl_buf[3];
            uint64_t stack = cl_buf[5];
            uint64_t stack_size = cl_buf[6];
            uint64_t tls = cl_buf[7];
            uint64_t saved_rcx = cur->saved_user_rip;
            if (saved_rcx == 0) {
                extern uint64_t syscall_kernel_rsp0;
                if ((uintptr_t)syscall_kernel_rsp0 != 0) {
                    uint64_t candidate = 0;
                    if (find_valid_saved_ret(syscall_kernel_rsp0, &candidate, 64) == 0) saved_rcx = candidate;
                }
            }
            if (saved_rcx == 0) return ret_err(EINVAL);
            if (stack != 0 && stack_size != 0) {
                uintptr_t child_rsp = (uintptr_t)(stack + stack_size);
                child_rsp &= ~0xFULL;
                if (child_rsp < 0x1000 || child_rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EINVAL);
                if (mark_user_identity_range_2m_sys((uint64_t)(stack & ~((uintptr_t)PAGE_SIZE_2M - 1)),
                    (uint64_t)(child_rsp + 4096)) != 0) return ret_err(EFAULT);
                char child_name[32];
                snprintf(child_name, sizeof(child_name), "%s.child", cur->name);
                thread_t *child = thread_create_blocked(user_thread_entry, child_name);
                if (!child) return ret_err(ENOMEM);
                /* Use trampoline to restore parent's rdi,rsi,rdx,r8-r11,rbx,rbp,r12-r15 (glibc needs rdx=fn, r8=arg) */
                uintptr_t tramp = (uintptr_t)USER_VFORK_TRAMP;
                mark_user_identity_range_2m_sys((uint64_t)(tramp & ~((uintptr_t)(PAGE_SIZE_2M - 1))),
                    (uint64_t)((tramp & ~((uintptr_t)(PAGE_SIZE_2M - 1))) + PAGE_SIZE_2M));
                if ((uintptr_t)tramp + 128 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    unsigned char stub[160];
                    int off = 0;
                    stub[off++] = 0x48; stub[off++] = 0xBF; memcpy(&stub[off], &cur->saved_user_rdi, 8); off += 8;
                    stub[off++] = 0x48; stub[off++] = 0xBE; memcpy(&stub[off], &cur->saved_user_rsi, 8); off += 8;
                    stub[off++] = 0x48; stub[off++] = 0xBA; memcpy(&stub[off], &cur->saved_user_rdx, 8); off += 8;
                    stub[off++] = 0x49; stub[off++] = 0xB8; memcpy(&stub[off], &cur->saved_user_r8, 8); off += 8;
                    stub[off++] = 0x49; stub[off++] = 0xB9; memcpy(&stub[off], &cur->saved_user_r9, 8); off += 8;
                    stub[off++] = 0x49; stub[off++] = 0xBA; memcpy(&stub[off], &cur->saved_user_r10, 8); off += 8;
                    stub[off++] = 0x48; stub[off++] = 0xB9; { uint64_t rc = saved_rcx; memcpy(&stub[off], &rc, 8); off += 8; }
                    stub[off++] = 0x49; stub[off++] = 0xBB; memcpy(&stub[off], &cur->saved_user_r11, 8); off += 8;
                    stub[off++] = 0x48; stub[off++] = 0xBB; memcpy(&stub[off], &cur->saved_user_rbx, 8); off += 8;
                    stub[off++] = 0x48; stub[off++] = 0xBD; memcpy(&stub[off], &cur->saved_user_rbp, 8); off += 8;
                    stub[off++] = 0x49; stub[off++] = 0xBC; memcpy(&stub[off], &cur->saved_user_r12, 8); off += 8;
                    stub[off++] = 0x49; stub[off++] = 0xBD; memcpy(&stub[off], &cur->saved_user_r13, 8); off += 8;
                    stub[off++] = 0x49; stub[off++] = 0xBE; memcpy(&stub[off], &cur->saved_user_r14, 8); off += 8;
                    stub[off++] = 0x49; stub[off++] = 0xBF; memcpy(&stub[off], &cur->saved_user_r15, 8); off += 8;
                    stub[off++] = 0x48; stub[off++] = 0x31; stub[off++] = 0xC0; /* xor eax,eax - child returns 0 */
                    stub[off++] = 0x48; stub[off++] = 0xBC; { uint64_t rs = (uint64_t)child_rsp; memcpy(&stub[off], &rs, 8); off += 8; }
                    stub[off++] = 0xFF; stub[off++] = 0xE1; /* jmp rcx */
                    for (int z = off; z < (int)sizeof(stub); z++) stub[z] = 0x90;
                    memcpy((void*)tramp, stub, off);
                    child->user_rip = (uint64_t)tramp;
                } else {
                    child->user_rip = saved_rcx;
                }
                child->user_stack = (uint64_t)child_rsp;
                child->ring = 3;
                child->user_fs_base = (flags & 0x00080000u) ? tls : cur->user_fs_base;
                child->euid = cur->euid;
                child->egid = cur->egid;
                child->umask = cur->umask;
                child->attached_tty = cur->attached_tty;
                child->parent_tid = (int)(cur->tid ? cur->tid : 1);
                child->sid = cur->sid;
                child->pgid = cur->pgid;
                strncpy(child->cwd, cur->cwd, sizeof(child->cwd)-1);
                child->cwd[sizeof(child->cwd)-1] = '\0';
                for (int i = 0; i < THREAD_MAX_FD; i++) {
                    child->fds[i] = cur->fds[i];
                    if (child->fds[i]) {
                        if (child->fds[i]->refcount <= 0) child->fds[i]->refcount = 1;
                        else child->fds[i]->refcount++;
                    }
                }
                if (child_tid_ptr && child_tid_ptr < (uint64_t)MMIO_IDENTITY_LIMIT - 4)
                    copy_to_user_safe((void*)(uintptr_t)child_tid_ptr, &child->tid, 4);
                if (parent_tid_ptr && parent_tid_ptr < (uint64_t)MMIO_IDENTITY_LIMIT - 4)
                    copy_to_user_safe((void*)(uintptr_t)parent_tid_ptr, &child->tid, 4);
                thread_unblock((int)(child->tid ? child->tid : 1));
                return (uint64_t)(child->tid ? child->tid : 1);
            }
            return syscall_do(SYS_fork, 0, 0, 0, 0, 0, 0);
        }
        case SYS_set_tid_address: {
            /* set_tid_address(int *tidptr): used by glibc to set clear_child_tid. */
            uint64_t tidptr = a1;
            if (tidptr != 0) {
                if (tidptr >= (uint64_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                cur->clear_child_tid = tidptr;
            }
            return (uint64_t)(cur->tid ? cur->tid : 1);
        }
        case SYS_vfork: {
            /* Minimal vfork semantics:
               - create child thread that shares parent's address space and fds
               - parent is blocked until child calls execve or exit
               - parent returns child's pid, child returns 0
             */
            thread_t *p = cur;
            if (!p) return ret_err(EINVAL);
            /* Read saved return RIP and user RSP saved by syscall_entry64.
               The assembly syscall entry writes the saved return RIP into
               global `syscall_saved_ret_rip` for reliable access from C. */
            /* prefer recorded user return RIP (works for both int0x80 and SYSCALL paths) */
            uint64_t saved_rcx = p->saved_user_rip;
            /* If saved return RIP wasn't recorded, attempt to find a valid candidate
               on the kernel syscall stack using stricter validation. */
            if (saved_rcx == 0) {
                extern uint64_t syscall_kernel_rsp0;
                if ((uintptr_t)syscall_kernel_rsp0 != 0) {
                    uint64_t candidate = 0;
                    if (find_valid_saved_ret(syscall_kernel_rsp0, &candidate, 64) == 0) {
                        saved_rcx = candidate;
                    } else {
                    }
                }
            }
            uint64_t saved_rsp = p->saved_user_rsp;

            /* If we still don't have a valid saved_rcx at this point, fail early. */
            if (saved_rcx == 0) {
                return ret_err(EINVAL);
            }
            /* Try to ensure the user pages around saved_rcx are user-accessible to avoid PF
               when the child enters user mode. This sets PG_US on the containing 2MiB region. */
            if (saved_rcx != 0) {
                uintptr_t begin = (uintptr_t)saved_rcx & ~((uintptr_t)PAGE_SIZE_2M - 1);
                uintptr_t end = begin + (uintptr_t)PAGE_SIZE_2M;
                if (mark_user_identity_range_2m_sys((uint64_t)begin, (uint64_t)end) == 0) {
                } else {
                    /* If we cannot make the candidate return site user-accessible, refuse vfork
                       rather than heuristically using an unmapped/privileged address which
                       leads to immediate #PF err=0x5 when the child enters user mode. */
                    kprintf("vfork: aborting due to unmapped/privileged saved return site\n");
                    return ret_err(EINVAL);
                }
                /* Also try to broadly ensure common user ranges are user-accessible (helps when writes hit elsewhere). */
                if (mark_user_identity_range_2m_sys(0x200000, (uint64_t)USER_STACK_TOP) == 0) {
                } else {
                }
            }
            // kprintf("DBG: vfork: syscall_user_return_rip=0x%llx syscall_user_rsp_saved=0x%llx (saved_rcx=0x%llx saved_rsp=0x%llx)\n",
            //         (unsigned long long)syscall_user_return_rip, (unsigned long long)syscall_user_rsp_saved,
            //         (unsigned long long)saved_rcx, (unsigned long long)saved_rsp);
            /* vfork semantics for AxonOS (safe variant):
               - create child thread, but do NOT run it on the parent's stack
               - copy active portion of parent's stack into a dedicated child stack
               - parent is NOT blocked in-kernel (avoids returning from a blocked syscall frame)
               This behaves closer to fork(), but avoids the post-exit #GP caused by
               corruption of the parent's syscall frame while it is blocked in-kernel. */
            if (saved_rcx == 0) {
                /* cannot create child if we don't have return site */
                return ret_err(EINVAL);
            }
            /* create child kernel thread that will enter user mode at user_thread_entry.
               Create it BLOCKED first to avoid it running before we finish initializing
               user_rip/user_stack/user_fs_base (race became visible once we added an always-READY idle thread). */
            thread_t *child = thread_create_blocked(user_thread_entry, "vfork-child");
            if (!child) return ret_err(ENOMEM);
            /* initialize child's user context and inherit parent's FDs/credentials */
            /* Create a small user-mode trampoline that zeroes RAX and jumps to saved_rcx.
               This avoids executing user code directly in an unknown register/stack snapshot. */
            {
                /* ---- clone parent's active stack slice into child's own stack ---- */
                uintptr_t parent_fs = (uintptr_t)p->user_fs_base;
                uintptr_t parent_tls_region = (parent_fs >= 0x1000u) ? (parent_fs - 0x1000u) : 0;
                if ((uintptr_t)saved_rsp == 0 || (uintptr_t)saved_rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    return ret_err(EINVAL);
                }
                uintptr_t max_copy = (uintptr_t)USER_STACK_SIZE;
                if (max_copy > (uintptr_t)(1024 * 1024)) max_copy = (uintptr_t)(1024 * 1024);
                uintptr_t avail = (uintptr_t)MMIO_IDENTITY_LIMIT - (uintptr_t)saved_rsp;
                uintptr_t copy_bytes = (avail < max_copy) ? avail : max_copy;
                if (copy_bytes < 256) {
                    return ret_err(EINVAL);
                }

                /* pick child's stack_top based on child tid to avoid overlap */
                uintptr_t child_stack_top = (uintptr_t)USER_STACK_TOP;
                /* reuse the same layout helper as exec uses: stack_top = tls + sizes */
                {
                    extern uintptr_t user_stack_top_for_tid(uint64_t tid); /* in core/elf.c (static), can't call */
                    (void)user_stack_top_for_tid;
                }
                /* We can't call elf.c static helper here, so derive stack_top from parent's
                   canonical layout by using child's tls base region below USER_STACK_TOP:
                   stack_top = USER_STACK_TOP - (tid+1)*stride. Keep stride in sync with elf.c. */
                {
                    const uintptr_t stride = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + (uintptr_t)(64 * 1024);
                    const uint64_t slot = (uint64_t)child->tid + 1ULL;
                    /* Avoid overflow and avoid (off + 0x10000) wrap. If tid is out of range, use top slot. */
                    if (stride != 0 && slot <= (uint64_t)((uintptr_t)-1) / (uint64_t)stride) {
                        const uintptr_t off = (uintptr_t)(slot * (uint64_t)stride);
                        const uintptr_t top = (uintptr_t)USER_STACK_TOP;
                        const uintptr_t min_room = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + 0x10000u;
                        if (top > min_room && off < (top - min_room)) {
                            child_stack_top = (uintptr_t)USER_STACK_TOP - off;
                        }
                    }
                }
                child_stack_top &= ~((uintptr_t)0xFULL);
                uintptr_t child_rsp = (child_stack_top - copy_bytes);
                /* Preserve original stack alignment (SSE movdqa expects this). */
                uintptr_t align_mask = (uintptr_t)0xFULL;
                uintptr_t want = (uintptr_t)saved_rsp & align_mask;
                uintptr_t have = (uintptr_t)child_rsp & align_mask;
                if (have != want) {
                    child_rsp += (want - have) & align_mask;
                }

                /* ensure child stack region is user-accessible */
                {
                    uintptr_t sb = (child_stack_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL;
                    if (mark_user_identity_range_2m_sys((uint64_t)sb, (uint64_t)child_stack_top) != 0) {
                        return ret_err(EFAULT);
                    }
                }
                /* copy active stack slice */
                memcpy((void*)child_rsp, (void*)(uintptr_t)saved_rsp, (size_t)copy_bytes);
                /* Relocate pointers inside the copied stack slice itself */
                {
                    const uintptr_t parent_lo = (uintptr_t)saved_rsp;
                    const uintptr_t parent_hi = parent_lo + (uintptr_t)copy_bytes;
                    const uintptr_t delta = (uintptr_t)child_rsp - parent_lo;
                    uintptr_t pp = (uintptr_t)child_rsp;
                    uintptr_t end = (uintptr_t)child_rsp + (uintptr_t)copy_bytes;
                    for (; pp + 8 <= end; pp += 8) {
                        uint64_t v = *(uint64_t*)(uintptr_t)pp;
                        uintptr_t vv = (uintptr_t)v;
                        if (vv >= parent_lo && vv < parent_hi) {
                            *(uint64_t*)(uintptr_t)pp = (uint64_t)(vv + delta);
                        }
                    }
                }

                /* ---- set up separate TLS (copy 4KiB from parent) ---- */
                uintptr_t child_tls_region = child_stack_top - (uintptr_t)USER_STACK_SIZE - (uintptr_t)USER_TLS_SIZE;
                /* Use same layout as exec: FS base inside region, fake pthread on next page. */
                uintptr_t child_fs = child_tls_region + 0x1000u;
                uintptr_t child_pthread_fake = child_tls_region + 0x2000u;
                if (mark_user_identity_range_2m_sys((uint64_t)child_tls_region, (uint64_t)(child_pthread_fake + 0x1000u)) != 0) {
                    return ret_err(EFAULT);
                }
                /* clear/clone minimal TLS layout (3 pages) */
                memset((void*)child_tls_region, 0, 0x3000u);
                if (parent_tls_region != 0 && parent_tls_region + 0x3000u < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    memcpy((void*)child_tls_region, (void*)parent_tls_region, 0x3000u);
                } else {
                    /* already zeroed */
                }
                /* Ensure the self pointer slot used by glibc pthread_getspecific is valid. */
                *(volatile uint64_t*)(uintptr_t)(child_fs - 0x78u) = (uint64_t)child_pthread_fake;
                /* Provide default "C" locale string for specifics[5] (see core/elf.c). */
                {
                    const uintptr_t c_str = child_tls_region + 0x2800u;
                    if (c_str + 2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                        *(volatile uint8_t*)(uintptr_t)(c_str + 0) = (uint8_t)'C';
                        *(volatile uint8_t*)(uintptr_t)(c_str + 1) = 0;
                        const uintptr_t specific5_slot = child_pthread_fake + 0x80u + (uintptr_t)(5u * 8u);
                        /* The TLS region may have been cloned from parent and contain garbage/non-canonical
                           pointers in the specifics area. Clear a small window and force slot 5. */
                        for (int si = 0; si < 32; si++) {
                            *(volatile uint64_t*)(uintptr_t)(child_pthread_fake + 0x80u + (uintptr_t)(si * 8u)) = 0;
                        }
                        *(volatile uint64_t*)(uintptr_t)specific5_slot = (uint64_t)c_str;
                    }
                }
                child->user_fs_base = (uint64_t)child_fs;

                uintptr_t tramp = (uintptr_t)USER_VFORK_TRAMP;
                /* ensure tramp region is user-accessible */
                mark_user_identity_range_2m_sys((uint64_t)(tramp & ~((uintptr_t)(PAGE_SIZE_2M - 1))),
                                               (uint64_t)((tramp & ~((uintptr_t)(PAGE_SIZE_2M - 1))) + PAGE_SIZE_2M));
                if ((uintptr_t)tramp + 64 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    const uintptr_t parent_lo = (uintptr_t)saved_rsp;
                    const uintptr_t parent_hi = parent_lo + (uintptr_t)copy_bytes;
                    #define VFORK_RELOC(val64) \
                        ((((uintptr_t)(val64) >= parent_lo) && ((uintptr_t)(val64) < parent_hi)) ? \
                         (uint64_t)((uintptr_t)child_rsp + ((uintptr_t)(val64) - parent_lo)) : \
                         (uint64_t)(val64))
                    /* Build a vfork trampoline that restores a full user register snapshot
                       (as if we returned from a real SYSCALL instruction):
                         - restore caller-saved regs: RDI,RSI,RDX,R8,R9,R10,RCX,R11
                         - restore callee-saved regs: RBX,RBP,R12-R15
                         - set RAX=0 (vfork return value in child)
                         - set RSP=saved stack
                         - jump to RCX (return RIP) */
                    unsigned char stub[160];
                    int off = 0;
                    /* movabs rdi, imm64 */
                    uint64_t imm_rdi = VFORK_RELOC(p->saved_user_rdi);
                    stub[off++] = 0x48; stub[off++] = 0xBF; memcpy(&stub[off], &imm_rdi, 8); off += 8;
                    /* movabs rsi, imm64 */
                    uint64_t imm_rsi = VFORK_RELOC(p->saved_user_rsi);
                    stub[off++] = 0x48; stub[off++] = 0xBE; memcpy(&stub[off], &imm_rsi, 8); off += 8;
                    /* movabs rdx, imm64 */
                    uint64_t imm_rdx = VFORK_RELOC(p->saved_user_rdx);
                    stub[off++] = 0x48; stub[off++] = 0xBA; memcpy(&stub[off], &imm_rdx, 8); off += 8;
                    /* movabs r8, imm64 */
                    uint64_t imm_r8 = VFORK_RELOC(p->saved_user_r8);
                    stub[off++] = 0x49; stub[off++] = 0xB8; memcpy(&stub[off], &imm_r8, 8); off += 8;
                    /* movabs r9, imm64 */
                    uint64_t imm_r9 = VFORK_RELOC(p->saved_user_r9);
                    stub[off++] = 0x49; stub[off++] = 0xB9; memcpy(&stub[off], &imm_r9, 8); off += 8;
                    /* movabs r10, imm64 */
                    uint64_t imm_r10 = VFORK_RELOC(p->saved_user_r10);
                    stub[off++] = 0x49; stub[off++] = 0xBA; memcpy(&stub[off], &imm_r10, 8); off += 8;
                    /* movabs rcx, imm64 (return RIP) */
                    uint64_t imm_rcx = (uint64_t)saved_rcx;
                    stub[off++] = 0x48; stub[off++] = 0xB9; memcpy(&stub[off], &imm_rcx, 8); off += 8;
                    /* movabs r11, imm64 (saved RFLAGS from SYSCALL) */
                    uint64_t imm_r11_flags = p->saved_user_r11;
                    stub[off++] = 0x49; stub[off++] = 0xBB; memcpy(&stub[off], &imm_r11_flags, 8); off += 8;
                    /* movabs rbx, imm64 */
                    uint64_t imm_rbx = VFORK_RELOC(p->saved_user_rbx);
                    stub[off++] = 0x48; stub[off++] = 0xBB; memcpy(&stub[off], &imm_rbx, 8); off += 8;
                    /* movabs rbp, imm64 */
                    uint64_t imm_rbp = VFORK_RELOC(p->saved_user_rbp);
                    stub[off++] = 0x48; stub[off++] = 0xBD; memcpy(&stub[off], &imm_rbp, 8); off += 8;
                    /* movabs r12, imm64 */
                    uint64_t imm_r12 = VFORK_RELOC(p->saved_user_r12);
                    stub[off++] = 0x49; stub[off++] = 0xBC; memcpy(&stub[off], &imm_r12, 8); off += 8;
                    /* movabs r13, imm64 */
                    uint64_t imm_r13 = VFORK_RELOC(p->saved_user_r13);
                    stub[off++] = 0x49; stub[off++] = 0xBD; memcpy(&stub[off], &imm_r13, 8); off += 8;
                    /* movabs r14, imm64 */
                    uint64_t imm_r14 = VFORK_RELOC(p->saved_user_r14);
                    stub[off++] = 0x49; stub[off++] = 0xBE; memcpy(&stub[off], &imm_r14, 8); off += 8;
                    /* movabs r15, imm64 */
                    uint64_t imm_r15 = VFORK_RELOC(p->saved_user_r15);
                    stub[off++] = 0x49; stub[off++] = 0xBF; memcpy(&stub[off], &imm_r15, 8); off += 8;
                    /* xor rax, rax -> return value 0 in child */
                    stub[off++] = 0x48; stub[off++] = 0x31; stub[off++] = 0xC0;
                    /* movabs rsp, saved_rsp -> 48 BC imm64 */
                    uint64_t imm_rsp = (uint64_t)child_rsp;
                    stub[off++] = 0x48; stub[off++] = 0xBC; memcpy(&stub[off], &imm_rsp, 8); off += 8;
                    /* jmp rcx -> FF E1 */
                    stub[off++] = 0xFF; stub[off++] = 0xE1;
                    #undef VFORK_RELOC
                    /* pad with NOPs */
                    for (int z = off; z < (int)sizeof(stub); z++) stub[z] = 0x90;
                    memcpy((void*)(uintptr_t)tramp, stub, (size_t)off);
                    /* Read back bytes to verify write succeeded */
                    unsigned char verify[16];
                    memcpy(verify, (void*)(uintptr_t)tramp, sizeof(verify));
                    child->user_rip = (uint64_t)tramp;
                } else {
                    /* fallback: use saved_rcx if tramp can't be used */
                    child->user_rip = saved_rcx;
                }
                child->user_stack = (uint64_t)child_rsp;
                child->ring = 3;
            }
            child->parent_tid = (int)(p->tid ? p->tid : 1);
            child->sid = p->sid;
            child->pgid = p->pgid;
            child->euid = p->euid; child->egid = p->egid;
            child->attached_tty = p->attached_tty;
            strncpy(child->cwd, p->cwd, sizeof(child->cwd) - 1);
            child->cwd[sizeof(child->cwd) - 1] = '\0';
            qemu_debug_printf("vfork: parent=%llu child=%llu saved_rcx=0x%llx saved_rsp=0x%llx\n",
                (unsigned long long)(p->tid ? p->tid : 1),
                (unsigned long long)(child->tid ? child->tid : 1),
                (unsigned long long)saved_rcx, (unsigned long long)saved_rsp);
            /* Preserve parent userspace memory across vfork/exec.
               In our shared-address-space model, exec in the child overwrites
               parent memory, so we must snapshot+restore for correctness.
               Optimization: backup only the used region (heap + mmap) instead of
               the full 0x200000..USER_TLS_BASE (~122 MiB). Typical vfork+exec
               (sh, busybox) uses only a few MiB. */
            {
                const uintptr_t base = (uintptr_t)0x00200000u;
                uintptr_t end = (uintptr_t)USER_TLS_BASE;
                if (end < base) end = base;
                /* Backup only up to the end of used memory */
                uintptr_t used_end = (uintptr_t)p->user_brk_cur;
                if (p->user_mmap_next > used_end) used_end = p->user_mmap_next;
                /* Minimum: cover program load + small heap (busybox ~2MB at 0x400000) */
                const uintptr_t min_backup = base + (8u * 1024u * 1024u);
                if (used_end < min_backup || used_end == 0) used_end = min_backup;
                if (used_end > end) used_end = end;
                uint64_t len64 = (uint64_t)(used_end - base);
                if (len64 == 0 || len64 > (uint64_t)(256u * 1024u * 1024u)) {
                    return ret_err(ENOMEM);
                }
                child->vfork_parent_mem_backup = kmalloc((size_t)len64);
                if (!child->vfork_parent_mem_backup) {
                    return ret_err(ENOMEM);
                }
                /* Small backup: single copy. Large: chunk with yields to avoid freeze. */
                const size_t chunk = 512u * 1024u;
                if ((size_t)len64 <= chunk) {
                    memcpy(child->vfork_parent_mem_backup, (void*)base, (size_t)len64);
                } else {
                    for (size_t off = 0; off < (size_t)len64; off += chunk) {
                        size_t n = chunk;
                        if (off + n > (size_t)len64) n = (size_t)len64 - off;
                        memcpy((char*)child->vfork_parent_mem_backup + off, (void*)(base + off), n);
                        if (off + n < (size_t)len64) thread_yield();
                    }
                }
                child->vfork_parent_mem_backup_len = len64;
                child->vfork_parent_mem_backup_base = (uint64_t)base;
                child->vfork_parent_brk_saved = (uint64_t)p->user_brk_cur;
                child->vfork_parent_tid = (int)(p->tid ? p->tid : 1);
                /* block parent until child exits */
                p->vfork_parent_tid = -1;
                p->state = THREAD_BLOCKED;
                qemu_debug_printf("vfork: parent blocked, child->vfork_parent_tid=%d\n", child->vfork_parent_tid);
            }
            /* duplicate file descriptors (increase refcounts) */
            for (int i = 0; i < THREAD_MAX_FD; i++) {
                child->fds[i] = p->fds[i];
                if (child->fds[i]) {
                    if (child->fds[i]->refcount <= 0) child->fds[i]->refcount = 1;
                    else child->fds[i]->refcount++;
                }
            }
            /* If parent was blocked (init backup path), yield to run child now. */
            if (p->state == THREAD_BLOCKED && child->vfork_parent_tid >= 0) {
                qemu_debug_printf("vfork: unblocking child %llu, calling thread_schedule()\n",
                    (unsigned long long)(child->tid ? child->tid : 1));
                thread_unblock((int)(child->tid ? child->tid : 1));
                thread_schedule();
                /* parent resumed after child exit; restore syscall frame */
                qemu_debug_printf("vfork: parent %llu resumed after child exit\n",
                    (unsigned long long)(p->tid ? p->tid : 1));
                rebuild_syscall_frame(p);
                return (uint64_t)(child->tid ? child->tid : 1);
            }
            /* default path: do not block parent; just allow child to run */
            qemu_debug_printf("vfork: default path, unblocking child %llu\n",
                (unsigned long long)(child->tid ? child->tid : 1));
            child->vfork_parent_tid = -1;
            thread_unblock((int)(child->tid ? child->tid : 1));
            /* when parent is unblocked and resumes here, return child's pid to parent */
            return (uint64_t)(child->tid ? child->tid : 1);
        }
        case SYS_set_robust_list:
            /* set_robust_list(head, len): accept (no robust futex handling yet) */
            (void)a1; (void)a2;
            return 0;
        case SYS_futex: {
            /* minimal futex handler: FUTEX_WAIT / FUTEX_WAKE */
            extern int futex_syscall(uintptr_t uaddr, int op, int val, const void *timeout, uintptr_t uaddr2, int val3);
            int res = futex_syscall((uintptr_t)a1, (int)a2, (int)a3, (const void*)(uintptr_t)a4, (uintptr_t)a5, (int)a6);
            if (res < 0) return ret_err(-res);
            return (uint64_t)res;
        }
        case SYS_rseq:
            /* Minimal rseq registration:
               int rseq(struct rseq *rseq, uint32_t rseq_len, int flags, uint32_t sig)
               We accept a non-NULL pointer and length (basic validation) and store it
               per-thread so userspace can use rseq registration checks. This is not a
               full rseq implementation but enough for libc compatibility. */
            {
                const void *rseq_ptr = (const void*)(uintptr_t)a1;
                uint32_t rseq_len = (uint32_t)a2;
                int flags = (int)a3;
                (void)flags;
                thread_t *tcur = thread_get_current_user();
                if (!tcur) tcur = thread_current();
                if (rseq_ptr == NULL) {
                    /* unregister */
                    if (tcur) tcur->rseq_ptr = NULL;
                    return 0;
                }
                if ((uintptr_t)rseq_ptr + (uintptr_t)rseq_len > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                if (rseq_len < 16 || rseq_len > 4096) return ret_err(EINVAL);
                if (tcur) tcur->rseq_ptr = (void*)rseq_ptr;
                return 0;
            }
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

            /* First try the real VFS symlink implementation. */
            char kpath[256];
            resolve_user_path(cur, path, kpath, sizeof(kpath));
            ssize_t rr = vfs_readlink(kpath, buf, bufsiz);
            if (rr >= 0) return (uint64_t)rr;

            /* Fallback: provide /proc/self/exe for libc/busybox even if procfs doesn't implement it yet. */
            if (strcmp(kpath, "/proc/self/exe") == 0) {
                const char *target = cur->name[0] ? cur->name : "/bin/busybox";
                size_t L = strlen(target);
                if (bufsiz == 0) return ret_err(EINVAL);
                if (L > bufsiz) L = bufsiz;
                memcpy(buf, target, L);
                return (uint64_t)L; /* no NUL terminator */
            }
            return ret_err(ENOENT);
        }
        case SYS_link: {
            /* link(oldpath, newpath) - create hard link */
            const char *oldpath_u = (const char*)(uintptr_t)a1;
            const char *newpath_u = (const char*)(uintptr_t)a2;
            if (!oldpath_u || !newpath_u) return ret_err(EFAULT);
            if ((uintptr_t)oldpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)newpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char oldpath[256], newpath[256];
            resolve_user_path(cur, oldpath_u, oldpath, sizeof(oldpath));
            resolve_user_path(cur, newpath_u, newpath, sizeof(newpath));
            int r = fs_link(oldpath, newpath);
            if (r == 0) return 0;
            return ret_err(r < 0 ? -r : EIO);
        }
        case SYS_rename: {
            /* rename(oldpath, newpath) - syscall 82; rpm needs this for move */
            const char *oldpath_u = (const char*)(uintptr_t)a1;
            const char *newpath_u = (const char*)(uintptr_t)a2;
            if (!oldpath_u || !newpath_u) return ret_err(EFAULT);
            if ((uintptr_t)oldpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)newpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char oldpath[256], newpath[256];
            resolve_user_path(cur, oldpath_u, oldpath, sizeof(oldpath));
            resolve_user_path(cur, newpath_u, newpath, sizeof(newpath));
            /* If newpath is a directory, target is newpath/basename(oldpath) (POSIX) */
            {
                struct stat st;
                if (vfs_stat(newpath, &st) == 0 && (st.st_mode & S_IFDIR)) {
                    const char *base = strrchr(oldpath, '/');
                    base = base ? base + 1 : oldpath;
                    size_t nlen = strlen(newpath);
                    size_t blen = strlen(base);
                    if (nlen + 1 + blen + 1 <= sizeof(newpath)) {
                        if (nlen > 0 && newpath[nlen - 1] != '/') {
                            newpath[nlen] = '/';
                            newpath[nlen + 1] = '\0';
                            nlen++;
                        }
                        memcpy(newpath + nlen, base, blen + 1);
                    }
                }
            }
            int r = fs_rename(oldpath, newpath);
            if (r == 0) return 0;
            /* Map fs driver internal codes to Linux errno (ramfs uses -1,-2,-3,-5) */
            if (r == -2) return ret_err(ENOENT);
            if (r == -3) return ret_err(ENOTDIR);
            if (r == -5) return ret_err(ENOMEM);
            if (r == -17) return ret_err(EEXIST);
            return ret_err(r < 0 ? -r : EIO);
        }
        case SYS_umask: {
            /* umask(mask) - syscall 95; returns previous mask, sets new mask */
            unsigned int mask = (unsigned int)(a1 & 07777u);
            unsigned int prev = cur->umask;
            cur->umask = mask;
            return (uint64_t)prev;
        }
        case SYS_mkdir: {
            /* mkdir(path, mode) - syscall 83; init often runs "mkdir -p /dev" before mount */
            const char *path_u = (const char*)(uintptr_t)a1;
            mode_t mode = (mode_t)(a2 & 0xFFFFu);
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            if (path[0] == '\0') return ret_err(EINVAL);
            /* root "/" always exists; rpm may do mkdir -p / and fail with EPERM otherwise */
            if (path[0] == '/' && path[1] == '\0') return 0;
            int r = fs_mkdir(path);
            if (r == 0) {
                (void)fs_chmod(path, (mode & 07777u) | S_IFDIR);
                return 0;
            }
            return ret_err(r < 0 ? -r : EIO);
        }
        case SYS_chmod: {
            /* chmod(path, mode) */
            const char *path_u = (const char*)(uintptr_t)a1;
            mode_t mode = (mode_t)(a2 & 0xFFFFu);
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct stat st;
            if (vfs_stat(path, &st) != 0) return ret_err(ENOENT);
            int r = fs_chmod(path, mode);
            if (r == 0) return 0;
            return ret_err(EPERM);
        }
        case SYS_chown: {
            /* chown(path, uid, gid) - syscall 92; rpm may set ownership; stub success */
            (void)a1; (void)a2; (void)a3;
            return 0;
        }
        case SYS_utimensat: {
            /* utimensat(dirfd, path, times, flags) - syscall 280; rpm may set mtime; stub success */
            (void)a1; (void)a2; (void)a3; (void)a4;
            return 0;
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
        case SYS_gettimeofday: {
            /* gettimeofday(struct timeval *tv, struct timezone *tz) */
            void *tv_u = (void*)(uintptr_t)a1;
            (void)a2;
            if (!tv_u) return ret_err(EFAULT);
            struct timeval_k { int64_t tv_sec; int64_t tv_usec; } tv;
            rtc_datetime_t dt;
            rtc_read_datetime(&dt);
            uint64_t secs = rtc_datetime_to_epoch(&dt);
            uint64_t usec = (uint64_t)(pit_get_time_ms() % 1000ULL) * 1000ULL;
            tv.tv_sec = (int64_t)secs;
            tv.tv_usec = (int64_t)usec;
            if (copy_to_user_safe(tv_u, &tv, sizeof(tv)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_clock_nanosleep: {
            /* clock_nanosleep(clockid, flags, req, rem) */
            (void)a1;
            uint64_t flags = a2;
            const void *req_u = (const void*)(uintptr_t)a3;
            void *rem_u = (void*)(uintptr_t)a4;
            (void)rem_u;
            if (flags != 0) return ret_err(EINVAL);
            if (!req_u) return ret_err(EFAULT);
            struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
            if (copy_from_user_raw(&ts, req_u, sizeof(ts)) != 0) return ret_err(EFAULT);
            if (ts.tv_sec < 0 || ts.tv_nsec < 0) return ret_err(EINVAL);
            uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
            if (ms == 0 && ts.tv_nsec > 0) ms = 1;
            if (ms > 0) thread_sleep((uint32_t)ms);
            return 0;
        }
        case SYS_access: {
            /* access(path, mode) */
            const char *path_u = (const char*)(uintptr_t)a1;
            (void)a2;
            if (!path_u) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct stat st;
            if (vfs_stat(path, &st) == 0) return 0;
            return ret_err(ENOENT);
        }
        case 201: { /* time(time_t *tloc) */
            void *tloc = (void*)(uintptr_t)a1;
            /* If pointer is provided, store seconds since epoch there (time_t is 64-bit) */
            rtc_datetime_t dt;
            rtc_read_datetime(&dt);
            uint64_t secs = rtc_datetime_to_epoch(&dt);
            if (tloc) {
                if ((uintptr_t)tloc + sizeof(int64_t) > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                int64_t sval = (int64_t)secs;
                if (copy_to_user_safe(tloc, &sval, sizeof(sval)) != 0) return ret_err(EFAULT);
            }
            return (uint64_t)secs;
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
            snprintf(u.release, sizeof(u.release), "3.2.0", OS_VERSION);
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
            if (is_init_user(cur)) return 1;
            return (uint64_t)(cur->tid ? cur->tid : 1);
        case SYS_getppid:
            if (is_init_user(cur)) return 0;
            if (cur && cur->parent_tid >= 0) return (uint64_t)cur->parent_tid;
            return 1;
        case SYS_gettid:
            if (is_init_user(cur)) return 1;
            return (uint64_t)(cur->tid ? cur->tid : 1);
        case SYS_getuid:
        case SYS_geteuid:
            return (uint64_t)cur->euid;
        case SYS_getgid:
        case SYS_getegid:
            return (uint64_t)cur->egid;
        case SYS_setsid:
            if (cur) {
                cur->sid = (int)(cur->tid ? cur->tid : 1);
                cur->pgid = (int)(cur->tid ? cur->tid : 1);
                user_pgrp = (uint64_t)cur->pgid;
            }
            return user_pgrp;
        case SYS_getpgrp:
            if (cur) {
                if (cur->pgid != 0) return (uint64_t)cur->pgid;
            }
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
                /* Allow setting pgid for current process or a child process.
                   If pid refers to another thread, verify it's a child of current (simple permission). */
                if ((uint64_t)pid != self) {
                    thread_t *t = thread_get(pid);
                    if (!t) {
                        kprintf("sys_setpgid: pid=%d pgid=%d -> ESRCH (not found)\n", pid, pgid);
                        return ret_err(ESRCH);
                    }
                    /* simple permission: only parent can change child's pgid */
                    if (t->parent_tid != (int)self) {
                        kprintf("sys_setpgid: pid=%d pgid=%d -> EPERM (not parent)\n", pid, pgid);
                        return ret_err(EPERM);
                    }
                    /* Additional guard: do not allow setting arbitrary pgid==1 (init) unless
                       caller is pid 1. This avoids user processes mistakenly moving into
                       init's pgrp which later confuses job control and can cause shells to exit. */
                    if (pgid == 1 && (int)self != 1 && !is_init_user(cur)) {
                        kprintf("sys_setpgid: pid=%d attempted to set pgid=1 -> EPERM (denied)\n", pid);
                        return ret_err(EPERM);
                    }
                    /* Additional guard: do not allow setting arbitrary pgid different from current
                       unless caller is session leader. */
                    int caller_tid = (int)self;
                    int caller_sid = cur ? cur->sid : -1;
                    if ((int)pgid != t->pgid && caller_sid != caller_tid) {
                        kprintf("sys_setpgid: pid=%d pgid=%d -> EPERM (not session leader)\n", pid, pgid);
                        return ret_err(EPERM);
                    }
                    t->pgid = pgid;
                } else {
                    if (cur) cur->pgid = pgid;
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
        case SYS_select: { /* select(nfds, readfds, writefds, exceptfds, timeout) - minimal stub */
            int nfds = (int)a1;
            (void)a2; (void)a3; (void)a4;
            void *timeout_u = (void*)(uintptr_t)a5;
            if (nfds < 0) return ret_err(EINVAL);
            if (timeout_u && (uintptr_t)timeout_u < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                struct timeval_k { int64_t tv_sec; int64_t tv_usec; } tv;
                if (copy_from_user_raw(&tv, timeout_u, sizeof(tv)) == 0 && (tv.tv_sec > 0 || tv.tv_usec > 0)) {
                    uint64_t ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000ULL);
                    if (ms == 0 && tv.tv_usec > 0) ms = 1;
                    if (ms > 0) thread_sleep((uint32_t)(ms > 0xFFFFFFFFULL ? 0xFFFFFFFFU : (uint32_t)ms));
                }
            }
            /* No fd readiness; return 0 (timeout / no events) */
            return 0;
        }
        case SYS_nanosleep: { /* nanosleep(req, rem) - Linux 35 */
            const void *req_u = (const void*)(uintptr_t)a1;
            void *rem_u = (void*)(uintptr_t)a2;
            (void)rem_u;
            if (!req_u) return ret_err(EFAULT);
            struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
            if (copy_from_user_raw(&ts, req_u, sizeof(ts)) != 0) return ret_err(EFAULT);
            if (ts.tv_sec < 0 || ts.tv_nsec < 0) return ret_err(EINVAL);
            uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
            if (ms == 0 && ts.tv_nsec > 0) ms = 1;
            if (ms > 0) thread_sleep((uint32_t)(ms > 0xFFFFFFFFULL ? 0xFFFFFFFFU : (uint32_t)ms));
            return 0;
        }
        case SYS_socket: { /* socket(domain, type, protocol) - no network stack */
            (void)a1; (void)a2; (void)a3;
            return ret_err(ENOSYS);
        }
        case SYS_sysinfo: { /* sysinfo(struct sysinfo *) - syscall 99; glibc allocatestack needs sane freeram */
            void *info_u = (void*)(uintptr_t)a1;
            if (!info_u || (uintptr_t)info_u + 112 > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            /* Linux struct sysinfo x86_64: uptime(0), loads[3](8), totalram(32), freeram(40), sharedram(48),
               bufferram(56), totalswap(64), freeswap(72), procs(80), pad(82), totalhigh(84), freehigh(92),
               mem_unit(100). glibc advise_stack_range: freesize from freeram*mem_unit; must be >= stack size. */
            uint8_t buf[128];
            memset(buf, 0, sizeof(buf));
            int64_t uptime_sec = (int64_t)(pit_get_time_ms() / 1000);
            memcpy(buf + 0, &uptime_sec, 8);
            /* loads[3] at 8,16,24 = 0 */
            uint64_t totalram = 128 * 1024 * 1024;  /* 128MB */
            uint64_t freeram = 64 * 1024 * 1024;   /* 64MB - enough for stack allocation */
            memcpy(buf + 32, &totalram, 8);
            memcpy(buf + 40, &freeram, 8);
            /* sharedram, bufferram at 48,56 = 0 */
            /* totalswap, freeswap at 64,72 = 0 */
            uint16_t procs = (uint16_t)thread_get_count();
            memcpy(buf + 80, &procs, 2);
            /* totalhigh, freehigh at 84,92 = 0 */
            uint32_t mem_unit = 1;
            memcpy(buf + 100, &mem_unit, 4);
            if (copy_to_user_safe(info_u, buf, 112) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_getrlimit: { /* getrlimit(resource, rlim) */
            int resource = (int)a1;
            void *rlim_u = (void*)(uintptr_t)a2;
            if (!rlim_u || (uintptr_t)rlim_u + 16 > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            /* struct rlimit { rlim_t rlim_cur; rlim_t rlim_max; }; rlim_t = 64-bit */
            uint64_t cur_val = 0xFFFFFFFFFFFFFFFFULL, max_val = 0xFFFFFFFFFFFFFFFFULL;
            switch (resource) {
                case 3: /* RLIMIT_STACK */ cur_val = 8 * 1024 * 1024; max_val = cur_val; break;
                case 4: /* RLIMIT_CORE */ cur_val = 0; max_val = 0xFFFFFFFFFFFFFFFFULL; break;
                case 6: /* RLIMIT_NPROC */ cur_val = 4096; max_val = 4096; break;
                case 7: /* RLIMIT_NOFILE */ cur_val = (uint64_t)THREAD_MAX_FD; max_val = cur_val; break;
                case 9: /* RLIMIT_AS */ cur_val = max_val = 0xFFFFFFFFFFFFFFFFULL; break;
                default: cur_val = max_val = 0xFFFFFFFFFFFFFFFFULL; break;
            }
            if (copy_to_user_safe(rlim_u, &cur_val, sizeof(cur_val)) != 0) return ret_err(EFAULT);
            if (copy_to_user_safe((char*)rlim_u + 8, &max_val, sizeof(max_val)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case SYS_sched_getaffinity: { /* sched_getaffinity(pid, len, user_mask) */
            int pid = (int)a1;
            size_t len = (size_t)a2;
            void *mask_u = (void*)(uintptr_t)a3;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (pid != 0 && (uint64_t)pid != self) return ret_err(ESRCH);
            if (!mask_u || len < 8 || (uintptr_t)mask_u + len > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            /* Single CPU: set bit 0 */
            uint64_t mask = 1;
            size_t copy = len < 8 ? len : 8;
            if (copy_to_user_safe(mask_u, &mask, copy) != 0) return ret_err(EFAULT);
            for (size_t i = 8; i < len; i++) {
                char zero = 0;
                if (copy_to_user_safe((char*)mask_u + i, &zero, 1) != 0) return ret_err(EFAULT);
            }
            return 0;
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
        case SYS_dup2: { /* dup2(oldfd, newfd) — Linux 33; getty/nano need this to dup TTY to stdin/stdout/stderr */
            int oldfd = (int)a1;
            int newfd = (int)a2;
            int r = thread_fd_dup2(oldfd, newfd);
            if (r < 0) return ret_err(EBADF);
            return (uint64_t)r;
        }
        case 269: /* faccessat(dirfd, pathname, mode, flags) */
        case 271: /* safe trial: map to faccessat-like check (AT_FDCWD) */
        case 439: /* faccessat2(dirfd, pathname, mode, flags, ...) */
        {
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            int mode = (int)a3;
            int flags = (int)a4;
            (void)mode; (void)flags;
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            /* build path relative to CWD/dirfd similarly to 269, but only check existence */
            {
                char path[512];
                if (path_u[0] == '/') {
                    strncpy(path, path_u, sizeof(path));
                    path[sizeof(path) - 1] = '\0';
                } else {
                    const int AT_FDCWD = -100;
                    if (dirfd == AT_FDCWD) {
                        resolve_user_path(cur, path_u, path, sizeof(path));
                    } else if (dirfd >= 0 && dirfd < THREAD_MAX_FD && cur->fds[dirfd]) {
                        const char *base = cur->fds[dirfd]->path ? cur->fds[dirfd]->path : "/";
                        size_t bl = strlen(base);
                        if (bl + 1 + strlen(path_u) + 1 > sizeof(path)) return ret_err(ENAMETOOLONG);
                        char basecopy[512]; strncpy(basecopy, base, sizeof(basecopy)); basecopy[sizeof(basecopy)-1] = '\0';
                        if (basecopy[bl-1] != '/') {
                            char *s = strrchr(basecopy, '/');
                            if (s) *(s+1) = '\0';
                            else { basecopy[0] = '/'; basecopy[1] = '\0'; }
                        }
                        snprintf(path, sizeof(path), "%s%s", basecopy, path_u);
                    } else {
                        resolve_user_path(cur, path_u, path, sizeof(path));
                    }
                }
                struct stat st;
                if (vfs_stat(path, &st) != 0) return ret_err(ENOENT);
                return 0;
            }
            /* Additional diagnostics for syscall 271: dump raw args and nearby memory for easier debugging */
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
        case SYS_rt_sigtimedwait: {
            /* rt_sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout, size_t sigsetsize) */
            const void *timeout_u = (const void*)(uintptr_t)a3;
            size_t sigsetsize = (size_t)a4;
            void *info_u = (void*)(uintptr_t)a2;
            /* accept 0, 8, or glibc-sized 128-byte sigset; we use lower 64 bits */
            if (!(sigsetsize == 0 || sigsetsize == 8 || sigsetsize == 128)) return ret_err(EINVAL);
            uint64_t mask = 0;
            if (sigsetsize >= 8 && a1) {
                if (copy_from_user_raw(&mask, (const void*)(uintptr_t)a1, sizeof(mask)) != 0) return ret_err(EFAULT);
            }
            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            int sig = thread_fetch_pending_signal(tcur, mask ? mask : ~0ULL);
            if (sig) {
                if (sig == SIGCHLD && info_u) {
                    thread_t *c = find_terminated_child(tcur);
                    struct siginfo_k {
                        int si_signo;
                        int si_errno;
                        int si_code;
                        int si_pid;
                        int si_uid;
                        int si_status;
                        long si_utime;
                        long si_stime;
                    } info;
                    memset(&info, 0, sizeof(info));
                    info.si_signo = SIGCHLD;
                    info.si_code = 1; /* CLD_EXITED */
                    if (c) {
                        info.si_pid = (int)(c->tid ? c->tid : 1);
                        info.si_status = (int)((c->exit_status >> 8) & 0xFF);
                    }
                    copy_to_user_safe(info_u, &info, sizeof(info));
                }
                return (uint64_t)sig;
            }
            if (mask & (1ULL << (SIGCHLD - 1))) {
                thread_t *c = find_terminated_child(tcur);
                if (c) {
                    if (info_u) {
                        struct siginfo_k {
                            int si_signo;
                            int si_errno;
                            int si_code;
                            int si_pid;
                            int si_uid;
                            int si_status;
                            long si_utime;
                            long si_stime;
                        } info;
                        memset(&info, 0, sizeof(info));
                        info.si_signo = SIGCHLD;
                        info.si_code = 1; /* CLD_EXITED */
                        info.si_pid = (int)(c->tid ? c->tid : 1);
                        info.si_status = (int)((c->exit_status >> 8) & 0xFF);
                        copy_to_user_safe(info_u, &info, sizeof(info));
                    }
                    return (uint64_t)SIGCHLD;
                }
            }
            if (timeout_u) {
                struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
                if (copy_from_user_raw(&ts, timeout_u, sizeof(ts)) != 0) return ret_err(EFAULT);
                if (ts.tv_sec < 0 || ts.tv_nsec < 0) return ret_err(EINVAL);
                uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
                if (ms == 0 && ts.tv_nsec > 0) ms = 1;
                if (ms > 0) thread_sleep((uint32_t)ms);
                sig = thread_fetch_pending_signal(tcur, mask ? mask : ~0ULL);
                if (sig) {
                    if (sig == SIGCHLD && info_u) {
                        thread_t *c = find_terminated_child(tcur);
                        struct siginfo_k {
                            int si_signo;
                            int si_errno;
                            int si_code;
                            int si_pid;
                            int si_uid;
                            int si_status;
                            long si_utime;
                            long si_stime;
                        } info;
                        memset(&info, 0, sizeof(info));
                        info.si_signo = SIGCHLD;
                        info.si_code = 1; /* CLD_EXITED */
                        if (c) {
                            info.si_pid = (int)(c->tid ? c->tid : 1);
                            info.si_status = (int)((c->exit_status >> 8) & 0xFF);
                        }
                        copy_to_user_safe(info_u, &info, sizeof(info));
                    }
                    return (uint64_t)sig;
                }
                if (mask & (1ULL << (SIGCHLD - 1))) {
                    thread_t *c = find_terminated_child(tcur);
                    if (c) {
                        if (info_u) {
                            struct siginfo_k {
                                int si_signo;
                                int si_errno;
                                int si_code;
                                int si_pid;
                                int si_uid;
                                int si_status;
                                long si_utime;
                                long si_stime;
                            } info;
                            memset(&info, 0, sizeof(info));
                            info.si_signo = SIGCHLD;
                            info.si_code = 1; /* CLD_EXITED */
                            info.si_pid = (int)(c->tid ? c->tid : 1);
                            info.si_status = (int)((c->exit_status >> 8) & 0xFF);
                            copy_to_user_safe(info_u, &info, sizeof(info));
                        }
                        return (uint64_t)SIGCHLD;
                    }
                }
                return ret_err(EAGAIN);
            }
            /* no timeout: block until signal */
            for (;;) {
                thread_sleep(10);
                sig = thread_fetch_pending_signal(tcur, mask ? mask : ~0ULL);
                if (sig) {
                    if (sig == SIGCHLD && info_u) {
                        thread_t *c = find_terminated_child(tcur);
                        struct siginfo_k {
                            int si_signo;
                            int si_errno;
                            int si_code;
                            int si_pid;
                            int si_uid;
                            int si_status;
                            long si_utime;
                            long si_stime;
                        } info;
                        memset(&info, 0, sizeof(info));
                        info.si_signo = SIGCHLD;
                        info.si_code = 1; /* CLD_EXITED */
                        if (c) {
                            info.si_pid = (int)(c->tid ? c->tid : 1);
                            info.si_status = (int)((c->exit_status >> 8) & 0xFF);
                        }
                        copy_to_user_safe(info_u, &info, sizeof(info));
                    }
                    return (uint64_t)sig;
                }
                if (mask & (1ULL << (SIGCHLD - 1))) {
                    thread_t *c = find_terminated_child(tcur);
                    if (c) {
                        if (info_u) {
                            struct siginfo_k {
                                int si_signo;
                                int si_errno;
                                int si_code;
                                int si_pid;
                                int si_uid;
                                int si_status;
                                long si_utime;
                                long si_stime;
                            } info;
                            memset(&info, 0, sizeof(info));
                            info.si_signo = SIGCHLD;
                            info.si_code = 1; /* CLD_EXITED */
                            info.si_pid = (int)(c->tid ? c->tid : 1);
                            info.si_status = (int)((c->exit_status >> 8) & 0xFF);
                            copy_to_user_safe(info_u, &info, sizeof(info));
                        }
                        return (uint64_t)SIGCHLD;
                    }
                }
            }
        }
        case SYS_execve: {
            /* copy path, argv, envp from user and call kernel_execve_from_path */
            const char *path_u = (const char*)(uintptr_t)a1;
            const char *const *argv_u = (const char *const*)(uintptr_t)a2;
            const char *const *envp_u = (const char *const*)(uintptr_t)a3;
            if (!path_u) return ret_err(EFAULT);
            if (!user_range_ok(path_u, 1)) return ret_err(EFAULT);
            /* Copy path */
            size_t plen = user_strnlen_bounded(path_u, 1024);
            if (plen == 0 || plen >= 1024) return ret_err(ENOENT);
            char *path = (char*)kmalloc(plen + 1);
            if (!path) return ret_err(ENOMEM);
            if (!user_range_ok(path_u, plen + 1) || copy_from_user_raw(path, path_u, plen + 1) != 0) {
                kfree(path);
                return ret_err(EFAULT);
            }
            char resolved_path[512];
            resolve_user_path(cur, path, resolved_path, sizeof(resolved_path));
            /* Copy argv array (NULL-terminated) */
            int argc = 0;
            if (argv_u) {
                /* count args */
                while (argc < 256) {
                    uint64_t p = 0;
                    if (user_read_u64((const void*)(uintptr_t)(&argv_u[argc]), &p) != 0) {
                        kfree(path);
                        return ret_err(EFAULT);
                    }
                    if (p == 0) break;
                    argc++;
                }
            }
            const char **kargv = (const char**)kmalloc((size_t)(argc + 1) * sizeof(char*));
            if (!kargv) { kfree(path); return ret_err(ENOMEM); }
            for (int i = 0; i < argc; i++) {
                uint64_t a_up = 0;
                if (user_read_u64((const void*)(uintptr_t)(&argv_u[i]), &a_up) != 0) {
                    kfree((void*)kargv); kfree(path); return ret_err(EFAULT);
                }
                const char *a_u = (const char*)(uintptr_t)a_up;
                if (!a_u || !user_range_ok(a_u, 1)) { kfree((void*)kargv); kfree(path); return ret_err(EFAULT); }
                size_t L = user_strnlen_bounded(a_u, 4096);
                char *ks = (char*)kmalloc(L + 1);
                if (!ks) { for (int j=0;j<i;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(ENOMEM); }
                if (!user_range_ok(a_u, L + 1) || copy_from_user_raw(ks, a_u, L + 1) != 0) {
                    kfree(ks);
                    for (int j=0;j<i;j++) kfree((void*)kargv[j]);
                    kfree((void*)kargv);
                    kfree(path);
                    return ret_err(EFAULT);
                }
                kargv[i] = ks;
            }
            kargv[argc] = NULL;
            /* Copy envp similarly (but allow NULL) */
            int envc = 0;
            const char **kenvp = NULL;
            if (envp_u) {
                while (envc < 256) {
                    uint64_t p = 0;
                    if (user_read_u64((const void*)(uintptr_t)(&envp_u[envc]), &p) != 0) {
                        for (int j=0;j<argc;j++) kfree((void*)kargv[j]);
                        kfree((void*)kargv);
                        kfree(path);
                        return ret_err(EFAULT);
                    }
                    if (p == 0) break;
                    envc++;
                }
                kenvp = (const char**)kmalloc((size_t)(envc + 1) * sizeof(char*));
                if (!kenvp) { for (int j=0;j<argc;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(ENOMEM); }
                for (int i = 0; i < envc; i++) {
                    uint64_t e_up = 0;
                    if (user_read_u64((const void*)(uintptr_t)(&envp_u[i]), &e_up) != 0) {
                        for (int j=0;j<i;j++) kfree((void*)kenvp[j]);
                        kfree(kenvp);
                        for (int j=0;j<argc;j++) kfree((void*)kargv[j]);
                        kfree((void*)kargv);
                        kfree(path);
                        return ret_err(EFAULT);
                    }
                    const char *e_u = (const char*)(uintptr_t)e_up;
                    if (!e_u || !user_range_ok(e_u, 1)) { for (int j=0;j<i;j++) kfree((void*)kenvp[j]); kfree(kenvp); for (int j=0;j<argc;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(EFAULT); }
                    size_t L = user_strnlen_bounded(e_u, 4096);
                    char *ks = (char*)kmalloc(L + 1);
                    if (!ks) { for (int j=0;j<i;j++) kfree((void*)kenvp[j]); kfree(kenvp); for (int j=0;j<argc;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(ENOMEM); }
                    if (!user_range_ok(e_u, L + 1) || copy_from_user_raw(ks, e_u, L + 1) != 0) { kfree(ks); for (int j=0;j<i;j++) kfree((void*)kenvp[j]); kfree(kenvp); for (int j=0;j<argc;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(EFAULT); }
                    kenvp[i] = ks;
                }
                kenvp[envc] = NULL;
            }

            /* call kernel execve (does not return on success) */
            int rc = kernel_execve_from_path(resolved_path, (const char *const *)kargv, (const char *const *)kenvp);

            /* cleanup on failure */
            if (kenvp) { for (int i=0;i<envc;i++) if (kenvp[i]) kfree((void*)kenvp[i]); kfree(kenvp); }
            for (int i=0;i<argc;i++) if (kargv[i]) kfree((void*)kargv[i]);
            if (kargv) kfree((void*)kargv);
            kfree(path);
            if (rc == -2) return ret_err(ENOEXEC);
            return (rc == 0) ? 0 : ret_err(ENOENT);
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
        case SYS_fork: {
            /* Minimal fork emulation:
               - create a new kernel thread that will enter user mode at the saved
                 return RIP and user RSP (copied from syscall stack / saved RSP).
               - duplicate file descriptor table (increment refcounts).
               - return child's pid to parent, child will see 0 as fork return (user_thread_entry clears RAX). */
            /* Read saved return RIP from syscall entry recorded in `syscall_user_return_rip`.
               If it's zero (not recorded), attempt to read it from the kernel syscall stack
               top (`syscall_kernel_rsp0`) at the same offset used by the SYSCALL entry. */
            uint64_t saved_rcx = cur->saved_user_rip;
            if (saved_rcx == 0) {
                extern uint64_t syscall_kernel_rsp0;
                if ((uintptr_t)syscall_kernel_rsp0 != 0) {
                    uint64_t candidate = 0;
                    if (find_valid_saved_ret(syscall_kernel_rsp0, &candidate, 64) == 0) {
                        saved_rcx = candidate;
                    } else {
                    }
                }
            }
            uint64_t saved_rsp = cur->saved_user_rsp;

            /* create kernel thread that will enter user mode at saved_rcx/saved_rsp */
            if (saved_rcx == 0) {
                return ret_err(EINVAL);
            }
            /* Try to ensure the user pages around saved_rcx are user-accessible to avoid PF
               when the child enters user mode. This sets PG_US on the containing 2MiB region. */
            if (saved_rcx != 0) {
                uintptr_t begin = (uintptr_t)saved_rcx & ~((uintptr_t)PAGE_SIZE_2M - 1);
                uintptr_t end = begin + (uintptr_t)PAGE_SIZE_2M;
                if (mark_user_identity_range_2m_sys((uint64_t)begin, (uint64_t)end) == 0) {
                } else {
                }
                /* Also try to broadly ensure common user ranges are user-accessible (helps when writes hit elsewhere). */
                if (mark_user_identity_range_2m_sys(0x200000, (uint64_t)USER_STACK_TOP) == 0) {
                } else {
                }
            }
            char child_name[32];
            snprintf(child_name, sizeof(child_name), "%s.child", cur->name);
            // kprintf("DBG: fork: syscall_user_return_rip=0x%llx syscall_user_rsp_saved=0x%llx (saved_rcx=0x%llx saved_rsp=0x%llx)\n",
            //         (unsigned long long)syscall_user_return_rip, (unsigned long long)syscall_user_rsp_saved,
            //         (unsigned long long)saved_rcx, (unsigned long long)saved_rsp);
            /* Create BLOCKED first to avoid running before initialization. */
            thread_t *child = thread_create_blocked(user_thread_entry, child_name);
            if (!child) return ret_err(ENOMEM);
            /* clone parent's active stack slice into child's own stack (like vfork safe variant) */
            {
                uintptr_t parent_fs = (uintptr_t)cur->user_fs_base;
                uintptr_t parent_tls_region = (parent_fs >= 0x1000u) ? (parent_fs - 0x1000u) : 0;
                if ((uintptr_t)saved_rsp == 0 || (uintptr_t)saved_rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    return ret_err(EINVAL);
                }
                uintptr_t max_copy = (uintptr_t)USER_STACK_SIZE;
                if (max_copy > (uintptr_t)(1024 * 1024)) max_copy = (uintptr_t)(1024 * 1024);
                uintptr_t avail = (uintptr_t)MMIO_IDENTITY_LIMIT - (uintptr_t)saved_rsp;
                uintptr_t copy_bytes = (avail < max_copy) ? avail : max_copy;
                if (copy_bytes < 256) {
                    return ret_err(EINVAL);
                }

                uintptr_t child_stack_top = (uintptr_t)USER_STACK_TOP;
                {
                    const uintptr_t stride = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + (uintptr_t)(64 * 1024);
                    const uint64_t slot = (uint64_t)child->tid + 1ULL;
                    if (stride != 0 && slot <= (uint64_t)((uintptr_t)-1) / (uint64_t)stride) {
                        const uintptr_t off = (uintptr_t)(slot * (uint64_t)stride);
                        const uintptr_t top = (uintptr_t)USER_STACK_TOP;
                        const uintptr_t min_room = (uintptr_t)USER_STACK_SIZE + (uintptr_t)USER_TLS_SIZE + 0x10000u;
                        if (top > min_room && off < (top - min_room)) {
                            child_stack_top = (uintptr_t)USER_STACK_TOP - off;
                        }
                    }
                }
                child_stack_top &= ~((uintptr_t)0xFULL);
                uintptr_t child_rsp = (child_stack_top - copy_bytes);
                /* Preserve original stack alignment (SSE movdqa expects this). */
                uintptr_t align_mask = (uintptr_t)0xFULL;
                uintptr_t want = (uintptr_t)saved_rsp & align_mask;
                uintptr_t have = (uintptr_t)child_rsp & align_mask;
                if (have != want) {
                    child_rsp += (want - have) & align_mask;
                }

                {
                    uintptr_t sb = (child_stack_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL;
                    if (mark_user_identity_range_2m_sys((uint64_t)sb, (uint64_t)child_stack_top) != 0) {
                        return ret_err(EFAULT);
                    }
                }
                memcpy((void*)child_rsp, (void*)(uintptr_t)saved_rsp, (size_t)copy_bytes);
                {
                    const uintptr_t parent_lo = (uintptr_t)saved_rsp;
                    const uintptr_t parent_hi = parent_lo + (uintptr_t)copy_bytes;
                    const uintptr_t delta = (uintptr_t)child_rsp - parent_lo;
                    uintptr_t pp = (uintptr_t)child_rsp;
                    uintptr_t end = (uintptr_t)child_rsp + (uintptr_t)copy_bytes;
                    for (; pp + 8 <= end; pp += 8) {
                        uint64_t v = *(uint64_t*)(uintptr_t)pp;
                        uintptr_t vv = (uintptr_t)v;
                        if (vv >= parent_lo && vv < parent_hi) {
                            *(uint64_t*)(uintptr_t)pp = (uint64_t)(vv + delta);
                        }
                    }
                }

                /* set up TLS for child */
                uintptr_t child_tls_region = child_stack_top - (uintptr_t)USER_STACK_SIZE - (uintptr_t)USER_TLS_SIZE;
                uintptr_t child_fs = child_tls_region + 0x1000u;
                uintptr_t child_pthread_fake = child_tls_region + 0x2000u;
                if (mark_user_identity_range_2m_sys((uint64_t)child_tls_region, (uint64_t)(child_pthread_fake + 0x1000u)) != 0) {
                    return ret_err(EFAULT);
                }
                memset((void*)child_tls_region, 0, 0x3000u);
                if (parent_tls_region != 0 && parent_tls_region + 0x3000u < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    memcpy((void*)child_tls_region, (void*)parent_tls_region, 0x3000u);
                }
                *(volatile uint64_t*)(uintptr_t)(child_fs - 0x78u) = (uint64_t)child_pthread_fake;
                {
                    const uintptr_t c_str = child_tls_region + 0x2800u;
                    if (c_str + 2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                        *(volatile uint8_t*)(uintptr_t)(c_str + 0) = (uint8_t)'C';
                        *(volatile uint8_t*)(uintptr_t)(c_str + 1) = 0;
                        const uintptr_t specific5_slot = child_pthread_fake + 0x80u + (uintptr_t)(5u * 8u);
                        for (int si = 0; si < 32; si++) {
                            *(volatile uint64_t*)(uintptr_t)(child_pthread_fake + 0x80u + (uintptr_t)(si * 8u)) = 0;
                        }
                        *(volatile uint64_t*)(uintptr_t)specific5_slot = (uint64_t)c_str;
                    }
                }
                child->user_fs_base = (uint64_t)child_fs;

                /* set up user entry and stack for the child (restore full regs, relocate stack pointers) */
                {
                    uintptr_t tramp = (uintptr_t)USER_VFORK_TRAMP;
                    mark_user_identity_range_2m_sys((uint64_t)(tramp & ~((uintptr_t)(PAGE_SIZE_2M - 1))),
                                                   (uint64_t)((tramp & ~((uintptr_t)(PAGE_SIZE_2M - 1))) + PAGE_SIZE_2M));
                    if ((uintptr_t)tramp + 64 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                        const uintptr_t parent_lo = (uintptr_t)saved_rsp;
                        const uintptr_t parent_hi = parent_lo + (uintptr_t)copy_bytes;
                        #define VFORK_RELOC(val64) \
                            ((((uintptr_t)(val64) >= parent_lo) && ((uintptr_t)(val64) < parent_hi)) ? \
                             (uint64_t)((uintptr_t)child_rsp + ((uintptr_t)(val64) - parent_lo)) : \
                             (uint64_t)(val64))
                        unsigned char stub[160];
                        int off = 0;
                        uint64_t imm_rdi = VFORK_RELOC(cur->saved_user_rdi);
                        stub[off++] = 0x48; stub[off++] = 0xBF; memcpy(&stub[off], &imm_rdi, 8); off += 8;
                        uint64_t imm_rsi = VFORK_RELOC(cur->saved_user_rsi);
                        stub[off++] = 0x48; stub[off++] = 0xBE; memcpy(&stub[off], &imm_rsi, 8); off += 8;
                        uint64_t imm_rdx = VFORK_RELOC(cur->saved_user_rdx);
                        stub[off++] = 0x48; stub[off++] = 0xBA; memcpy(&stub[off], &imm_rdx, 8); off += 8;
                        uint64_t imm_r8 = VFORK_RELOC(cur->saved_user_r8);
                        stub[off++] = 0x49; stub[off++] = 0xB8; memcpy(&stub[off], &imm_r8, 8); off += 8;
                        uint64_t imm_r9 = VFORK_RELOC(cur->saved_user_r9);
                        stub[off++] = 0x49; stub[off++] = 0xB9; memcpy(&stub[off], &imm_r9, 8); off += 8;
                        uint64_t imm_r10 = VFORK_RELOC(cur->saved_user_r10);
                        stub[off++] = 0x49; stub[off++] = 0xBA; memcpy(&stub[off], &imm_r10, 8); off += 8;
                        uint64_t imm_rcx = (uint64_t)saved_rcx;
                        stub[off++] = 0x48; stub[off++] = 0xB9; memcpy(&stub[off], &imm_rcx, 8); off += 8;
                        uint64_t imm_r11_flags = cur->saved_user_r11;
                        stub[off++] = 0x49; stub[off++] = 0xBB; memcpy(&stub[off], &imm_r11_flags, 8); off += 8;
                        uint64_t imm_rbx = VFORK_RELOC(cur->saved_user_rbx);
                        stub[off++] = 0x48; stub[off++] = 0xBB; memcpy(&stub[off], &imm_rbx, 8); off += 8;
                        uint64_t imm_rbp = VFORK_RELOC(cur->saved_user_rbp);
                        stub[off++] = 0x48; stub[off++] = 0xBD; memcpy(&stub[off], &imm_rbp, 8); off += 8;
                        uint64_t imm_r12 = VFORK_RELOC(cur->saved_user_r12);
                        stub[off++] = 0x49; stub[off++] = 0xBC; memcpy(&stub[off], &imm_r12, 8); off += 8;
                        uint64_t imm_r13 = VFORK_RELOC(cur->saved_user_r13);
                        stub[off++] = 0x49; stub[off++] = 0xBD; memcpy(&stub[off], &imm_r13, 8); off += 8;
                        uint64_t imm_r14 = VFORK_RELOC(cur->saved_user_r14);
                        stub[off++] = 0x49; stub[off++] = 0xBE; memcpy(&stub[off], &imm_r14, 8); off += 8;
                        uint64_t imm_r15 = VFORK_RELOC(cur->saved_user_r15);
                        stub[off++] = 0x49; stub[off++] = 0xBF; memcpy(&stub[off], &imm_r15, 8); off += 8;
                        stub[off++] = 0x48; stub[off++] = 0x31; stub[off++] = 0xC0;
                        uint64_t imm_rsp = (uint64_t)child_rsp;
                        stub[off++] = 0x48; stub[off++] = 0xBC; memcpy(&stub[off], &imm_rsp, 8); off += 8;
                        stub[off++] = 0xFF; stub[off++] = 0xE1;
                        #undef VFORK_RELOC
                        for (int z = off; z < (int)sizeof(stub); z++) stub[z] = 0x90;
                        memcpy((void*)(uintptr_t)tramp, stub, off);
                        unsigned char verify[16];
                        memcpy(verify, (void*)(uintptr_t)tramp, sizeof(verify));
                        child->user_rip = (uint64_t)tramp;
                    } else {
                        child->user_rip = saved_rcx;
                    }
                    child->user_stack = (uint64_t)child_rsp;
                    child->ring = 3;
                }
            }
            /* inherit credentials */
            child->euid = cur->euid;
            child->egid = cur->egid;
            child->attached_tty = cur->attached_tty;
            /* inherit userspace TLS base so child doesn't fault on %fs */
            child->user_fs_base = cur->user_fs_base;
            /* inherit job control + parent */
            child->parent_tid = (int)(cur->tid ? cur->tid : 1);
            child->sid = cur->sid;
            child->pgid = cur->pgid;
            /* copy cwd */
            strncpy(child->cwd, cur->cwd, sizeof(child->cwd)-1);
            child->cwd[sizeof(child->cwd)-1] = '\0';
            /* duplicate file descriptors (increase refcounts) */
            for (int i = 0; i < THREAD_MAX_FD; i++) {
                child->fds[i] = cur->fds[i];
                if (child->fds[i]) {
                    if (child->fds[i]->refcount <= 0) child->fds[i]->refcount = 1;
                    else child->fds[i]->refcount++;
                }
            }
            /* now allow child to run */
            thread_unblock((int)(child->tid ? child->tid : 1));
            /* child is ready, return child's pid to parent */
            return (uint64_t)(child->tid ? child->tid : 1);
        }
        case SYS_wait4: {
            /* waitpid(pid, status*, options, rusage*) minimal implementation
               - pid > 0: wait for specific child pid
               - pid == -1: wait for any child
               We only support blocking wait (options == 0) and ignore rusage. */
            int pid = (int)a1;
            int *status_u = (int*)(uintptr_t)a2;
            int options = (int)a3;
            (void)a4;
            /* Support WNOHANG (1), WUNTRACED (2), WCONTINUED (8) as no-ops. */
            enum { WNOHANG = 1, WUNTRACED = 2, WCONTINUED = 8 };
            if (options & ~(WNOHANG | WUNTRACED | WCONTINUED)) return ret_err(ENOSYS);
            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            if (!tcur) return ret_err(EINVAL);

            for (;;) {
                thread_t *found = NULL;
                if (pid > 0) {
                    thread_t *c = thread_get(pid);
                    if (c && c->parent_tid == (int)tcur->tid) found = c;
                } else if (pid == -1) {
                    /* find any child of current that is not already reaped */
                    for (int i = 0; i < thread_get_count(); i++) {
                        thread_t *c = thread_get_by_index(i);
                        if (!c) continue;
                        if (c->parent_tid != (int)tcur->tid) continue;
                        if (c->state == THREAD_TERMINATED && c->exit_status == 0x80000000) continue; /* already reaped */
                        found = c;
                        break;
                    }
                } else {
                    return ret_err(EINVAL);
                }
                if (!found) {
                    /* Init fallback: if we somehow lost parent linkage, still reap any terminated child. */
                    if (pid == -1 && is_init_user(tcur)) {
                        for (int i = 0; i < thread_get_count(); i++) {
                            thread_t *c = thread_get_by_index(i);
                            if (!c) continue;
                            if (c->state == THREAD_TERMINATED && c->exit_status != 0x80000000) {
                                found = c;
                                break;
                            }
                        }
                    }
                    if (!found) {
                        if (options & WNOHANG) {
                            thread_sleep(1);
                            return 0;
                        }
                        return ret_err(ECHILD);
                    }
                }
                /* If child was already reaped, behave like Linux: ECHILD */
                if (found->state == THREAD_TERMINATED && found->exit_status == 0x80000000) {
                    if (options & WNOHANG) {
                        thread_sleep(1);
                        return 0;
                    }
                    return ret_err(ECHILD);
                }
                /* If already terminated -> return immediately */
                if (found->state == THREAD_TERMINATED && found->exit_status != 0x80000000) {
                    int st = found->exit_status;
                    if (status_u) {
                        if (copy_to_user_safe(status_u, &st, sizeof(st)) != 0) return ret_err(EFAULT);
                    }
                    /* mark reaped */
                    found->exit_status = 0x80000000;
                    return (uint64_t)(found->tid ? found->tid : 1);
                }
                /* not terminated -> WNOHANG returns immediately */
                if (options & WNOHANG) {
                    thread_sleep(1);
                    return 0;
                }
                /* block current thread and set waiter on child */
                found->waiter_tid = (int)tcur->tid;
                /* block current and yield */
                thread_block((int)tcur->tid);
                thread_yield();
                /* when unblocked, loop to check again */
            }
            return ret_err(EINVAL);
        }
        case SYS_ioctl: {
            int fd = (int)a1;
            uint64_t req = a2;
            void *argp = (void*)(uintptr_t)a3;
            /* Map negative fds to fd 0 (controlling/stdin) to be tolerant of libc behavior. */
            if (fd < 0) {
                fd = 0;
            }
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);

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

            /* Important: libc frequently probes terminal state on stdout/stderr very early
               (e.g. ld.lld does ioctl(TCGETS) on fd=2). Do NOT require tty classification
               for these "query" ioctls; return sensible defaults even if the fd isn't a tty.
               This avoids hangs if a file->path pointer is corrupted and devfs_is_tty_file()
               would fault while doing strcmp(). */
            if (req == TIOCGWINSZ) {
                if (!argp) return ret_err(EFAULT);
                struct winsize ws = { .ws_row = 25, 
                                      .ws_col = 80, 
                                      .ws_xpixel = 0, 
                                      .ws_ypixel = 0 };
                if (copy_to_user_safe(argp, &ws, sizeof(ws)) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (req == TIOCSWINSZ) {
                if (!argp)  return ret_err(EFAULT); /* accept setting window size silently */
                /* optionally we could copy_from_user and store winsize, but accept for now */
                return 0;
            }
            if (req == TIOCSCTTY) {
                /* Attach this thread to the tty as controlling tty. Allow when tty is free
                   so getty (launched by init, often not session leader) can acquire the console. */
                thread_t *curth = thread_current();
                if (!curth) return 0;
                int cur_sid = devfs_get_tty_controlling_sid(f);
                if (cur_sid >= 0 && cur_sid != curth->sid) return ret_err(EPERM);
                devfs_tty_attach_thread(f, curth);
                devfs_set_tty_controlling_sid(f, curth->sid);
                return 0;
            }
            if (req == TIOCGPGRP) {
                if (!argp) return ret_err(EFAULT);
                /* Try to return tty-specific foreground pgrp, fallback to global user_pgrp */
                int pgrp = devfs_tty_get_fg_pgrp(f);
                if (pgrp < 0) pgrp = (int)(user_pgrp);
                uint32_t pu = (uint32_t)pgrp;
                if (copy_to_user_safe(argp, &pu, sizeof(pu)) != 0) return ret_err(EFAULT);
                return 0;
            }
            if (req == TIOCSPGRP) {
                if (!argp) return ret_err(EFAULT);
                uint32_t p = 0;
                if (copy_from_user_raw(&p, argp, sizeof(p)) != 0) return ret_err(EFAULT);
                /* Be permissive: allow any pgrp for now to avoid shells exiting
                   due to strict job-control checks in this minimal tty model. */
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

            /* For the remaining tty-specific ioctls, require a real tty file. */
            if (!devfs_is_tty_file(f)) {
                return ret_err(ENOTTY);
            }
            if (req == TCSETS || req == TCSETSW || req == TCSETSF) {
                /* Apply minimal termios flags to the underlying tty: read c_lflag and store it */
                if (!argp) return ret_err(EFAULT);
                struct termios_k {
                    uint32_t c_iflag;
                    uint32_t c_oflag;
                    uint32_t c_cflag;
                    uint32_t c_lflag;
                    uint32_t c_line;
                    uint8_t  c_cc[8];
                    uint32_t c_ispeed;
                    uint32_t c_ospeed;
                } tio;
                size_t need = sizeof(uint32_t) * 4; /* at least up to c_lflag */
                if (copy_from_user_raw(&tio, argp, need) != 0) return ret_err(EFAULT);
                /* map fd to tty and set flags */
                if (!f) return ret_err(ENOTTY);
                /* ensure this file is a tty */
                if (!devfs_is_tty_file(f)) return ret_err(ENOTTY);
                /* Resolve file -> tty index safely (driver_private may be a marker) */
                int tty_idx = devfs_get_tty_index_from_file(f);
                if (tty_idx < 0) return ret_err(ENOTTY);
                struct devfs_tty *tty = devfs_get_tty_by_index(tty_idx);
                if (!tty) return ret_err(ENOTTY);
                tty->term_lflag = tio.c_lflag;
                return 0;
            }
            return ret_err(EINVAL);
        }
        case SYS_write: {
            int fd = (int)a1;
            const void *bufp = (const void*)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (f->type == FS_TYPE_PIPE && f->fs_private == (void *)1) {
                pipe_t *p = (pipe_t *)f->driver_private;
                if (!p) return ret_err(EBADF);
                size_t copied = 0;
                void *tmp = copy_from_user_safe(bufp, cnt, PIPE_BUF_SIZE, &copied);
                if (!tmp) return ret_err(EFAULT);
                ssize_t wr = pipe_write_bytes(p, tmp, copied, cur);
                kfree(tmp);
                return (wr >= 0) ? (uint64_t)wr : ret_err((int)-wr);
            }
            size_t copied = 0;
            void *tmp = copy_from_user_safe(bufp, cnt, 4096, &copied);
            if (!tmp) return ret_err(EFAULT);

            ssize_t wr = fs_write(f, tmp, copied, f->pos);
            if (wr > 0) f->pos += (size_t)wr;
            kfree(tmp);
            return (wr >= 0) ? (uint64_t)wr : ret_err(EINVAL);
        }
        case SYS_readv: {
            /* readv(fd, const struct iovec *iov, int iovcnt) - scatter read */
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
                void *base = (void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                if ((uintptr_t)base + len > (uintptr_t)MMIO_IDENTITY_LIMIT) return (total > 0) ? total : ret_err(EFAULT);
                size_t off = 0;
                while (off < len) {
                    size_t chunk = len - off;
                    if (chunk > 4096) chunk = 4096;
                    void *tmp = kmalloc(chunk);
                    if (!tmp) return (total > 0) ? total : ret_err(ENOMEM);
                    ssize_t rr = fs_read(f, tmp, chunk, f->pos);
                    if (rr <= 0) {
                        kfree(tmp);
                        return (total > 0) ? total : ret_err(EINVAL);
                    }
                    memcpy((char*)base + off, tmp, (size_t)rr);
                    kfree(tmp);
                    f->pos += (size_t)rr;
                    total += (uint64_t)rr;
                    off += (size_t)rr;
                    if ((size_t)rr < chunk) return total;
                }
            }
            return total;
        }
        case SYS_read: {
            int fd = (int)a1;
            void *bufp = (void*)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (f->type == FS_TYPE_PIPE && !f->fs_private) {
                pipe_t *p = (pipe_t *)f->driver_private;
                if (!p) return ret_err(EBADF);
                size_t to_read = cnt < (size_t)PIPE_BUF_SIZE ? cnt : (size_t)PIPE_BUF_SIZE;
                void *tmp = kmalloc(to_read);
                if (!tmp) return ret_err(ENOMEM);
                ssize_t rr = pipe_read_bytes(p, tmp, to_read, cur);
                if (rr > 0 && (uintptr_t)bufp + (size_t)rr <= (uintptr_t)MMIO_IDENTITY_LIMIT)
                    memcpy(bufp, tmp, (size_t)rr);
                kfree(tmp);
                return (rr >= 0) ? (uint64_t)rr : ret_err((int)-rr);
            }
            size_t to_read = cnt < 4096 ? cnt : 4096;
            void *tmp = kmalloc(to_read);
            if (!tmp) return ret_err(ENOMEM);
            ssize_t rr = fs_read(f, tmp, to_read, f->pos);

            if (rr > 0) {
                if (f->path && strcmp(f->path, "/etc/inittab") == 0) {
                    /* Normalize CRLF -> LF for busybox init parser. */
                    for (ssize_t i = 0; i < rr; i++) {
                        if (((char*)tmp)[i] == '\r') ((char*)tmp)[i] = '\n';
                    }
                    if (f->pos == 0) {
                        char preview[129];
                        size_t plen = (rr < 128) ? (size_t)rr : 128;
                        int has_nul = 0;
                        int has_respawn = 0;
                        int has_askfirst = 0;
                        int lines = 0;
                        for (size_t i = 0; i < plen; i++) {
                            char c = ((char*)tmp)[i];
                            if (c == '\0') has_nul = 1;
                            if (c < 32 || c > 126) c = '.';
                            preview[i] = c;
                        }
                        preview[plen] = '\0';
                        for (ssize_t i = 0; i < rr; i++) {
                            char c = ((char*)tmp)[i];
                            if (c == '\n') lines++;
                        }
                        if (rr >= 7) {
                            for (ssize_t i = 0; i + 7 <= rr; i++) {
                                if (memcmp((char*)tmp + i, "respawn", 7) == 0) { has_respawn = 1; break; }
                            }
                        }
                        if (rr >= 8) {
                            for (ssize_t i = 0; i + 8 <= rr; i++) {
                                if (memcmp((char*)tmp + i, "askfirst", 8) == 0) { has_askfirst = 1; break; }
                            }
                        }
                        {
                            char hex[3 * 32 + 1];
                            size_t hlen = (rr < 32) ? (size_t)rr : 32;
                            size_t w = 0;
                            for (size_t i = 0; i < hlen && w + 3 < sizeof(hex); i++) {
                                static const char *hx = "0123456789abcdef";
                                unsigned char b = (unsigned char)((char*)tmp)[i];
                                hex[w++] = hx[(b >> 4) & 0xF];
                                hex[w++] = hx[b & 0xF];
                                hex[w++] = ' ';
                            }
                            hex[w] = '\0';
                        }
                    }
                }
                if ((uintptr_t)bufp + (size_t)rr <= (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    memcpy(bufp, tmp, (size_t)rr);
                    f->pos += (size_t)rr;
                    kfree(tmp);
                    return (uint64_t)rr;
                }
                kfree(tmp);
                return ret_err(EFAULT);
            }
            if (f->path && strcmp(f->path, "/etc/inittab") == 0 && f->pos == 0) {
            }
            kfree(tmp);
            return (rr >= 0) ? (uint64_t)rr : ret_err(EINVAL);
        }
        case SYS_sendfile: {
            /* ssize_t sendfile(out_fd, in_fd, off_t *offset, size_t count) */
            int out_fd = (int)a1;
            int in_fd = (int)a2;
            off_t *offp = (off_t*)(uintptr_t)a3;
            size_t count = (size_t)a4;
            if (out_fd < 0 || out_fd >= THREAD_MAX_FD) {
                return ret_err(EBADF);
            }
            if (in_fd < 0 || in_fd >= THREAD_MAX_FD) {
                return ret_err(EBADF);
            }
            struct fs_file *fout = cur->fds[out_fd];
            struct fs_file *fin = cur->fds[in_fd];
            if (!fout || !fin) {
                return ret_err(EBADF);
            }
            /* Only support regular file -> write and read via fs_read/fs_write */
            size_t total = 0;
            size_t tocopy = count;
            size_t bufcap = tocopy < 4096 ? tocopy : 4096;
            if (bufcap == 0) return 0;
            uint8_t *tmp = (uint8_t*)kmalloc(bufcap);
            if (!tmp) {
                return ret_err(ENOMEM);
            }
            off_t use_pos = -1;
            if (offp) use_pos = *offp;
            while (tocopy > 0) {
                size_t chunk = tocopy < bufcap ? tocopy : bufcap;
                ssize_t rr;
                if (use_pos >= 0) {
                    rr = fs_read(fin, tmp, chunk, (size_t)use_pos);
                } else {
                    rr = fs_read(fin, tmp, chunk, fin->pos);
                }
                if (rr < 0) {
                    kfree(tmp);
                    return ret_err(EINVAL);
                }
                if (rr == 0) break;
                /* write to fout at its current position */
                ssize_t wr = fs_write(fout, tmp, (size_t)rr, fout->pos);
                if (wr <= 0) {
                    kfree(tmp);
                    return (total > 0) ? (uint64_t)total : ret_err(EINVAL);
                }
                if (use_pos >= 0) use_pos += (off_t)rr; else fin->pos += (size_t)rr;
                fout->pos += (size_t)wr;
                total += (size_t)wr;
                tocopy -= (size_t)rr;
                if ((size_t)rr < chunk) break;
            }
            kfree(tmp);
            if (offp) *offp = use_pos;
            return (uint64_t)total;
        }
        case SYS_poll: {
            /* int poll(struct pollfd *fds, nfds_t nfds, int timeout_ms) */
            const void *ufds = (const void*)(uintptr_t)a1;
            int nfds = (int)a2;
            int timeout = (int)a3; /* milliseconds, -1 means infinite */
            if (nfds < 0 || nfds > 1024) return ret_err(EINVAL);
            if (nfds == 0) {
                /* just wait for timeout */
                if (timeout <= 0) return 0;
                if (timeout < 0) {
                    /* block indefinitely but yield */
                    for (;;) { thread_sleep(10); }
                } else {
                    int waited = 0;
                    while (waited < timeout) { thread_sleep(10); waited += 10; }
                    return 0;
                }
            }
            size_t entry_size = 8; /* struct { int fd; short events; short revents; } */
            size_t bytes = (size_t)nfds * entry_size;
            void *kbuf = kmalloc(bytes);
            if (!kbuf) return ret_err(ENOMEM);
            if (copy_from_user_raw(kbuf, ufds, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }

            enum { POLLIN = 0x001, POLLERR = 0x008, POLLHUP = 0x010, POLLNVAL = 0x020 };

            auto_check:
            {
                int ready = 0;
                thread_t *curth = thread_get_current_user();
                if (!curth) curth = thread_current();
                for (int i = 0; i < nfds; i++) {
                    int fd = *(int*)((uint8_t*)kbuf + i * entry_size + 0);
                    short events = *(short*)((uint8_t*)kbuf + i * entry_size + 4);
                    short revents = 0;
                    if (fd < 0 || fd >= THREAD_MAX_FD) {
                        revents = POLLNVAL;
                    } else {
                        struct fs_file *f = curth ? curth->fds[fd] : NULL;
                        if (!f) {
                            revents = POLLNVAL;
                        } else {
                            /* tty */
                            if (devfs_is_tty_file(f)) {
                                int tidx = devfs_get_tty_index_from_file(f);
                                if (tidx < 0) tidx = devfs_get_active();
                                if ((events & POLLIN) && devfs_tty_available(tidx) > 0) revents |= POLLIN;
                            } else {
                                /* regular file: readable if pos < size */
                                if ((events & POLLIN)) {
                                    if (f->type != FS_TYPE_DIR) {
                                        if ((size_t)f->pos < (size_t)f->size) revents |= POLLIN;
                                    } else {
                                        /* directories: indicate readable */
                                        revents |= POLLIN;
                                    }
                                }
                            }
                        }
                    }
                    *(short*)((uint8_t*)kbuf + i * entry_size + 6) = revents; /* revents slot at offset 6? Actually struct layout fd(0), events(4), revents(6) */
                    if (revents) ready++;
                }
                if (ready > 0) {
                    if (copy_to_user_safe((void*)ufds, kbuf, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                    kfree(kbuf);
                    return (uint64_t)ready;
                }
            }

            if (timeout == 0) { kfree(kbuf); return 0; }
            int elapsed = 0;
            int step = 10; /* ms */
            thread_t *curth_poll = thread_get_current_user();
            if (!curth_poll) curth_poll = thread_current();
            int cur_tid = curth_poll ? (int)curth_poll->tid : -1;
            int tty_waiting[16];
            int n_tty_waiting;
            if (timeout < 0) {
                /* block indefinitely: add self as TTY waiter so we wake on keypress */
                for (;;) {
                    n_tty_waiting = 0;
                    if (cur_tid >= 0) {
                        for (int i = 0; i < nfds && n_tty_waiting < (int)(sizeof(tty_waiting)/sizeof(tty_waiting[0])); i++) {
                            int fd = *(int*)((uint8_t*)kbuf + i * entry_size + 0);
                            short events = *(short*)((uint8_t*)kbuf + i * entry_size + 4);
                            if (fd < 0 || fd >= THREAD_MAX_FD || !(events & POLLIN)) continue;
                            struct fs_file *f = curth_poll ? curth_poll->fds[fd] : NULL;
                            if (!f || !devfs_is_tty_file(f)) continue;
                            int tidx = devfs_get_tty_index_from_file(f);
                            if (tidx < 0) tidx = devfs_get_active();
                            if (devfs_tty_add_waiter(tidx, cur_tid) == 0) tty_waiting[n_tty_waiting++] = tidx;
                        }
                    }
                    if (n_tty_waiting > 0) {
                        thread_block(cur_tid);
                        thread_yield(); /* must yield so keyboard ISR can run and unblock */
                        for (int w = 0; w < n_tty_waiting; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                        goto auto_check;
                    }
                    thread_sleep(step);
                    goto auto_check;
                }
            } else {
                /* timeout > 0: use TTY waiters + block_with_timeout to wake on keypress
                   (Escape) immediately instead of sleeping full timeout */
                n_tty_waiting = 0;
                if (cur_tid >= 0) {
                    for (int i = 0; i < nfds && n_tty_waiting < (int)(sizeof(tty_waiting)/sizeof(tty_waiting[0])); i++) {
                        int fd = *(int*)((uint8_t*)kbuf + i * entry_size + 0);
                        short events = *(short*)((uint8_t*)kbuf + i * entry_size + 4);
                        if (fd < 0 || fd >= THREAD_MAX_FD || !(events & POLLIN)) continue;
                        struct fs_file *f = curth_poll ? curth_poll->fds[fd] : NULL;
                        if (!f || !devfs_is_tty_file(f)) continue;
                        int tidx = devfs_get_tty_index_from_file(f);
                        if (tidx < 0) tidx = devfs_get_active();
                        if (devfs_tty_add_waiter(tidx, cur_tid) == 0) tty_waiting[n_tty_waiting++] = tidx;
                    }
                }
                if (n_tty_waiting > 0) {
                    int remain = timeout - elapsed;
                    if (remain > 0) {
                        uint64_t t0 = pit_get_time_ms();
                        thread_block_with_timeout(cur_tid, (uint32_t)remain);
                        thread_yield(); /* must yield so keyboard ISR can run and unblock */
                        elapsed += (int)(pit_get_time_ms() - t0);
                        if (elapsed >= timeout) {
                            for (int w = 0; w < n_tty_waiting; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                            if (copy_to_user_safe((void*)ufds, kbuf, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                            kfree(kbuf);
                            return 0; /* timeout expired */
                        }
                    }
                    for (int w = 0; w < n_tty_waiting; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                    goto auto_check;
                }
                int step_ms = 2;
                while (elapsed < timeout) {
                    uint32_t sleep_ms = (uint32_t)(timeout - elapsed);
                    if (sleep_ms > (uint32_t)step_ms) sleep_ms = (uint32_t)step_ms;
                    thread_sleep(sleep_ms);
                    elapsed += (int)sleep_ms;
                    goto auto_check;
                }
            }
            /* timeout expired */
            if (copy_to_user_safe((void*)ufds, kbuf, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }
            kfree(kbuf);
            return 0;
        }
        case SYS_open: {
            const char *path_u = (const char*)(uintptr_t)a1;
            (void)a2;
            (void)a3;
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            if (strcmp(path, "/etc/inittab") == 0) {
                struct stat st;
                if (vfs_stat(path, &st) == 0 && st.st_size == 0) {
                    return ret_err(ENOENT);
                }
            }
            struct fs_file *f = fs_open(path);
            if (!f) {
                return ret_err(ENOENT);
            }
            int fd = thread_fd_alloc(f);
            if (fd < 0) { fs_file_free(f); return ret_err(EBADF); }
            return (uint64_t)(unsigned)fd;
        }
        case SYS_openat: {
            /* openat(dirfd, pathname, flags, mode) - dirfd=AT_FDCWD(-100) uses cwd */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            int flags = (int)a3;
            (void)a4;
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            int rc = resolve_user_path_at(cur, dirfd, path_u, path, sizeof(path));
            if (rc != 0) return ret_err(-rc);
            if (strcmp(path, "/etc/inittab") == 0) {
                struct stat st;
                if (vfs_stat(path, &st) == 0 && st.st_size == 0) {
                    return ret_err(ENOENT);
                }
            }
            struct fs_file *f = fs_open(path);
            if (!f) {
                const int O_CREAT_MASK = 0x40;
                if (flags & O_CREAT_MASK) {
                    f = fs_create_file(path);
                    if (!f) {
                        return ret_err(ENOENT);
                    }
                } else {
                    return ret_err(ENOENT);
                }
            }
            const int O_TRUNC_MASK = 0x200;
            if (f && (flags & O_TRUNC_MASK)) { f->size = 0; f->pos = 0; }
            int fd = thread_fd_alloc(f);
            if (fd < 0) { fs_file_free(f); return ret_err(EBADF); }
            return (uint64_t)(unsigned)fd;
        }
        case SYS_pipe:
        case SYS_pipe2: {
            /* pipe(int pipefd[2]); pipe2(int pipefd[2], int flags). flags (e.g. O_CLOEXEC) ignored for now. */
            void *pipefd_u = (void*)(uintptr_t)a1;
            (void)a2; /* flags for pipe2 */
            if (!pipefd_u || (uintptr_t)pipefd_u + 8 > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            pipe_t *p = (pipe_t *)kmalloc(sizeof(pipe_t));
            if (!p) return ret_err(ENOMEM);
            p->buf = (uint8_t *)kmalloc(PIPE_BUF_SIZE);
            if (!p->buf) { kfree(p); return ret_err(ENOMEM); }
            p->size = PIPE_BUF_SIZE;
            p->head = p->tail = 0;
            p->refcount = 2;
            p->reader_waiter_tid = p->writer_waiter_tid = -1;
            p->lock.lock = 0;

            struct fs_file *r = (struct fs_file *)kmalloc(sizeof(struct fs_file));
            struct fs_file *w = (struct fs_file *)kmalloc(sizeof(struct fs_file));
            if (!r || !w) { kfree(p->buf); kfree(p); if (r) kfree(r); if (w) kfree(w); return ret_err(ENOMEM); }
            memset(r, 0, sizeof(*r)); memset(w, 0, sizeof(*w));
            r->type = w->type = FS_TYPE_PIPE;
            r->driver_private = w->driver_private = p;
            r->fs_private = NULL; w->fs_private = (void *)1; /* 0=read end, 1=write end */
            r->refcount = w->refcount = 1;

            int fd0 = thread_fd_alloc(r);
            int fd1 = thread_fd_alloc(w);
            if (fd0 < 0 || fd1 < 0) {
                if (fd0 >= 0) thread_fd_close(fd0);
                if (fd1 >= 0) thread_fd_close(fd1);
                return ret_err(EMFILE);
            }
            int fds[2] = { fd0, fd1 };
            if (copy_to_user_safe(pipefd_u, fds, 8) != 0) {
                thread_fd_close(fd0);
                thread_fd_close(fd1);
                return ret_err(EFAULT);
            }
            return 0;
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
            if ((uintptr_t)st_u + STAT_COPY_SIZE > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            struct stat st;
            int rc_st = (num == SYS_lstat) ? vfs_lstat(path, &st) : vfs_stat(path, &st);
            if (rc_st != 0) return ret_err(ENOENT);
            /* build Linux x86_64 ABI struct stat and copy full layout so vi/busybox S_ISREG works */
            {
                struct compat_stat {
                    uint64_t st_dev;
                    uint64_t st_ino;
                    uint64_t st_nlink;
                    uint32_t st_mode;
                    uint32_t st_uid;
                    uint32_t st_gid;
                    uint32_t __pad0;
                    uint64_t st_rdev;
                    int64_t  st_size;
                    int64_t  st_blksize;
                    int64_t  st_blocks;
                    int64_t  st_atime_sec;
                    int64_t  st_atime_nsec;
                    int64_t  st_mtime_sec;
                    int64_t  st_mtime_nsec;
                    int64_t  st_ctime_sec;
                    int64_t  st_ctime_nsec;
                    int64_t  __unused[3];
                } cs;
                memset(&cs, 0, sizeof(cs));
                cs.st_dev = 0;
                cs.st_ino = (uint64_t)st.st_ino;
                cs.st_nlink = (uint64_t)st.st_nlink;
                cs.st_mode = (uint32_t)st.st_mode;
                cs.st_uid = (uint32_t)st.st_uid;
                cs.st_gid = (uint32_t)st.st_gid;
                cs.st_rdev = 0;
                cs.st_size = (int64_t)st.st_size;
                cs.st_blksize = 0;
                cs.st_blocks = 0;
                cs.st_atime_sec = (int64_t)st.st_atime;
                cs.st_mtime_sec = (int64_t)st.st_mtime;
                cs.st_ctime_sec = (int64_t)st.st_ctime;

                uint8_t tmp[256];
                if (sizeof(cs) > sizeof(tmp)) return ret_err(EINVAL);
                memcpy(tmp, &cs, sizeof(cs));
                memset(tmp + sizeof(cs), 0, STAT_COPY_SIZE - sizeof(cs));
                if (copy_to_user_safe(st_u, tmp, STAT_COPY_SIZE) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_fstat: {
            int fd = (int)a1;
            void *st_u = (void*)(uintptr_t)a2;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!st_u) return ret_err(EFAULT);
            if ((uintptr_t)st_u + STAT_COPY_SIZE > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            struct stat st;
            if (vfs_fstat(f, &st) != 0) return ret_err(EINVAL);
            /* build Linux x86_64 ABI struct stat so vi/busybox S_ISREG(st.st_mode) works */
            {
                struct compat_stat {
                    uint64_t st_dev;
                    uint64_t st_ino;
                    uint64_t st_nlink;
                    uint32_t st_mode;
                    uint32_t st_uid;
                    uint32_t st_gid;
                    uint32_t __pad0;
                    uint64_t st_rdev;
                    int64_t  st_size;
                    int64_t  st_blksize;
                    int64_t  st_blocks;
                    int64_t  st_atime_sec;
                    int64_t  st_atime_nsec;
                    int64_t  st_mtime_sec;
                    int64_t  st_mtime_nsec;
                    int64_t  st_ctime_sec;
                    int64_t  st_ctime_nsec;
                    int64_t  __unused[3];
                } cs;
                memset(&cs, 0, sizeof(cs));
                cs.st_dev = 0;
                cs.st_ino = (uint64_t)st.st_ino;
                cs.st_nlink = (uint64_t)st.st_nlink;
                cs.st_mode = (uint32_t)st.st_mode;
                cs.st_uid = (uint32_t)st.st_uid;
                cs.st_gid = (uint32_t)st.st_gid;
                cs.st_rdev = 0;
                cs.st_size = (int64_t)st.st_size;
                cs.st_blksize = 0;
                cs.st_blocks = 0;
                cs.st_atime_sec = (int64_t)st.st_atime;
                cs.st_mtime_sec = (int64_t)st.st_mtime;
                cs.st_ctime_sec = (int64_t)st.st_ctime;

                uint8_t tmp[256];
                if (sizeof(cs) > sizeof(tmp)) return ret_err(EINVAL);
                memcpy(tmp, &cs, sizeof(cs));
                memset(tmp + sizeof(cs), 0, STAT_COPY_SIZE - sizeof(cs));
                if (copy_to_user_safe(st_u, tmp, STAT_COPY_SIZE) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        case SYS_newfstatat: {
            /* newfstatat(dirfd, pathname, statbuf, flags) - use same Linux ABI layout as stat/fstat */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            void *st_u = (void*)(uintptr_t)a3;
            int flags = (int)a4;
            if (!st_u) return ret_err(EFAULT);
            if ((uintptr_t)st_u + STAT_COPY_SIZE > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            struct stat st;
            /* AT_EMPTY_PATH (0x1000): path ignored, stat the file given by dirfd (vi uses this) */
            if ((flags & 0x1000) != 0 && path_u && path_u[0] == '\0') {
                if (dirfd < 0 || dirfd >= THREAD_MAX_FD) return ret_err(EBADF);
                struct fs_file *f = cur->fds[dirfd];
                if (!f) return ret_err(EBADF);
                if (vfs_fstat(f, &st) != 0) return ret_err(EINVAL);
            } else {
                if (!path_u) return ret_err(EFAULT);
                if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                char path[256];
                resolve_user_path(cur, path_u, path, sizeof(path));
                if (vfs_stat(path, &st) != 0) return ret_err(ENOENT);
            }

            {
                struct compat_stat {
                    uint64_t st_dev;
                    uint64_t st_ino;
                    uint64_t st_nlink;
                    uint32_t st_mode;
                    uint32_t st_uid;
                    uint32_t st_gid;
                    uint32_t __pad0;
                    uint64_t st_rdev;
                    int64_t  st_size;
                    int64_t  st_blksize;
                    int64_t  st_blocks;
                    int64_t  st_atime_sec;
                    int64_t  st_atime_nsec;
                    int64_t  st_mtime_sec;
                    int64_t  st_mtime_nsec;
                    int64_t  st_ctime_sec;
                    int64_t  st_ctime_nsec;
                    int64_t  __unused[3];
                } cs;
                memset(&cs, 0, sizeof(cs));
                cs.st_dev = 0;
                cs.st_ino = (uint64_t)st.st_ino;
                cs.st_nlink = (uint64_t)st.st_nlink;
                cs.st_mode = (uint32_t)st.st_mode;
                cs.st_uid = (uint32_t)st.st_uid;
                cs.st_gid = (uint32_t)st.st_gid;
                cs.st_rdev = 0;
                cs.st_size = (int64_t)st.st_size;
                cs.st_blksize = 0;
                cs.st_blocks = 0;
                cs.st_atime_sec = (int64_t)st.st_atime;
                cs.st_mtime_sec = (int64_t)st.st_mtime;
                cs.st_ctime_sec = (int64_t)st.st_ctime;

                uint8_t tmp[256];
                if (sizeof(cs) > sizeof(tmp)) return ret_err(EINVAL);
                memcpy(tmp, &cs, sizeof(cs));
                memset(tmp + sizeof(cs), 0, STAT_COPY_SIZE - sizeof(cs));
                if (copy_to_user_safe(st_u, tmp, STAT_COPY_SIZE) != 0) return ret_err(EFAULT);
            }
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
        case SYS_getdents: /* historic getdents syscall (78) */
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

            /* Synthesize linux_dirent64 records into a kernel buffer, then copy to userspace.
               This avoids exposing malformed driver records directly to libc. */
            uint8_t kbuf[1024];
            ssize_t rr = fs_readdir_next(f, kbuf, sizeof(kbuf));
            if (rr <= 0) return 0;

            size_t in_off = 0;
            size_t out_off = 0;
            size_t out_cap = count < 4096 ? count : 4096;
            uint8_t *outbuf = (uint8_t*)kmalloc(out_cap);
            if (!outbuf) return ret_err(ENOMEM);

            while (in_off + 8 <= (size_t)rr) {
                struct ext2_dir_entry *de = (struct ext2_dir_entry*)(kbuf + in_off);
                if (de->rec_len < 8) break;
                size_t rem = (size_t)rr - in_off;
                size_t entry_rec = (size_t)de->rec_len;
                if (entry_rec == 0) break;
                /* Do not parse a partial entry at buffer end — would corrupt next name */
                if (entry_rec > rem) break;
                size_t max_name = (entry_rec > 8) ? entry_rec - 8 : 0;
                size_t name_len_use = (size_t)de->name_len;
                if (name_len_use > max_name) name_len_use = max_name;

                const char *nm_raw = (const char*)(kbuf + in_off + 8);
                char namebuf_local[256];
                size_t copy_n = (name_len_use < sizeof(namebuf_local)-1) ? name_len_use : (sizeof(namebuf_local)-1);
                if (copy_n > 0) memcpy(namebuf_local, nm_raw, copy_n);
                namebuf_local[copy_n] = '\0';
                for (size_t _i = 0; _i < copy_n; _i++) {
                    unsigned char ch = (unsigned char)namebuf_local[_i];
                    if (ch < 32 || ch > 126) namebuf_local[_i] = '?';
                }
                const char *nm = namebuf_local;
                size_t nlen = copy_n;

                /* Determine inode/type by stat'ing the full path if possible.
                   IMPORTANT: some virtual filesystems don't provide st_ino (0).
                   Userspace tools often treat d_ino==0 as "absent" and skip it,
                   which makes mountpoints like /dev invisible. */
                uint64_t out_ino = (uint64_t)de->inode;
                uint8_t out_type = (uint8_t)de->file_type;
                if (f->path && nlen > 0) {
                    char fullpath[512];
                    size_t plen = strlen(f->path);
                    if (plen + 1 + nlen + 1 < sizeof(fullpath)) {
                        memcpy(fullpath, f->path, plen);
                        if (plen == 0 || fullpath[plen-1] != '/') fullpath[plen++] = '/';
                        memcpy(fullpath + plen, nm, nlen);
                        fullpath[plen + nlen] = '\0';
                        struct fs_file *ef = fs_open(fullpath);
                        if (ef) {
                            struct stat st;
                            if (vfs_fstat(ef, &st) == 0) {
                                if ((uint64_t)st.st_ino != 0) {
                                    out_ino = (uint64_t)st.st_ino;
                                }
                                if ((st.st_mode & S_IFDIR) == S_IFDIR) out_type = EXT2_FT_DIR;
                                else out_type = EXT2_FT_REG_FILE;
                            }
                            fs_file_free(ef);
                        }
                    }
                }

                size_t reclen = 19 + nlen + 1;
                reclen = (reclen + 7) & ~7u;
                if (out_off + reclen > out_cap) break;

                uint8_t *outp = outbuf + out_off;
                *(uint64_t*)(outp + 0) = (uint64_t)out_ino;
                *(int64_t*)(outp + 8) = (int64_t)f->pos;
                *(uint16_t*)(outp + 16) = (uint16_t)reclen;
                outp[18] = (uint8_t)out_type;
                memcpy(outp + 19, nm, nlen);
                outp[19 + nlen] = '\0';
                for (size_t z = 19 + nlen + 1; z < reclen; z++) outp[z] = 0;

                out_off += reclen;
                in_off += entry_rec;
            }

            /* Rewind directory position so next getdents64 re-reads the partial entry */
            if (in_off < (size_t)rr)
                f->pos -= (rr - (off_t)in_off);

            /* copy synthesized data to user buffer per-record (safer) */
            size_t wrote = 0;
            size_t scan = 0;
            while (scan + 18 < out_off) {
                uint16_t recl = *(uint16_t*)(outbuf + scan + 16);
                if (recl == 0) break;
                if (scan + recl > out_off) break;
                /* bounds check user destination */
                if ((uintptr_t)dirp_u + wrote + recl > (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    break;
                }
                int rc = copy_to_user_safe((uint8_t*)dirp_u + wrote, outbuf + scan, recl);
                if (rc != 0) {
                    kfree(outbuf);
                    return ret_err(EFAULT);
                }
                wrote += recl;
                scan += recl;
            }
            kfree(outbuf);
            return (uint64_t)wrote;
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
        case SYS_mount: {
            /* mount(source, target, fstype, flags, data) */
            const char *src_u = (const char*)(uintptr_t)a1;
            const char *tgt_u = (const char*)(uintptr_t)a2;
            const char *type_u = (const char*)(uintptr_t)a3;
            (void)src_u; (void)a4; (void)a5;
            if (!tgt_u || !type_u) return ret_err(EINVAL);
            char *k_type = copy_user_cstr(type_u, 64);
            if (!k_type) return ret_err(EFAULT);
            char *k_tgt_raw = copy_user_cstr(tgt_u, 256);
            if (!k_tgt_raw) { kfree(k_type); return ret_err(EFAULT); }
            char target[256];
            resolve_user_path(cur, k_tgt_raw, target, sizeof(target));
            kfree(k_tgt_raw);
            if (target[0] == '\0') { kfree(k_type); return ret_err(EINVAL); }

            int rc = -1;
            if (strcmp(k_type, "proc") == 0 || strcmp(k_type, "procfs") == 0) {
                (void)procfs_register();
                ramfs_mkdir(target);
                rc = procfs_mount(target);
            } else if (strcmp(k_type, "sysfs") == 0) {
                if (sysfs_register() == 0) {
                    ramfs_mkdir(target);
                    rc = sysfs_mount(target);
                    if (rc == 0)
                        kernel_sysfs_populate_default();
                }
            } else if (strcmp(k_type, "devfs") == 0 || strcmp(k_type, "devtmpfs") == 0 || strcmp(k_type, "tmpfs") == 0) {
                /* tmpfs as mount type for /dev: treat same as devtmpfs (init inittab fallback) */
                ramfs_mkdir(target);
                rc = devfs_mount(target);
            } else {
                rc = -1;
            }

            kfree(k_type);
            return (rc == 0) ? 0 : ret_err(ENOSYS);
        }
        case SYS_brk: {
            /* Simple brk: bump within a safe range in identity-mapped low memory. */
            uintptr_t req = (uintptr_t)a1;
            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            uintptr_t *p_base = tcur ? &tcur->user_brk_base : &user_brk_base;
            uintptr_t *p_cur = tcur ? &tcur->user_brk_cur : &user_brk_cur;
            if (*p_base == 0) {
                /* initialize lazy: place brk after 8MiB by default */
                *p_base = 8u * 1024u * 1024u;
                *p_cur = *p_base;
            }
            if (req == 0) return (uint64_t)(*p_cur);
            req = align_up_u(req, 16);
            /* Don't allow brk to collide with reserved TLS/stack area. */
            uintptr_t top_limit = (uintptr_t)USER_TLS_BASE;
            if (tcur) {
                uintptr_t tls_base = user_tls_base_for_tid_local(tcur->tid);
                if (tls_base > 0x200000 && tls_base < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    top_limit = tls_base;
                }
            }
            if (req < *p_base || req >= top_limit) return (uint64_t)(*p_cur);
            /* mark and zero new range */
            if (req > *p_cur) {
                if (mark_user_identity_range_2m_sys((uint64_t)(*p_cur), (uint64_t)req) != 0) return ret_err(EFAULT);
                memset((void*)(*p_cur), 0, req - (*p_cur));
            }
            *p_cur = req;
            return (uint64_t)(*p_cur);
        }
        case SYS_mmap: {
            /* mmap(addr,len,prot,flags,fd,off) - anonymous and file-backed MAP_PRIVATE */
            (void)a1;
            size_t len = (size_t)a2;
            int prot = (int)a3;
            int flags = (int)a4;
            (void)prot;
            if (len == 0) return ret_err(EINVAL);
            len = (size_t)align_up_u((uintptr_t)len, 4096);
            enum { MAP_FIXED = 0x10, MAP_ANONYMOUS = 0x20, MAP_PRIVATE = 0x02,
                   MAP_STACK = 0x20000, MAP_GROWSDOWN = 0x0100, MAP_NORESERVE = 0x4000 };
            if (flags & MAP_FIXED) return ret_err(EINVAL);
            if (!(flags & MAP_PRIVATE)) return ret_err(ENOSYS);
            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            uintptr_t *p_mmap_next = tcur ? &tcur->user_mmap_next : &user_mmap_next;
            if (*p_mmap_next == 0) *p_mmap_next = 32u * 1024u * 1024u;
            uintptr_t addr = align_up_u(*p_mmap_next, 4096);
            uintptr_t top_limit = (uintptr_t)USER_TLS_BASE;
            if (tcur) {
                uintptr_t tls_base = user_tls_base_for_tid_local(tcur->tid);
                if (tls_base > 0x200000 && tls_base < (uintptr_t)MMIO_IDENTITY_LIMIT)
                    top_limit = tls_base;
            }
            if (addr + len >= top_limit) return ret_err(ENOMEM);
            if (mark_user_identity_range_2m_sys((uint64_t)addr, (uint64_t)(addr + len)) != 0) return ret_err(EFAULT);

            if (flags & MAP_ANONYMOUS) {
                flags &= ~(MAP_ANONYMOUS | MAP_PRIVATE | MAP_STACK | MAP_GROWSDOWN | MAP_NORESERVE);
                if (flags != 0) return ret_err(ENOSYS);
                memset((void*)addr, 0, len);
            } else {
                /* File-backed MAP_PRIVATE (e.g. BusyBox rpm mmaps .rpm file) */
                int fd = (int)(int64_t)a5;
                off_t file_off = (off_t)(int64_t)a6;
                if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
                struct fs_file *f = cur->fds[fd];
                if (!f) return ret_err(EBADF);
                if (f->type != FS_TYPE_REG) return ret_err(EBADF);
                memset((void*)addr, 0, len);
                size_t file_avail = 0;
                if ((size_t)file_off < f->size) file_avail = f->size - (size_t)file_off;
                size_t to_read = len < file_avail ? len : file_avail;
                if (to_read > 0) {
                    ssize_t nr = fs_read(f, (void*)addr, to_read, (size_t)file_off);
                    (void)nr; /* partial read leaves rest zeroed */
                }
            }
            *p_mmap_next = addr + len;
            return (uint64_t)addr;
        }
        case SYS_munmap:
            return 0;
        case SYS_madvise: {
            /* madvise(addr, length, advice) - syscall 28; glibc/apm uses MADV_DONTNEED etc.; stub success */
            (void)a1; (void)a2; (void)a3;
            return 0;
        }
        case SYS_mprotect:
            return 0;
        case SYS_exit: {
            (void)a1;
            qemu_debug_printf("sys_exit: pid=%llu name=%s called exit(code=%llu)\n",
                              (unsigned long long)(cur->tid ? cur->tid : 1),
                              cur && cur->name ? cur->name : "(null)",
                              (unsigned long long)a1);
            /* store exit status in wait format (status << 8) */
            if (cur) {
                int code = (int)a1;
                cur->exit_status = (code & 0xFF) << 8;
                if (cur->parent_tid >= 0) {
                    thread_t *pt = thread_get(cur->parent_tid);
                    if (pt) thread_set_pending_signal(pt, SIGCHLD);
                }
                /* wake vfork parent if any (restore parent's stack snapshot first) */
                if (cur->vfork_parent_tid >= 0) {
                    qemu_debug_printf("sys_exit: waking vfork parent %d from child %llu\n",
                        cur->vfork_parent_tid, (unsigned long long)(cur->tid ? cur->tid : 1));
                    vfork_restore_parent_memory(cur);
                    vfork_restore_parent_stack(cur);
                    thread_unblock(cur->vfork_parent_tid);
                    cur->vfork_parent_tid = -1;
                } else {
                    qemu_debug_printf("sys_exit: child %llu has no vfork_parent_tid (was %d)\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1), cur->vfork_parent_tid);
                }
                /* wake arbitrary waiter if present */
                if (cur->waiter_tid >= 0) {
                    thread_unblock(cur->waiter_tid);
                }
                /* glibc pthread_join waits on clear_child_tid; write 0 and FUTEX_WAKE so parent wakes */
                if (cur->clear_child_tid != 0 && cur->clear_child_tid < (uint64_t)MMIO_IDENTITY_LIMIT - 4) {
                    uint32_t zero = 0;
                    copy_to_user_safe((void*)(uintptr_t)cur->clear_child_tid, &zero, 4);
                    {
                        extern int futex_syscall(uintptr_t uaddr, int op, int val, const void *timeout, uintptr_t uaddr2, int val3);
                        futex_syscall((uintptr_t)cur->clear_child_tid, 1 | 128, 1, NULL, 0, 0);
                    }
                    cur->clear_child_tid = 0;
                }
            }
            /* mark terminated */
            if (cur) cur->state = THREAD_TERMINATED;
            /* IMPORTANT:
               If this is a scheduled kernel thread (tid!=0), do not drop into ring0 shell.
               Just yield so the parent/other threads continue running.
               Only the main kernel shell thread (tid==0) should "return to osh" on exit. */
            thread_t *kcur = thread_current();
            if (kcur && kcur->tid != 0) {
                thread_yield();
                /* If yield returns, it means no context switch was possible.
                   Stay in an interruptible halt loop (idle thread should normally prevent this). */
                for (;;) asm volatile("sti; hlt" ::: "memory");
            }
            syscall_exit_to_shell_flag = 1;
            return 0;
        }
        case SYS_exit_group: {
            (void)a1;
            qemu_debug_printf("sys_exit_group: pid=%llu name=%s called exit_group(code=%llu)\n",
                              (unsigned long long)(cur->tid ? cur->tid : 1),
                              cur && cur->name ? cur->name : "(null)",
                              (unsigned long long)a1);
            if (cur) {
                int code = (int)a1;
                cur->exit_status = (code & 0xFF) << 8;
                if (cur->parent_tid >= 0) {
                    thread_t *pt = thread_get(cur->parent_tid);
                    if (pt) thread_set_pending_signal(pt, SIGCHLD);
                }
                if (cur->vfork_parent_tid >= 0) {
                    qemu_debug_printf("sys_exit_group: waking vfork parent %d from child %llu\n",
                        cur->vfork_parent_tid, (unsigned long long)(cur->tid ? cur->tid : 1));
                    vfork_restore_parent_memory(cur);
                    vfork_restore_parent_stack(cur);
                    thread_unblock(cur->vfork_parent_tid);
                    cur->vfork_parent_tid = -1;
                } else {
                    qemu_debug_printf("sys_exit_group: child %llu has no vfork_parent_tid (was %d)\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1), cur->vfork_parent_tid);
                }
                if (cur->waiter_tid >= 0) thread_unblock(cur->waiter_tid);
                if (cur->clear_child_tid != 0 && cur->clear_child_tid < (uint64_t)MMIO_IDENTITY_LIMIT - 4) {
                    uint32_t zero = 0;
                    copy_to_user_safe((void*)(uintptr_t)cur->clear_child_tid, &zero, 4);
                    { extern int futex_syscall(uintptr_t uaddr, int op, int val, const void *timeout, uintptr_t uaddr2, int val3);
                      futex_syscall((uintptr_t)cur->clear_child_tid, 1 | 128, 1, NULL, 0, 0); }
                    cur->clear_child_tid = 0;
                }
                cur->state = THREAD_TERMINATED;
            }
            thread_t *kcur = thread_current();
            if (kcur && kcur->tid != 0) {
                thread_yield();
                for (;;) asm volatile("sti; hlt" ::: "memory");
            }
            syscall_exit_to_shell_flag = 1;
            return 0;
        }
        default:
            /* Log unknown syscall with full args for easier diagnosis.
               If it's syscall 271, try to print a possible pathname from a1 to help identify it. */
            qemu_debug_printf("UNKNOWN SYSCALL: %u num=%u args=%llu,%llu,%llu,%llu,%llu,%llu\n",
                    (unsigned long long)(cur->tid ? cur->tid : 1),
                    (unsigned long long)num,
                    (unsigned long long)a1, (unsigned long long)a2, (unsigned long long)a3,
                    (unsigned long long)a4, (unsigned long long)a5, (unsigned long long)a6);
            if (num == 271) {
                /* attempt to copy a NUL-terminated string from userspace pointer a1 */
                const char *up = (const char*)(uintptr_t)a1;
                if (up && (uintptr_t)up < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    size_t copied = 0;
                    void *tmp = copy_from_user_safe(up, 256, 256, &copied);
                    if (tmp && copied > 0) {
                        ((char*)tmp)[copied - 1] = '\\0';
                        qemu_debug_printf("UNKNOWN SYSCALL 271: path='%s' (copied %u bytes)\n", (char*)tmp, (unsigned)copied);
                        kfree(tmp);
                    } else {
                        qemu_debug_printf("UNKNOWN SYSCALL 271: failed to copy path at %p\n", (void*)up);
                    }
                } else {
                    qemu_debug_printf("UNKNOWN SYSCALL 271: invalid user pointer %p\n", (void*)(uintptr_t)a1);
                }
            }
            (void)a4; (void)a5; (void)a6;
            return ret_err(ENOSYS);
    }
}

void isr_syscall(cpu_registers_t* regs) {
    if (!regs) return;
    /* Record user rip/rsp for int0x80 path so fork/vfork can find return site. */
    syscall_user_return_rip = regs->rip;
    syscall_user_rsp_saved = regs->rsp;
    /* Debug: record that we saw a syscall from user with these values */
    qemu_debug_printf("DBG: isr_syscall: recorded user RIP=0x%llx RSP=0x%llx\n", (unsigned long long)syscall_user_return_rip, (unsigned long long)syscall_user_rsp_saved);
    if (syscall_user_return_rip == 0) {
        qemu_debug_printf("DBG: isr_syscall: return RIP==0, dumping kernel syscall stack for diagnosis\n");
        debug_dump_kernel_syscall_stack();
    }
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

    klogprintf("syscall: int0x80 handler registered; SYSCALL enabled\n");
}


