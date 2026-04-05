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
#include <fat32.h>
#include <e1000.h>
#include <usb.h>
#include <usbdevfs.h>
#include <net_tcp.h>
#include <dns.h>
#include <mm.h>
#include <smp.h>
#include <loadavg.h>
#include <console.h>
#include <ramfs.h>
#include <dhcp.h>
#include <debug.h>
#include <klog.h>
#include <fbdev.h>
#include <stdio.h>

/* Linux x86_64 struct stat size; ensures st_mode at correct offset for S_ISREG etc. */
#define STAT_COPY_SIZE 144
#define NET_FRAME_BUF 2048

/* Verbose DNS tracing for threads named "wget" — off by default: heavy klog+fs_write
 * and per-byte kprintf were implicated in heap stress / reentrancy under VMware. */
#ifndef AXON_WGET_DNS_TRACE
#define AXON_WGET_DNS_TRACE 0
#endif

extern void kprintf(const char *fmt, ...);

/* Helper exported from core/elf.c */
extern uint64_t virt_to_phys(uint64_t va);

/* Saved user RSP for syscall_entry64 (single-core, single-syscall-in-flight). */
uint64_t syscall_user_rsp_saved = 0;
/* Kernel syscall stack top (RSP0) installed by tss_set_rsp0(). Used by syscall_entry64. */
uint64_t syscall_kernel_rsp0 = 0;
/* Saved user RIP for SYSCALL path (RCX at syscall entry). Used by fork/vfork helpers. */
uint64_t syscall_user_return_rip = 0;
/* Last userspace-visible return value from syscall_do before signal delivery. */
uint64_t syscall_user_return_rax = 0;
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

static inline int user_range_ok(const void *uaddr, size_t nbytes);
static inline int user_recv_range_ok(const void *uaddr, size_t nbytes);
static int copy_from_user_raw(void *kdst, const void *usrc, size_t n);
static size_t user_strnlen_bounded(const char *s, size_t max);

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

static thread_t *uaccess_thread(void) {
    thread_t *t = thread_get_current_user();
    if (!t) t = thread_current();
    return t;
}

static void uaccess_clear(thread_t *t) {
    if (!t) return;
    t->uaccess_begin = 0;
    t->uaccess_end = 0;
    t->uaccess_resume_rip = 0;
    t->uaccess_active = 0;
}

static int uaccess_arm(thread_t *t, const void *uptr, size_t n, void *resume_rip, int recv_range) {
    if (!t || !resume_rip) return -1;
    if (recv_range) {
        if (!user_recv_range_ok(uptr, n)) return -1;
    } else {
        if (!user_range_ok(uptr, n)) return -1;
    }
    t->uaccess_begin = (uintptr_t)uptr;
    t->uaccess_end = (uintptr_t)uptr + n;
    t->uaccess_resume_rip = (uint64_t)(uintptr_t)resume_rip;
    t->uaccess_active = 1;
    asm volatile("" ::: "memory");
    return 0;
}

int syscall_try_handle_uaccess_fault(uint64_t fault_addr, uint64_t *resume_rip_out) {
    thread_t *t = uaccess_thread();
    uintptr_t fault = (uintptr_t)fault_addr;
    if (!t || !t->uaccess_active) return 0;
    if (fault < t->uaccess_begin || fault >= t->uaccess_end) return 0;
    if (resume_rip_out) *resume_rip_out = t->uaccess_resume_rip;
    uaccess_clear(t);
    return 1;
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
    /* Restore complete; free snapshot to avoid unbounded memory leak across vfork-heavy workloads
       (busybox shell utilities like wget/adduser/addgroup). */
    kfree(child->vfork_parent_stack_backup);
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

/* exit_group must tear down clone3 peers: they share pgid and may sit in devfs tty waiters.
 * waiters[] is only 8 slots; excess blocks the shell's read(stdin) after wget returns. */
static void exit_group_reap_peer_threads(thread_t *cur) {
    if (!cur || cur->ring != 3) return;
    /* vfork child before execve still has parent's pgid; reaping would kill the shell. */
    if (cur->parent_tid >= 0) {
        thread_t *pt = thread_get(cur->parent_tid);
        if (pt && pt->ring == 3 && (int)cur->pgid == (int)pt->pgid)
            return;
    }
    int group_pgid = cur->pgid;
    int nt = thread_get_count();
    for (int i = 0; i < nt; i++) {
        thread_t *t = thread_get_by_index(i);
        if (!t || t == cur) continue;
        if (t->ring != 3) continue;
        if (t->state == THREAD_TERMINATED) continue;
        if ((int)t->pgid != group_pgid) continue;
        devfs_tty_remove_waiter_from_all_ttys((int)(t->tid ? t->tid : 1));
        if (t->waiter_tid >= 0) {
            int w = t->waiter_tid;
            t->waiter_tid = -1;
            thread_unblock(w);
        }
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            if (t->fds[fd]) {
                struct fs_file *f = t->fds[fd];
                t->fds[fd] = NULL;
                fs_file_free(f);
            }
        }
        if (t->mm && t->mm != mm_kernel()) {
            mm_release(t->mm);
            t->mm = mm_kernel();
        }
        t->exit_status = 9; /* WTERMSIG: SIGKILL */
        t->state = THREAD_TERMINATED;
    }
}

enum {
    MSR_EFER  = 0xC0000080u,
    MSR_STAR  = 0xC0000081u,
    MSR_LSTAR = 0xC0000082u,
    MSR_FMASK = 0xC0000084u,
    MSR_FS_BASE = 0xC0000100u,
};

/* Helper: copy up to `max` bytes from user pointer `uptr` into newly allocated buffer. */
static void *copy_from_user_safe(const void *uptr, size_t count, size_t max, size_t *out_copied) {
    if (!uptr || count == 0) { if (out_copied) *out_copied = 0; return NULL; }
    size_t to_copy = count < max ? count : max;
    void *buf = kmalloc(to_copy);
    if (!buf) { if (out_copied) *out_copied = 0; return NULL; }
    if (copy_from_user_raw(buf, uptr, to_copy) != 0) {
        kfree(buf);
        if (out_copied) *out_copied = 0;
        return NULL;
    }
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
#define EAFNOSUPPORT 97
#define EPROTONOSUPPORT 93
#define ESOCKTNOSUPPORT 94
#define EOPNOTSUPP 95
#define EDESTADDRREQ 89
#define ENETDOWN 100
#define ENETUNREACH 101
#define ENOTCONN 107
#define ENODEV   19
#define ETIMEDOUT 110
#define ECONNREFUSED 111

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
            /* Copy ring -> kernel buffer entirely under lock: another thread must not move
               tail/head while we read, or memcpy runs on stale indices and corrupts data. */
            size_t first = (tail + n <= p->size) ? n : (p->size - tail);
            memcpy(buf, p->buf + tail, first);
            if (first < n) memcpy((char*)buf + first, p->buf, n - first);
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
            size_t to_end = p->size - head;
            if (n <= to_end) {
                memcpy(p->buf + head, src + written, n);
            } else {
                memcpy(p->buf + head, src + written, to_end);
                memcpy(p->buf, src + written + to_end, n - to_end);
            }
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

/* ---------- Minimal IPv4/ICMP raw socket backend (for ping) ---------- */
#define SYSCALL_FTYPE_SOCKET  0x534F434Bu

#define AF_INET_LOCAL         2
#define AF_UNSPEC             0   /* treat as AF_INET for getaddrinfo fallback */
#define AF_INET6              10  /* Linux value; we stub to AF_INET */
#define AF_NETLINK_LOCAL      16
#define SOCK_STREAM_LOCAL     1
#define SOCK_DGRAM_LOCAL      2
#define SOCK_RAW_LOCAL        3
/* Linux: SOCK_NONBLOCK == O_NONBLOCK (glibc sets this in socket type / fcntl). */
#define O_NONBLOCK_LINUX      0x800
/* F_GETFL must include accmode; 0 breaks glibc fdopen/wget (bogus "out of memory"). */
#define O_RDWR_LINUX          2
#define IPPROTO_ICMP_LOCAL    1
#define IPPROTO_TCP_LOCAL     6
#define IPPROTO_UDP_LOCAL     17
#define NETLINK_ROUTE_LOCAL   0

#define ETH_TYPE_IPV4         0x0800
#define ETH_TYPE_ARP          0x0806


typedef struct __attribute__((packed)) {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
} eth_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t src;
    uint32_t dst;
} ipv4_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t csum;
} udp_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
} arp_hdr_t;

typedef struct {
    int sock_domain;
    /* socket(AF_UNIX) is created as IPv4 internally; nscd uses connect(sockaddr_un). */
    int unix_domain_stub;
    int type_base;
    int protocol;
    int connected;
    uint32_t peer_ip_be;
    uint16_t peer_port;
    uint16_t local_port;
    int rx_has_pending;
    size_t rx_pending_len;
    size_t rx_pending_off;
    uint32_t rx_pending_src_ip_be;
    uint16_t rx_pending_src_port;
    uint8_t rx_pending[2048];
    uint32_t last_dst_ip_be;
    uint16_t last_echo_id;
    uint16_t last_echo_seq;
    uint16_t next_echo_seq;
    int last_req_ts_fmt;
    size_t last_req_len;
    uint8_t last_req[2048];
    uint32_t nl_pid;
    uint32_t nl_groups;
    uint32_t nl_peer_pid;
    uint8_t nl_rx[4096];
    size_t nl_rx_len;
    size_t nl_rx_off;
    /* glibc tries TCP :53 first; many routers RST -> ECONNREFUSED. Fake connect and use UDP for DNS. */
    int dns_tcp_udp_bridge;
    int nonblock; /* O_NONBLOCK: recv must not fake-EAGAIN after an internal short timeout */
    net_tcp_conn_t tcp;
} ksock_net_t;

static inline size_t ksock_rx_pending_cap(void) {
    return (size_t)sizeof(((ksock_net_t *)0)->rx_pending);
}

/* Drop inconsistent pending state (e.g. off > len) before using rx_pending. */
static inline void ksock_rx_pending_normalize(ksock_net_t *s) {
    if (!s || !s->rx_has_pending) return;
    size_t cap = ksock_rx_pending_cap();
    if (s->rx_pending_len > cap || s->rx_pending_off > s->rx_pending_len) {
        s->rx_has_pending = 0;
        s->rx_pending_len = 0;
        s->rx_pending_off = 0;
    }
}

static inline size_t ksock_rx_pending_avail(const ksock_net_t *s) {
    if (!s || !s->rx_has_pending) return 0;
    if (s->rx_pending_off > s->rx_pending_len) return 0;
    return s->rx_pending_len - s->rx_pending_off;
}

static inline void ksock_rx_pending_install(ksock_net_t *s, int rn) {
    if (!s || rn <= 0) return;
    size_t n = (size_t)rn;
    size_t cap = ksock_rx_pending_cap();
    if (n > cap) n = cap;
    s->rx_has_pending = 1;
    s->rx_pending_len = n;
    s->rx_pending_off = 0;
}

typedef struct {
    int inited;
    int ready;
    uint8_t mac[6];
    uint32_t ip_be;
    uint32_t mask_be;
    uint32_t gw_be;
    uint32_t dns_be;
    uint16_t ip_id;
    uint8_t gw_mac[6];
    int gw_mac_valid;
} net_state_t;

static net_state_t g_net;
static net_state_t g_net_shadow;
static int g_net_shadow_valid = 0;
static uint32_t g_net_cfg_magic = 0x4E455443u; /* "NETC" */
static uint8_t g_net_cfg_mac[6];
static uint32_t g_net_cfg_ip_be = 0;
static uint32_t g_net_cfg_mask_be = 0;
static uint32_t g_net_cfg_gw_be = 0;
static uint32_t g_net_cfg_dns_be = 0;

/* ---------- RX pump: answer ARP/ICMP and queue everything else ---------- */
static inline uint16_t be16(uint16_t v);
static inline uint32_t be32(uint32_t v);
static uint16_t ip_checksum16(const void *data, size_t len);
static void ip_be_to_bytes(uint32_t ip_be, uint8_t out[4]);
static int net_send_eth_ipv4(const uint8_t dst_mac[6], uint32_t dst_ip_be, uint8_t proto, const void *l4, size_t l4_len);

#define NET_RXQ_SLOTS  32
#define NET_RXQ_BUF    2048
static uint8_t g_net_rxq[NET_RXQ_SLOTS][NET_RXQ_BUF];
static uint16_t g_net_rxq_len[NET_RXQ_SLOTS];
static uint32_t g_net_rxq_head = 0, g_net_rxq_tail = 0, g_net_rxq_count = 0;
static spinlock_t g_net_rxq_lock = { 0 };
static int g_net_rx_thread_started = 0;

static int net_rxq_push(const uint8_t *frame, size_t n) {
    if (!frame || n == 0) return -1;
    if (n > NET_RXQ_BUF) n = NET_RXQ_BUF;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    if (g_net_rxq_count >= NET_RXQ_SLOTS) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return -2;
    }
    memcpy(g_net_rxq[g_net_rxq_tail], frame, n);
    g_net_rxq_len[g_net_rxq_tail] = (uint16_t)n;
    g_net_rxq_tail = (g_net_rxq_tail + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count++;
    release_irqrestore(&g_net_rxq_lock, irqf);
    return 0;
}

static int net_rxq_pop(void *out, size_t cap) {
    if (!out || cap == 0) return -1;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    if (g_net_rxq_count == 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint32_t idx = g_net_rxq_head;
    uint16_t n = g_net_rxq_len[idx];
    g_net_rxq_len[idx] = 0;
    g_net_rxq_head = (idx + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count--;
    release_irqrestore(&g_net_rxq_lock, irqf);
    size_t copy_len = (n > cap) ? cap : (size_t)n;
    memcpy(out, g_net_rxq[idx], copy_len);
    return (int)copy_len;
}

static int net_reply_arp_if_needed(const uint8_t *frame, size_t n) {
    if (!g_net.ready || !frame || n < sizeof(eth_hdr_t) + sizeof(arp_hdr_t)) return 0;
    static int arp_dbg_left = 3;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_ARP) return 0;
    const arp_hdr_t *arp = (const arp_hdr_t *)(frame + sizeof(eth_hdr_t));
    if (be16(arp->oper) != 1) return 0; /* request */
    if (be16(arp->htype) != 1 || be16(arp->ptype) != ETH_TYPE_IPV4 || arp->hlen != 6 || arp->plen != 4) return 0;
    uint32_t tpa = ((uint32_t)arp->tpa[0] << 24) | ((uint32_t)arp->tpa[1] << 16) | ((uint32_t)arp->tpa[2] << 8) | arp->tpa[3];
    if (tpa != g_net.ip_be) return 0;
    if (arp_dbg_left-- > 0) {
        uint32_t spa = ((uint32_t)arp->spa[0] << 24) | ((uint32_t)arp->spa[1] << 16) | ((uint32_t)arp->spa[2] << 8) | arp->spa[3];
        klogprintf("net: ARP who-has %u.%u.%u.%u tell %u.%u.%u.%u (from %02x:%02x:%02x:%02x:%02x:%02x)\n",
                   (unsigned)((tpa >> 24) & 0xFF), (unsigned)((tpa >> 16) & 0xFF), (unsigned)((tpa >> 8) & 0xFF), (unsigned)(tpa & 0xFF),
                   (unsigned)((spa >> 24) & 0xFF), (unsigned)((spa >> 16) & 0xFF), (unsigned)((spa >> 8) & 0xFF), (unsigned)(spa & 0xFF),
                   eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
    }

    uint8_t reply[64];
    memset(reply, 0, sizeof(reply));
    eth_hdr_t *reth = (eth_hdr_t *)reply;
    memcpy(reth->dst, eth->src, 6);
    memcpy(reth->src, g_net.mac, 6);
    reth->ethertype = be16(ETH_TYPE_ARP);
    arp_hdr_t *rarp = (arp_hdr_t *)(reply + sizeof(eth_hdr_t));
    rarp->htype = be16(1);
    rarp->ptype = be16(ETH_TYPE_IPV4);
    rarp->hlen = 6;
    rarp->plen = 4;
    rarp->oper = be16(2); /* reply */
    memcpy(rarp->sha, g_net.mac, 6);
    ip_be_to_bytes(g_net.ip_be, rarp->spa);
    memcpy(rarp->tha, arp->sha, 6);
    memcpy(rarp->tpa, arp->spa, 4);
    (void)e1000_send_frame(reply, sizeof(reply));
    if (arp_dbg_left >= 0) klogprintf("net: ARP reply sent\n");
    return 1;
}

static int net_reply_icmp_echo_if_needed(const uint8_t *frame, size_t n) {
    if (!g_net.ready || !frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + 8) return 0;
    static int icmp_dbg_left = 3;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t)) return 0;
    if (ip->proto != IPPROTO_ICMP_LOCAL) return 0;
    uint32_t dst_ip_be = be32(ip->dst);
    if (dst_ip_be != g_net.ip_be) return 0;
    uint16_t tot = be16(ip->total_len);
    if (tot < ihl + 8) return 0;
    if (sizeof(eth_hdr_t) + (size_t)tot > n) return 0;
    const uint8_t *icmp = frame + sizeof(eth_hdr_t) + ihl;
    if (icmp[0] != 8 || icmp[1] != 0) return 0; /* echo request */
    size_t icmp_len = (size_t)tot - ihl;
    if (icmp_dbg_left-- > 0) {
        uint32_t src_ip_be = be32(ip->src);
        klogprintf("net: ICMP echo request from %u.%u.%u.%u len=%u\n",
                   (unsigned)((src_ip_be >> 24) & 0xFF), (unsigned)((src_ip_be >> 16) & 0xFF),
                   (unsigned)((src_ip_be >> 8) & 0xFF), (unsigned)(src_ip_be & 0xFF),
                   (unsigned)icmp_len);
    }

    uint8_t *reply = (uint8_t *)kmalloc(icmp_len);
    if (!reply) return 1; /* consume to avoid loops; out of memory */
    memcpy(reply, icmp, icmp_len);
    reply[0] = 0; /* echo reply */
    reply[2] = 0; reply[3] = 0;
    uint16_t csum = ip_checksum16(reply, icmp_len);
    reply[2] = (uint8_t)(csum >> 8);
    reply[3] = (uint8_t)(csum);
    uint32_t src_ip_be = be32(ip->src);
    (void)net_send_eth_ipv4(eth->src, src_ip_be, IPPROTO_ICMP_LOCAL, reply, icmp_len);
    kfree(reply);
    if (icmp_dbg_left >= 0) klogprintf("net: ICMP echo reply sent\n");
    return 1;
}

static int net_process_incoming_or_queue(const uint8_t *frame, size_t n) {
    if (!frame || n == 0) return 0;
    if (net_reply_arp_if_needed(frame, n)) return 1;
    if (net_reply_icmp_echo_if_needed(frame, n)) return 1;
    (void)net_rxq_push(frame, n);
    return 1;
}

static int net_recv_frame_any(void *buf, size_t cap) {
    if (!buf || cap == 0) return -1;
    int qn = net_rxq_pop(buf, cap);
    if (qn > 0) return qn;
    /* Pull from NIC; auto-respond to ARP/ICMP requests and keep looking. */
    for (int i = 0; i < 16; i++) {
        e1000_poll();
        int n = e1000_recv_frame(buf, cap);
        if (n <= 0) return n;
        if (net_reply_arp_if_needed((const uint8_t *)buf, (size_t)n)) continue;
        if (net_reply_icmp_echo_if_needed((const uint8_t *)buf, (size_t)n)) continue;
        return n;
    }
    return 0;
}

static void net_rx_pump_thread(void) {
    uint8_t buf[NET_RXQ_BUF];
    for (;;) {
        if (!g_net.ready) { thread_sleep(50); continue; }
        /* Drain a small budget to keep latency low but avoid starving other work. */
        for (int i = 0; i < 32; i++) {
            e1000_poll();
            int n = e1000_recv_frame(buf, sizeof(buf));
            if (n <= 0) break;
            (void)net_process_incoming_or_queue(buf, (size_t)n);
        }
        thread_sleep(1);
    }
}

static inline uint16_t be16(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static inline uint32_t be32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) | ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

/* Linux-style demux: scan the software RX ring for a matching UDP datagram; do not drop non-matches
 * that belong to TCP or another UDP port (head-of-line blocking was losing DNS replies). */
static int net_udp_match_sock_frame(const uint8_t *frame, size_t n, ksock_net_t *s) {
    if (!s || !frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ip->proto != IPPROTO_UDP_LOCAL || ihl < sizeof(ipv4_hdr_t)) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t)) return 0;
    const udp_hdr_t *uh = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    if (be16(uh->dst_port) != s->local_port) return 0;
    uint32_t src_ip = be32(ip->src);
    uint16_t sport = be16(uh->src_port);
    if (s->connected) {
        int ok = (src_ip == s->peer_ip_be && sport == s->peer_port);
        if (!ok && s->peer_port == 53u && sport == 53u &&
            ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
             (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge)))
            ok = 1;
        if (!ok) return 0;
    }
    uint16_t ulen = be16(uh->len);
    if (ulen < sizeof(udp_hdr_t)) return 0;
    return 1;
}

static int net_udp_match_raw_frame(const uint8_t *frame, size_t n, uint16_t local_port,
                                   uint32_t peer_ip_be, uint16_t peer_port) {
    if (!frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ip->proto != IPPROTO_UDP_LOCAL || ihl < sizeof(ipv4_hdr_t)) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t)) return 0;
    const udp_hdr_t *uh = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    if (be16(uh->dst_port) != local_port) return 0;
    uint32_t sip = be32(ip->src);
    uint16_t sp = be16(uh->src_port);
    int ok = (sip == peer_ip_be && sp == peer_port);
    if (!ok && peer_port == 53u && sp == 53u) ok = 1;
    return ok ? 1 : 0;
}

static int net_udp_copy_payload_from_frame(const uint8_t *frame, size_t n, uint8_t *out, size_t out_cap,
                                          uint32_t *out_src_ip_be, uint16_t *out_src_port) {
    if (!frame || !out || out_cap == 0) return 0;
    if (n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t) || ihl > 60) return 0;
    if (ip->proto != IPPROTO_UDP_LOCAL) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t)) return 0;
    const udp_hdr_t *uh = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    uint16_t sport = be16(uh->src_port);
    uint32_t src_ip = be32(ip->src);
    uint16_t ulen = be16(uh->len);
    if (ulen < sizeof(udp_hdr_t)) return 0;
    size_t payload_len = (size_t)ulen - sizeof(udp_hdr_t);
    size_t have = n - (sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t));
    if (payload_len > have) payload_len = have;
    size_t copy_len = (payload_len > out_cap) ? out_cap : payload_len;
    if (copy_len > 0) memcpy(out, (const uint8_t *)uh + sizeof(udp_hdr_t), copy_len);
    if (out_src_ip_be) *out_src_ip_be = src_ip;
    if (out_src_port) *out_src_port = sport;
    return (int)copy_len;
}

/* UDP payload length in frame (for FIONREAD); 0 if not a valid IPv4 UDP datagram. */
static int net_udp_payload_len_from_frame(const uint8_t *frame, size_t n) {
    if (!frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + sizeof(udp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t) || ihl > 60) return 0;
    if (ip->proto != IPPROTO_UDP_LOCAL) return 0;
    if (n < sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t)) return 0;
    const udp_hdr_t *uh = (const udp_hdr_t *)(frame + sizeof(eth_hdr_t) + ihl);
    uint16_t ulen = be16(uh->len);
    if (ulen < sizeof(udp_hdr_t)) return 0;
    size_t payload_len = (size_t)ulen - sizeof(udp_hdr_t);
    size_t have = n - (sizeof(eth_hdr_t) + ihl + sizeof(udp_hdr_t));
    if (payload_len > have) payload_len = have;
    if (payload_len > 0x7fffffffu) return 0;
    return (int)payload_len;
}

/* Bytes available for recv without dequeuing (head-of-line: first matching UDP in RX queue). */
static int net_rxq_peek_udp_payload_for_sock(ksock_net_t *s) {
    if (!s || s->local_port == 0) return 0;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    uint32_t cnt = g_net_rxq_count;
    uint32_t head0 = g_net_rxq_head;
    int plen = 0;
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t idx = (head0 + i) % NET_RXQ_SLOTS;
        uint16_t fn = g_net_rxq_len[idx];
        if (fn == 0) continue;
        if (net_udp_match_sock_frame(g_net_rxq[idx], fn, s)) {
            plen = net_udp_payload_len_from_frame(g_net_rxq[idx], fn);
            break;
        }
    }
    release_irqrestore(&g_net_rxq_lock, irqf);
    return plen;
}

static int net_recv_post_arp_icmp_from_nic(void *buf, size_t cap) {
    if (!buf || cap == 0) return -1;
    for (int i = 0; i < 16; i++) {
        e1000_poll();
        int nn = e1000_recv_frame(buf, cap);
        if (nn <= 0) return nn;
        if (net_reply_arp_if_needed((const uint8_t *)buf, (size_t)nn)) continue;
        if (net_reply_icmp_echo_if_needed((const uint8_t *)buf, (size_t)nn)) continue;
        return nn;
    }
    return 0;
}

static int net_rxq_take_udp_datagram(ksock_net_t *s, uint8_t *out, size_t out_cap,
                                    uint32_t *out_src_ip_be, uint16_t *out_src_port) {
    if (!s || !out || out_cap == 0) return -1;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    uint32_t cnt = g_net_rxq_count;
    if (cnt == 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint32_t head0 = g_net_rxq_head;
    int found_at = -1;
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t idx = (head0 + i) % NET_RXQ_SLOTS;
        uint16_t fn = g_net_rxq_len[idx];
        if (fn == 0) continue;
        if (net_udp_match_sock_frame(g_net_rxq[idx], fn, s)) {
            found_at = (int)i;
            break;
        }
    }
    if (found_at < 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint8_t tmp[NET_RXQ_BUF];
    for (int r = 0; r < found_at; r++) {
        uint32_t hi = g_net_rxq_head;
        uint16_t tn = g_net_rxq_len[hi];
        memcpy(tmp, g_net_rxq[hi], tn);
        g_net_rxq_len[hi] = 0;
        g_net_rxq_head = (hi + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count--;
        uint32_t ti = g_net_rxq_tail;
        memcpy(g_net_rxq[ti], tmp, tn);
        g_net_rxq_len[ti] = tn;
        g_net_rxq_tail = (ti + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count++;
    }
    uint32_t hi2 = g_net_rxq_head;
    uint16_t n = g_net_rxq_len[hi2];
    memcpy(tmp, g_net_rxq[hi2], n);
    g_net_rxq_len[hi2] = 0;
    g_net_rxq_head = (hi2 + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count--;
    release_irqrestore(&g_net_rxq_lock, irqf);
    return net_udp_copy_payload_from_frame(tmp, n, out, out_cap, out_src_ip_be, out_src_port);
}

static int net_rxq_take_udp_raw(uint16_t local_port, uint32_t peer_ip_be, uint16_t peer_port,
                               uint8_t *out, size_t out_cap) {
    if (!out || out_cap == 0 || local_port == 0) return -1;
    unsigned long irqf = 0;
    acquire_irqsave(&g_net_rxq_lock, &irqf);
    uint32_t cnt = g_net_rxq_count;
    if (cnt == 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint32_t head0 = g_net_rxq_head;
    int found_at = -1;
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t idx = (head0 + i) % NET_RXQ_SLOTS;
        uint16_t fn = g_net_rxq_len[idx];
        if (fn == 0) continue;
        if (net_udp_match_raw_frame(g_net_rxq[idx], fn, local_port, peer_ip_be, peer_port)) {
            found_at = (int)i;
            break;
        }
    }
    if (found_at < 0) {
        release_irqrestore(&g_net_rxq_lock, irqf);
        return 0;
    }
    uint8_t tmp[NET_RXQ_BUF];
    for (int r = 0; r < found_at; r++) {
        uint32_t hi = g_net_rxq_head;
        uint16_t tn = g_net_rxq_len[hi];
        memcpy(tmp, g_net_rxq[hi], tn);
        g_net_rxq_len[hi] = 0;
        g_net_rxq_head = (hi + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count--;
        uint32_t ti = g_net_rxq_tail;
        memcpy(g_net_rxq[ti], tmp, tn);
        g_net_rxq_len[ti] = tn;
        g_net_rxq_tail = (ti + 1) % NET_RXQ_SLOTS;
        g_net_rxq_count++;
    }
    uint32_t hi2 = g_net_rxq_head;
    uint16_t n = g_net_rxq_len[hi2];
    memcpy(tmp, g_net_rxq[hi2], n);
    g_net_rxq_len[hi2] = 0;
    g_net_rxq_head = (hi2 + 1) % NET_RXQ_SLOTS;
    g_net_rxq_count--;
    release_irqrestore(&g_net_rxq_lock, irqf);
    return net_udp_copy_payload_from_frame(tmp, n, out, out_cap, NULL, NULL);
}

static uint16_t ip_checksum16(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += (uint32_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len) sum += (uint32_t)(p[0] << 8);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static void ip_be_to_bytes(uint32_t ip_be, uint8_t out[4]) {
    out[0] = (uint8_t)(ip_be >> 24);
    out[1] = (uint8_t)(ip_be >> 16);
    out[2] = (uint8_t)(ip_be >> 8);
    out[3] = (uint8_t)(ip_be);
}

static int ip_same_subnet(uint32_t a_be, uint32_t b_be, uint32_t mask_be) {
    return ((a_be & mask_be) == (b_be & mask_be));
}

static int net_stack_init(void);
static void net_ensure_resolv_conf(uint32_t dns_be);
static int ip_mask_prefix_len(uint32_t mask_be);
static int net_resolve_mac(uint32_t ip_be, uint8_t out_mac[6], uint32_t timeout_ms);

static int net_send_eth_ipv4(const uint8_t dst_mac[6], uint32_t dst_ip_be, uint8_t proto, const void *l4, size_t l4_len) {
    if (!g_net.ready || !dst_mac || !l4 || l4_len > 1500) return -1;
    size_t frame_len = sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + l4_len;
    uint8_t *frame = (uint8_t *)kmalloc(frame_len);
    if (!frame) return -1;

    eth_hdr_t *eth = (eth_hdr_t *)frame;
    memcpy(eth->dst, dst_mac, 6);
    memcpy(eth->src, g_net.mac, 6);
    eth->ethertype = be16(ETH_TYPE_IPV4);

    ipv4_hdr_t *ip = (ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = 0x45;
    ip->total_len = be16((uint16_t)(sizeof(ipv4_hdr_t) + l4_len));
    ip->id = be16(++g_net.ip_id);
    ip->frag_off = be16(0x0000);
    ip->ttl = 64;
    ip->proto = proto;
    ip->src = be32(g_net.ip_be);
    ip->dst = be32(dst_ip_be);
    ip->csum = be16(ip_checksum16(ip, sizeof(*ip)));

    memcpy(frame + sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t), l4, l4_len);
    int r = e1000_send_frame(frame, frame_len);
    kfree(frame);
    return (r < 0) ? -1 : 0;
}

static int net_resolve_next_hop_mac(uint32_t dst_ip_be, uint8_t out_mac[6]) {
    if (!out_mac) return -1;
    if (net_stack_init() != 0) return -1;
    uint32_t nh = ip_same_subnet(dst_ip_be, g_net.ip_be, g_net.mask_be) ? dst_ip_be : g_net.gw_be;
    if (nh == g_net.gw_be && g_net.gw_mac_valid) {
        memcpy(out_mac, g_net.gw_mac, 6);
        return 0;
    }
    if (net_resolve_mac(nh, out_mac, 15000) != 0) return -1;
    if (nh == g_net.gw_be) {
        memcpy(g_net.gw_mac, out_mac, 6);
        g_net.gw_mac_valid = 1;
    }
    return 0;
}

static int net_send_udp_datagram(uint32_t dst_ip_be, uint16_t src_port, uint16_t dst_port, const uint8_t *payload, size_t payload_len) {
    if (!payload || payload_len > 1472) return -1;
    if (net_stack_init() != 0) return -1;
    uint8_t dst_mac[6];
    if (net_resolve_next_hop_mac(dst_ip_be, dst_mac) != 0) return -1;
    size_t l4_len = sizeof(udp_hdr_t) + payload_len;
    uint8_t *pkt = (uint8_t *)kmalloc(l4_len);
    if (!pkt) return -1;
    udp_hdr_t *uh = (udp_hdr_t *)pkt;
    uh->src_port = be16(src_port);
    uh->dst_port = be16(dst_port);
    uh->len = be16((uint16_t)l4_len);
    uh->csum = 0; /* checksum optional for IPv4 */
    if (payload_len > 0) memcpy(pkt + sizeof(udp_hdr_t), payload, payload_len);
    int r = net_send_eth_ipv4(dst_mac, dst_ip_be, IPPROTO_UDP_LOCAL, pkt, l4_len);
    kfree(pkt);
    return r;
}

static uint32_t g_net_ephemeral_port_seq;

/* Linux-style dynamic ports (32768–65535). Per-tid reuse broke resolver: parallel A/AAAA
 * UDP sockets on one thread shared the same local port and stole each other's replies. */
static uint16_t net_alloc_ephemeral_port(void) {
    uint32_t n = __atomic_add_fetch(&g_net_ephemeral_port_seq, 1u, __ATOMIC_RELAXED);
    return (uint16_t)(32768u + (n % 32768u));
}

static int net_recv_udp_datagram(ksock_net_t *s, uint8_t *out, size_t out_cap, uint32_t timeout_ms, uint32_t *out_src_ip_be, uint16_t *out_src_port) {
    if (!s || !out || out_cap == 0 || s->local_port == 0) return -1;
    if (net_stack_init() != 0) return -1;
    uint8_t *frame = kmalloc(NET_FRAME_BUF);
    if (!frame) return -1;
    uint64_t start = pit_get_time_ms();
    int ret = 0;
    /* timeout_ms==0: single attempt (poll / non-blocking). Old code used while(elapsed<0) and ran zero times. */
    do {
        int q = net_rxq_take_udp_datagram(s, out, out_cap, out_src_ip_be, out_src_port);
        if (q > 0) { ret = q; break; }
        if (q < 0) { ret = q; break; }
        int n = net_recv_post_arp_icmp_from_nic(frame, NET_FRAME_BUF);
        if (n <= 0) {
            if (pit_get_time_ms() - start >= (uint64_t)timeout_ms) break;
            thread_sleep(1);
            continue;
        }
        if (net_udp_match_sock_frame((const uint8_t *)frame, (size_t)n, s)) {
            ret = net_udp_copy_payload_from_frame((const uint8_t *)frame, (size_t)n, out, out_cap, out_src_ip_be, out_src_port);
            break;
        }
        (void)net_rxq_push((const uint8_t *)frame, (size_t)n);
        thread_sleep(0);
    } while (ret == 0 && (pit_get_time_ms() - start) < (uint64_t)timeout_ms);
    kfree(frame);
    return ret;
}

/* One-off UDP recv for DNS: filter by local_port and peer (peer_ip_be, peer_port). Returns bytes, 0=timeout, <0=error. */
static int net_recv_udp_raw(uint16_t local_port, uint32_t peer_ip_be, uint16_t peer_port,
                            uint8_t *out, size_t out_cap, uint32_t timeout_ms) {
    if (!out || out_cap == 0 || local_port == 0) return -1;
    if (net_stack_init() != 0) return -1;
    uint8_t *frame = kmalloc(NET_FRAME_BUF);
    if (!frame) return -1;
    uint64_t start = pit_get_time_ms();
    int ret = 0;
    do {
        int q = net_rxq_take_udp_raw(local_port, peer_ip_be, peer_port, out, out_cap);
        if (q > 0) { ret = q; break; }
        if (q < 0) { ret = q; break; }
        int n = net_recv_post_arp_icmp_from_nic(frame, NET_FRAME_BUF);
        if (n <= 0) {
            if (pit_get_time_ms() - start >= (uint64_t)timeout_ms) break;
            thread_sleep(1);
            continue;
        }
        if (net_udp_match_raw_frame((const uint8_t *)frame, (size_t)n, local_port, peer_ip_be, peer_port)) {
            ret = net_udp_copy_payload_from_frame((const uint8_t *)frame, (size_t)n, out, out_cap, NULL, NULL);
            break;
        }
        (void)net_rxq_push((const uint8_t *)frame, (size_t)n);
        thread_sleep(0);
    } while (ret == 0 && (pit_get_time_ms() - start) < (uint64_t)timeout_ms);
    kfree(frame);
    return ret;
}

#define NET_UDP_BLOCK_MAX_MS 120000u

/* One blocking recv: keep waiting (slice by slice) instead of returning EAGAIN after ~3s like a non-blocking socket. */
static int net_udp_recv_into_pending(ksock_net_t *s) {
    if (!s || s->rx_has_pending) return 1;
    if (s->local_port == 0) return -1;
    if (s->nonblock) {
        int rn = net_recv_udp_datagram(s, s->rx_pending, sizeof(s->rx_pending), 0u,
                                       &s->rx_pending_src_ip_be, &s->rx_pending_src_port);
        if (rn > 0) {
            ksock_rx_pending_install(s, rn);
            return 1;
        }
        return (rn < 0) ? -1 : 0;
    }
    uint64_t deadline = pit_get_time_ms() + (uint64_t)NET_UDP_BLOCK_MAX_MS;
    for (;;) {
        uint32_t slice = 10000u;
        uint64_t now = pit_get_time_ms();
        if (now >= deadline) return 0;
        if (now + slice > deadline) slice = (uint32_t)(deadline - now);
        if (slice < 1u) slice = 1u;
        int rn = net_recv_udp_datagram(s, s->rx_pending, sizeof(s->rx_pending), slice,
                                       &s->rx_pending_src_ip_be, &s->rx_pending_src_port);
        if (rn > 0) {
            ksock_rx_pending_install(s, rn);
            return 1;
        }
        if (rn < 0) return -1;
    }
}

static int net_send_l4_ipv4_cb(uint32_t dst_ip_be, uint8_t proto, const void *l4, size_t l4_len) {
    uint8_t dst_mac[6];
    if (net_resolve_next_hop_mac(dst_ip_be, dst_mac) != 0) return -1;
    return net_send_eth_ipv4(dst_mac, dst_ip_be, proto, l4, l4_len);
}

static int net_recv_frame_cb(void *buf, size_t cap) {
    return net_recv_frame_any(buf, cap);
}

static uint64_t net_time_ms_cb(void) {
    return pit_get_time_ms();
}

static void net_yield_cb(void) {
    /* VMware: thread_sleep(1) instead of yield — prevents tight loop, lets emulation deliver packets */
    thread_sleep(1);
}

static void net_tcp_return_frame_cb(const void *frame, size_t n) {
    if (!frame || n == 0) return;
    (void)net_rxq_push((const uint8_t *)frame, n);
}

static void net_make_tcp_ops(net_tcp_ops_t *ops) {
    if (!ops) return;
    memset(ops, 0, sizeof(*ops));
    ops->local_ip_be = g_net.ip_be;
    ops->send_l4 = net_send_l4_ipv4_cb;
    ops->recv_frame = net_recv_frame_cb;
    ops->time_ms = net_time_ms_cb;
    ops->yield = net_yield_cb;
    ops->return_frame = net_tcp_return_frame_cb;
}

static int net_send_arp_request(uint32_t target_ip_be) {
    uint8_t frame[64];
    memset(frame, 0, sizeof(frame));
    eth_hdr_t *eth = (eth_hdr_t *)frame;
    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, g_net.mac, 6);
    eth->ethertype = be16(ETH_TYPE_ARP);

    arp_hdr_t *arp = (arp_hdr_t *)(frame + sizeof(eth_hdr_t));
    arp->htype = be16(1);
    arp->ptype = be16(ETH_TYPE_IPV4);
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = be16(1);
    memcpy(arp->sha, g_net.mac, 6);
    ip_be_to_bytes(g_net.ip_be, arp->spa);
    memset(arp->tha, 0, 6);
    ip_be_to_bytes(target_ip_be, arp->tpa);

    return (e1000_send_frame(frame, sizeof(frame)) < 0) ? -1 : 0;
}

static int net_try_parse_arp_reply_for_ip(const uint8_t *frame, size_t n, uint32_t ip_be, uint8_t out_mac[6]) {
    if (!frame || n < sizeof(eth_hdr_t) + sizeof(arp_hdr_t)) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_ARP) return 0;
    const arp_hdr_t *arp = (const arp_hdr_t *)(frame + sizeof(eth_hdr_t));
    if (be16(arp->oper) != 2) return 0;
    uint32_t spa = ((uint32_t)arp->spa[0] << 24) | ((uint32_t)arp->spa[1] << 16) | ((uint32_t)arp->spa[2] << 8) | arp->spa[3];
    if (spa != ip_be) return 0;
    memcpy(out_mac, arp->sha, 6);
    return 1;
}

static int net_resolve_mac(uint32_t ip_be, uint8_t out_mac[6], uint32_t timeout_ms) {
    if (!out_mac) return -1;
    /* Drain RX so ARP reply is not behind leftover DHCP/other frames. */
    { uint8_t drain[256]; for (;;) { if (net_recv_frame_any(drain, sizeof(drain)) <= 0) break; } }
    if (net_send_arp_request(ip_be) != 0) return -1;
    uint8_t *frame = kmalloc(NET_FRAME_BUF);
    if (!frame) return -1;
    uint64_t start = pit_get_time_ms();
    int ret = -1;
    while ((pit_get_time_ms() - start) < timeout_ms) {
        int r = net_recv_frame_any(frame, NET_FRAME_BUF);
        if (r > 0 && net_try_parse_arp_reply_for_ip(frame, (size_t)r, ip_be, out_mac)) { ret = 0; break; }
        thread_sleep(1);
    }
    kfree(frame);
    return ret;
}


static int net_stack_init(void) {
    if (g_net.inited) return g_net.ready ? 0 : -1;
    if (g_net_shadow_valid && g_net_shadow.ready) {
        g_net = g_net_shadow;
        klogprintf("net: restored cached state ip=%u.%u.%u.%u gw=%u.%u.%u.%u\n",
                   (unsigned)((g_net.ip_be >> 24) & 0xFF), (unsigned)((g_net.ip_be >> 16) & 0xFF),
                   (unsigned)((g_net.ip_be >> 8) & 0xFF), (unsigned)(g_net.ip_be & 0xFF),
                   (unsigned)((g_net.gw_be >> 24) & 0xFF), (unsigned)((g_net.gw_be >> 16) & 0xFF),
                   (unsigned)((g_net.gw_be >> 8) & 0xFF), (unsigned)(g_net.gw_be & 0xFF));
        return 0;
    }
    memset(&g_net, 0, sizeof(g_net));
    g_net.inited = 1;
    g_net.ip_id = 1;
    if (e1000_get_mac(g_net.mac) != 0) return -1;

    /* Strong fallback cache keyed by NIC MAC: bypass repeated DHCP if g_net was reset. */
    if (g_net_cfg_magic == 0x4E455443u &&
        g_net_cfg_ip_be != 0 && g_net_cfg_mask_be != 0 && g_net_cfg_gw_be != 0 &&
        memcmp(g_net_cfg_mac, g_net.mac, 6) == 0) {
        g_net.ip_be = g_net_cfg_ip_be;
        g_net.mask_be = g_net_cfg_mask_be;
        g_net.gw_be = g_net_cfg_gw_be;
        g_net.dns_be = g_net_cfg_dns_be ? g_net_cfg_dns_be : g_net_cfg_gw_be;
        g_net.ready = 1;
        g_net_shadow = g_net;
        g_net_shadow_valid = 1;
        klogprintf("net: restored MAC cache ip=%u.%u.%u.%u gw=%u.%u.%u.%u\n",
                   (unsigned)((g_net.ip_be >> 24) & 0xFF), (unsigned)((g_net.ip_be >> 16) & 0xFF),
                   (unsigned)((g_net.ip_be >> 8) & 0xFF), (unsigned)(g_net.ip_be & 0xFF),
                   (unsigned)((g_net.gw_be >> 24) & 0xFF), (unsigned)((g_net.gw_be >> 16) & 0xFF),
                   (unsigned)((g_net.gw_be >> 8) & 0xFF), (unsigned)(g_net.gw_be & 0xFF));
        return 0;
    }
    
    dhcp_lease_t lease;
    uint32_t dns_be = 0;
    if (dhcp_acquire(g_net.mac, &lease) == 0) {
        g_net.ip_be = lease.ip_be;
        g_net.mask_be = lease.mask_be;
        g_net.gw_be = lease.gw_be;
        dns_be = lease.dns_be ? lease.dns_be : lease.gw_be;
        g_net.dns_be = dns_be;
    } else {
        /* Fallback for QEMU user networking only. Do NOT cache: bridged/NAT would
           get wrong 10.0.2.x and DNS would never work. Next init retries DHCP. */
        g_net.ip_be = 0x0A00020Fu;   /* 10.0.2.15 */
        g_net.mask_be = 0xFFFFFF00u; /* /24 */
        g_net.gw_be = 0x0A000202u;   /* 10.0.2.2 */
        dns_be = 0x0A000203u;        /* 10.0.2.3 QEMU DNS */
        g_net.dns_be = dns_be;
        klogprintf("net: DHCP failed, fallback ip=10.0.2.15 gw=10.0.2.2 (not cached)\n");
    }
    g_net.ready = 1;
    g_net_shadow = g_net;
    g_net_shadow_valid = 1;
    /* Only cache when DHCP succeeded; bridged mode would otherwise get stuck on 10.0.2.x */
    if (dns_be != 0x0A000203u) { /* not QEMU fallback */
        memcpy(g_net_cfg_mac, g_net.mac, 6);
        g_net_cfg_ip_be = g_net.ip_be;
        g_net_cfg_mask_be = g_net.mask_be;
        g_net_cfg_gw_be = g_net.gw_be;
        g_net_cfg_dns_be = g_net.dns_be;
    }
    klogprintf("net: ready ip=%u.%u.%u.%u gw=%u.%u.%u.%u\n",
               (unsigned)((g_net.ip_be >> 24) & 0xFF), (unsigned)((g_net.ip_be >> 16) & 0xFF),
               (unsigned)((g_net.ip_be >> 8) & 0xFF), (unsigned)(g_net.ip_be & 0xFF),
               (unsigned)((g_net.gw_be >> 24) & 0xFF), (unsigned)((g_net.gw_be >> 16) & 0xFF),
               (unsigned)((g_net.gw_be >> 8) & 0xFF), (unsigned)(g_net.gw_be & 0xFF));

    /* Start background RX pump once: reply to ARP/ICMP even when userland is idle. */
    if (!g_net_rx_thread_started) {
        thread_t *t = thread_create(net_rx_pump_thread, "net_rx");
        if (t) {
            t->nice = 10; /* low priority */
            g_net_rx_thread_started = 1;
        }
    }
    return 0;
}

int syscall_net_preinit(void) {
    return net_stack_init();
}

void syscall_net_ensure_resolv(void) {
    /* Without /etc/resolv.conf, glibc/musl/wget try stub paths (e.g. 127.0.0.1) and
       report "bad address". Mirror the same DNS choice as SYS_resolve. */
    (void)net_stack_init();
    uint32_t dns_be = 0;
    if (g_net.ready)
        dns_be = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
    if (!dns_be && g_net.gw_be)
        dns_be = g_net.gw_be;
    /* Last resort for QEMU usernet; bridged setups should have gw/dns above. */
    if (!dns_be)
        dns_be = 0x0A000202u;

    char line[96];
    unsigned a = (unsigned)((dns_be >> 24) & 0xFFu);
    unsigned b = (unsigned)((dns_be >> 16) & 0xFFu);
    unsigned c = (unsigned)((dns_be >> 8) & 0xFFu);
    unsigned d = (unsigned)(dns_be & 0xFFu);
    int n = snprintf(line, sizeof(line), "nameserver %u.%u.%u.%u\n", a, b, c, d);
    if (n <= 0 || (size_t)n >= sizeof(line))
        return;

    (void)fs_unlink("/etc/resolv.conf");
    struct fs_file *f = fs_create_file("/etc/resolv.conf");
    if (!f)
        f = fs_open("/etc/resolv.conf");
    if (f) {
        fs_write(f, line, (size_t)n, 0);
        fs_file_free(f);
    }
}

/* DNS resolver callbacks (ctx unused) */
static int dns_send_udp_cb(uint32_t dst_ip_be, uint16_t src_port, uint16_t dst_port,
                           const void *data, size_t len, void *ctx) {
    (void)ctx;
    return net_send_udp_datagram(dst_ip_be, src_port, dst_port, (const uint8_t *)data, len) == 0 ? 0 : -1;
}
static int dns_recv_udp_cb(uint16_t local_port, uint32_t peer_ip_be, uint16_t peer_port,
                           void *out, size_t cap, uint32_t timeout_ms, void *ctx) {
    (void)ctx;
    return net_recv_udp_raw(local_port, peer_ip_be, peer_port, (uint8_t *)out, cap, timeout_ms);
}

static int kernel_dns_resolve(const char *hostname, uint32_t dns_ip_be, uint32_t *out_ip_be) {
    if (!g_net.ready || !dns_ip_be) return -1;
    return net_dns_resolve(hostname, dns_ip_be, dns_send_udp_cb, dns_recv_udp_cb, NULL, out_ip_be);
}

/* Parse "a.b.c.d" to IPv4 network byte order. Returns 0 on success, -1 on invalid. */
static int parse_ipv4_dotted(const char *s, uint32_t *out_ip_be) {
    if (!s || !out_ip_be) return -1;
    uint32_t a = 0, b = 0, c = 0, d = 0;
    int na = 0, nb = 0, nc = 0, nd = 0;
    const char *p = s;
    while (*p >= '0' && *p <= '9') { a = a * 10 + (uint32_t)(*p - '0'); na++; p++; }
    if (na == 0 || *p != '.') return -1; p++;
    while (*p >= '0' && *p <= '9') { b = b * 10 + (uint32_t)(*p - '0'); nb++; p++; }
    if (nb == 0 || *p != '.') return -1; p++;
    while (*p >= '0' && *p <= '9') { c = c * 10 + (uint32_t)(*p - '0'); nc++; p++; }
    if (nc == 0 || *p != '.') return -1; p++;
    while (*p >= '0' && *p <= '9') { d = d * 10 + (uint32_t)(*p - '0'); nd++; p++; }
    if (nd == 0 || *p != '\0') return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255) return -1;
    *out_ip_be = (a << 24) | (b << 16) | (c << 8) | d;
    return 0;
}

/* Check if string looks like dotted-decimal IP (no hostname chars). */
static int is_dotted_ip(const char *s) {
    if (!s || !*s) return 0;
    size_t i = 0;
    int dots = 0;
    while (s[i]) {
        char c = s[i];
        if (c >= '0' && c <= '9') { i++; continue; }
        if (c == '.') { dots++; i++; continue; }
        return 0;
    }
    return (dots == 3);
}

/* Parse /etc/hosts and lookup hostname. Returns 0 if found, -1 if not. */
static int kernel_hosts_lookup(const char *hostname, uint32_t *out_ip_be) {
    if (!hostname || !hostname[0] || !out_ip_be) return -1;
    struct fs_file *f = fs_open("/etc/hosts");
    if (!f) return -1;
    char buf[2048];
    ssize_t n = fs_read(f, buf, sizeof(buf) - 1, 0);
    fs_file_free(f);
    if (n <= 0) return -1;
    buf[(size_t)n] = '\0';
    const char *p = buf;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p == '#' || !*p) {
            while (*p && *p != '\n') p++;
            continue;
        }
        char ip_str[64];
        size_t ii = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '#' && ii < sizeof(ip_str) - 1)
            ip_str[ii++] = *p++;
        ip_str[ii] = '\0';
        if (ii == 0) continue;
        uint32_t ip_be = 0;
        if (parse_ipv4_dotted(ip_str, &ip_be) != 0) continue;
        while (*p == ' ' || *p == '\t') p++;
        while (*p && *p != '#' && *p != '\n') {
            size_t hn = 0;
            char hn_buf[256];
            while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '#' && hn < sizeof(hn_buf) - 1)
                hn_buf[hn++] = *p++;
            hn_buf[hn] = '\0';
            if (hn > 0) {
                size_t hl = 0;
                while (hostname[hl] && hn_buf[hl] && hostname[hl] == hn_buf[hl]) hl++;
                if (hostname[hl] == '\0' && hn_buf[hl] == '\0') {
                    *out_ip_be = ip_be;
                    return 0;
                }
            }
            while (*p == ' ' || *p == '\t') p++;
        }
        while (*p && *p != '\n') p++;
    }
    return -1;
}

/*
 * Full resolver: 1) dotted-decimal IP, 2) /etc/hosts, 3) DNS.
 * Returns 0 on success, -1 on failure.
 */
static int kernel_resolve_full(const char *hostname, uint32_t dns_ip_be, uint32_t *out_ip_be) {
    if (!hostname || !hostname[0] || !out_ip_be) return -1;
    if (is_dotted_ip(hostname) && parse_ipv4_dotted(hostname, out_ip_be) == 0)
        return 0;
    if (kernel_hosts_lookup(hostname, out_ip_be) == 0)
        return 0;
    if (net_stack_init() != 0) return -1;
    return kernel_dns_resolve(hostname, dns_ip_be, out_ip_be);
}

static void net_ensure_resolv_conf(uint32_t dns_be) {
    (void)dns_be;
    /* no-op: see syscall_net_ensure_resolv() */
}

static int ip_mask_prefix_len(uint32_t mask_be) {
    int n = 0;
    for (int i = 31; i >= 0; i--) {
        if (mask_be & (1u << i)) n++;
        else break;
    }
    return n;
}

static int netlink_build_route_dump(ksock_net_t *s, uint16_t req_type, uint32_t seq);

static int net_send_icmp_echo(ksock_net_t *s, uint32_t dst_ip_be, const uint8_t *icmp, size_t icmp_len) {
    if (!s || !icmp || icmp_len == 0) return -1;
    if (net_stack_init() != 0) return -1;
    /* Drain RX before send (limit 64) so old echo replies don't block next recv (second ping timeout). */
    { uint8_t drain[256]; for (int d = 0; d < 64; d++) { if (net_recv_frame_any(drain, sizeof(drain)) <= 0) break; } }
    /* 0.0.0.0 and 255.255.255.255: no host replies; send to gateway so user gets a reply. */
    if (dst_ip_be == 0 || dst_ip_be == 0xFFFFFFFFu) dst_ip_be = g_net.gw_be;
    uint32_t nh = ip_same_subnet(dst_ip_be, g_net.ip_be, g_net.mask_be) ? dst_ip_be : g_net.gw_be;
    uint8_t dst_mac[6];
    if (nh == g_net.gw_be && g_net.gw_mac_valid) memcpy(dst_mac, g_net.gw_mac, 6);
    else {
        uint32_t arp_ms = 15000;
        if (net_resolve_mac(nh, dst_mac, arp_ms) != 0) {
            /* Повтор ARP для шлюза (VMware иногда отвечает с задержкой). */
            if (nh == g_net.gw_be) {
                uint8_t drain[256];
                for (;;) { if (net_recv_frame_any(drain, sizeof(drain)) <= 0) break; }
                if (net_send_arp_request(nh) != 0) return -1;
                if (net_resolve_mac(nh, dst_mac, arp_ms) != 0) return -1;
            } else
                return -1;
        }
        if (nh == g_net.gw_be) {
            memcpy(g_net.gw_mac, dst_mac, 6);
            g_net.gw_mac_valid = 1;
        }
    }
    s->last_dst_ip_be = dst_ip_be;

    if (s->type_base == SOCK_DGRAM_LOCAL) {
        /* Linux ping commonly uses SOCK_DGRAM + IPPROTO_ICMP:
           userspace passes payload only, kernel builds ICMP header. */
        size_t pkt_len = 8 + icmp_len;
        uint8_t *pkt = (uint8_t *)kmalloc(pkt_len);
        if (!pkt) return -1;
        memset(pkt, 0, pkt_len);
        pkt[0] = 8; /* Echo Request */
        pkt[1] = 0; /* code */
        uint16_t id = (uint16_t)((thread_current() ? thread_current()->tid : 1) & 0xFFFFu);
        uint16_t seq = ++s->next_echo_seq;
        pkt[4] = (uint8_t)(id >> 8); pkt[5] = (uint8_t)id;
        pkt[6] = (uint8_t)(seq >> 8); pkt[7] = (uint8_t)seq;
        memcpy(pkt + 8, icmp, icmp_len);
        uint16_t csum = ip_checksum16(pkt, pkt_len);
        pkt[2] = (uint8_t)(csum >> 8); pkt[3] = (uint8_t)csum;
        s->last_echo_id = id;
        s->last_echo_seq = seq;
        int r = net_send_eth_ipv4(dst_mac, dst_ip_be, IPPROTO_ICMP_LOCAL, pkt, pkt_len);
        kfree(pkt);
        return r;
    }

    /* SOCK_RAW path: userspace provides full ICMP packet including header. */
    if (icmp_len < 8) return -1;
    s->last_echo_id = (uint16_t)((icmp[4] << 8) | icmp[5]);
    s->last_echo_seq = (uint16_t)((icmp[6] << 8) | icmp[7]);
    return net_send_eth_ipv4(dst_mac, dst_ip_be, IPPROTO_ICMP_LOCAL, icmp, icmp_len);
}

static int net_try_parse_icmp_reply(const uint8_t *frame, size_t n, ksock_net_t *s, uint8_t *out, size_t out_cap, uint32_t *out_src_ip_be) {
    if (!frame || n < sizeof(eth_hdr_t) + sizeof(ipv4_hdr_t) + 8 || !s || !out) return 0;
    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    if (be16(eth->ethertype) != ETH_TYPE_IPV4) return 0;
    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)(frame + sizeof(eth_hdr_t));
    size_t ihl = (size_t)((ip->ver_ihl & 0x0Fu) * 4u);
    if (ihl < sizeof(ipv4_hdr_t)) return 0;
    if (ip->proto != IPPROTO_ICMP_LOCAL) return 0;
    uint16_t tot = be16(ip->total_len);
    if (tot < ihl + 8) return 0;
    if (sizeof(eth_hdr_t) + tot > n) return 0;
    const uint8_t *icmp = frame + sizeof(eth_hdr_t) + ihl;
    if (icmp[0] != 0 || icmp[1] != 0) return 0; /* echo reply */
    uint16_t id = (uint16_t)((icmp[4] << 8) | icmp[5]);
    uint16_t seq = (uint16_t)((icmp[6] << 8) | icmp[7]);
    if (id != s->last_echo_id || seq != s->last_echo_seq) return 0;
    size_t copy_len = 0;
    if (s->type_base == SOCK_DGRAM_LOCAL) {
        /* For datagram ICMP sockets return only ICMP payload. */
        size_t icmp_len = (size_t)tot - ihl;
        if (icmp_len < 8) return 0;
        size_t payload_len = icmp_len - 8;
        copy_len = (payload_len > out_cap) ? out_cap : payload_len;
        if (copy_len > 0) memcpy(out, icmp + 8, copy_len);
        else { out[0] = 0; copy_len = 1; } /* empty payload: still report success */
    } else {
        /* Raw ICMP sockets expect IPv4 header included. */
        copy_len = (tot > out_cap) ? out_cap : tot;
        memcpy(out, ip, copy_len);
    }
    if (out_src_ip_be) *out_src_ip_be = be32(ip->src);
    return (int)copy_len;
}

static int net_recv_icmp_echo_reply(ksock_net_t *s, uint8_t *out, size_t out_cap, uint32_t timeout_ms, uint32_t *out_src_ip_be) {
    if (!s || !out || out_cap == 0) return -1;
    if (net_stack_init() != 0) return -1;
    uint8_t *frame = kmalloc(NET_FRAME_BUF);
    if (!frame) return -1;
    uint64_t start = pit_get_time_ms();
    int ret = 0;
    while ((pit_get_time_ms() - start) < timeout_ms) {
        thread_t *tcur = thread_get_current_user();
        if (!tcur) tcur = thread_current();
        if (tcur && (tcur->pending_signals & (1ULL << (2 - 1)))) { ret = -4; break; } /* SIGINT */
        int n = net_recv_frame_any(frame, NET_FRAME_BUF);
        if (n > 0) {
            int got = net_try_parse_icmp_reply(frame, (size_t)n, s, out, out_cap, out_src_ip_be);
            if (got > 0) { ret = got; break; }
        } else {
            int spun = 0;
            for (; spun < 200 && ret <= 0; spun++) {
                n = net_recv_frame_any(frame, NET_FRAME_BUF);
                if (n > 0) {
                    int got = net_try_parse_icmp_reply(frame, (size_t)n, s, out, out_cap, out_src_ip_be);
                    if (got > 0) { ret = got; break; }
                    goto next_iter;
                }
            }
            if (spun >= 200) thread_sleep(1);
        }
next_iter:
        if (ret != 0) break;
    }
    kfree(frame);
    return ret;
}

enum {
    PING_TS_UNKNOWN = 0,
    PING_TS_NONE,
    PING_TS_U64_USEC,
    PING_TS_TIMEVAL64,
    PING_TS_TIMESPEC64,
    PING_TS_TIMEVAL32
};

static int net_detect_ping_ts_fmt(const uint8_t *payload, size_t payload_len) {
    if (!payload || payload_len < 8) return PING_TS_NONE;
    uint64_t w0 = 0, w1 = 0;
    memcpy(&w0, payload + 0, sizeof(w0));
    if (payload_len >= 16) memcpy(&w1, payload + 8, sizeof(w1));

    /* gettimeofday timeval64: sec near Unix epoch, usec sub-second */
    if (payload_len >= 16 &&
        w0 > 1000000000ULL && w0 < 5000000000ULL &&
        w1 < 1000000ULL) return PING_TS_TIMEVAL64;

    /* clock_gettime timespec64: sec since boot/epoch, nsec sub-second */
    if (payload_len >= 16 &&
        w0 < 0x7FFFFFFFULL &&
        w1 < 1000000000ULL) return PING_TS_TIMESPEC64;

    /* Common "u64 usec" ping payload style. */
    if (w0 > 1000000ULL) return PING_TS_U64_USEC;

    if (payload_len >= 8) {
        uint32_t s32 = 0, us32 = 0;
        memcpy(&s32, payload + 0, sizeof(s32));
        memcpy(&us32, payload + 4, sizeof(us32));
        if (s32 > 1000000000U && s32 < 5000000000U && us32 < 1000000U) return PING_TS_TIMEVAL32;
    }

    return PING_TS_UNKNOWN;
}

static void net_update_ping_ts_payload(uint8_t *payload, size_t payload_len, int fmt) {
    if (!payload || payload_len < 8) return;
    uint64_t now_ms = pit_get_time_ms();
    uint64_t sec = now_ms / 1000ULL;
    uint64_t usec = (now_ms % 1000ULL) * 1000ULL;
    uint64_t nsec = (now_ms % 1000ULL) * 1000000ULL;
    uint64_t us64 = sec * 1000000ULL + usec;

    switch (fmt) {
        case PING_TS_TIMEVAL64:
            if (payload_len >= 16) {
                memcpy(payload + 0, &sec, sizeof(sec));
                memcpy(payload + 8, &usec, sizeof(usec));
            }
            break;
        case PING_TS_TIMESPEC64:
            if (payload_len >= 16) {
                memcpy(payload + 0, &sec, sizeof(sec));
                memcpy(payload + 8, &nsec, sizeof(nsec));
            }
            break;
        case PING_TS_TIMEVAL32:
            if (payload_len >= 8) {
                uint32_t s32 = (uint32_t)sec;
                uint32_t us32 = (uint32_t)usec;
                memcpy(payload + 0, &s32, sizeof(s32));
                memcpy(payload + 4, &us32, sizeof(us32));
            }
            break;
        case PING_TS_U64_USEC:
        case PING_TS_UNKNOWN:
        default:
            memcpy(payload + 0, &us64, sizeof(us64));
            break;
    }
}

static int net_send_icmp_echo_timer_compat(ksock_net_t *s) {
    if (!s || s->last_dst_ip_be == 0 || s->last_req_len == 0) return -1;

    if (s->type_base == SOCK_DGRAM_LOCAL) {
        net_update_ping_ts_payload(s->last_req, s->last_req_len, s->last_req_ts_fmt);
        return net_send_icmp_echo(s, s->last_dst_ip_be, s->last_req, s->last_req_len);
    }

    if (s->last_req_len < 8) return -1;
    uint8_t *pkt = s->last_req;
    uint16_t seq = (uint16_t)((pkt[6] << 8) | pkt[7]);
    seq = (uint16_t)(seq + 1u);
    pkt[6] = (uint8_t)(seq >> 8);
    pkt[7] = (uint8_t)seq;
    if (s->last_req_len > 8) {
        net_update_ping_ts_payload(pkt + 8, s->last_req_len - 8, s->last_req_ts_fmt);
    }
    pkt[2] = 0;
    pkt[3] = 0;
    {
        uint16_t csum = ip_checksum16(pkt, s->last_req_len);
        pkt[2] = (uint8_t)(csum >> 8);
        pkt[3] = (uint8_t)csum;
    }
    return net_send_icmp_echo(s, s->last_dst_ip_be, pkt, s->last_req_len);
}

static struct fs_file *socket_file_get(thread_t *cur, int fd, ksock_net_t **out_sock) {
    if (!cur || fd < 0 || fd >= THREAD_MAX_FD) return NULL;
    struct fs_file *f = cur->fds[fd];
    if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) return NULL;
    if (out_sock) *out_sock = (ksock_net_t *)f->driver_private;
    return f;
}

/* Linux /proc/net/tcp IPv4 hex: byte-reverse of network-order IP (see /proc/net/tcp). */
static uint32_t ip_be_to_proc_net_hex(uint32_t ip_be) {
    return ((ip_be & 0xFFu) << 24) | ((ip_be & 0xFF00u) << 8)
         | ((ip_be >> 8) & 0xFF00u) | ((ip_be >> 24) & 0xFFu);
}

ssize_t procfs_net_snap_tcp(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    size_t w = 0;
    int n = snprintf((char *)buf + w, size - w,
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
    if (n < 0) return 0;
    w += (size_t)n;
    int sl = 0;
    int tcnt = thread_get_count();
    for (int ti = 0; ti < tcnt; ti++) {
        thread_t *t = thread_get_by_index(ti);
        if (!t) continue;
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            struct fs_file *f = t->fds[fd];
            if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
            ksock_net_t *s = (ksock_net_t *)f->driver_private;
            if (s->type_base != SOCK_STREAM_LOCAL || s->protocol != IPPROTO_TCP_LOCAL) continue;
            if (!s->tcp.used) continue;
            uint32_t lip_be = g_net.ready ? g_net.ip_be : 0u;
            uint32_t lhx = ip_be_to_proc_net_hex(lip_be);
            uint32_t rhx = ip_be_to_proc_net_hex(s->peer_ip_be);
            unsigned st = s->tcp.established ? 1u : 2u;
            unsigned long inode = (unsigned long)(((unsigned)t->tid + 1u) * 100000u + (unsigned)fd + 1000u);
            n = snprintf((char *)buf + w, w < size ? size - w : 0,
                "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08X %08X %5d %8d %lu\n",
                sl++, lhx, (unsigned)(s->local_port & 0xFFFFu), rhx, (unsigned)(s->peer_port & 0xFFFFu), st,
                0u, 0u, 0u, 0u, 0u, (int)t->euid, 0, inode);
            if (n < 0) return (ssize_t)w;
            w += (size_t)n;
            if (w + 256 >= size) return (ssize_t)w;
        }
    }
    return (ssize_t)w;
}

ssize_t procfs_net_snap_udp(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    size_t w = 0;
    int n = snprintf((char *)buf + w, size - w,
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
    if (n < 0) return 0;
    w += (size_t)n;
    int sl = 0;
    int tcnt = thread_get_count();
    for (int ti = 0; ti < tcnt; ti++) {
        thread_t *t = thread_get_by_index(ti);
        if (!t) continue;
        for (int fd = 0; fd < THREAD_MAX_FD; fd++) {
            struct fs_file *f = t->fds[fd];
            if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
            ksock_net_t *s = (ksock_net_t *)f->driver_private;
            if (s->type_base != SOCK_DGRAM_LOCAL || s->protocol != IPPROTO_UDP_LOCAL) continue;
            if (s->local_port == 0 && !s->connected) continue;
            uint32_t lip_be = g_net.ready ? g_net.ip_be : 0u;
            uint32_t lhx = ip_be_to_proc_net_hex(lip_be);
            uint32_t rhx = s->connected ? ip_be_to_proc_net_hex(s->peer_ip_be) : 0u;
            uint32_t rp = s->connected ? (uint32_t)(s->peer_port & 0xFFFFu) : 0u;
            unsigned st = 7u;
            unsigned long inode = (unsigned long)(((unsigned)t->tid + 1u) * 100000u + (unsigned)fd + 50000u);
            n = snprintf((char *)buf + w, w < size ? size - w : 0,
                "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08X %08X %5d %8d %lu\n",
                sl++, lhx, (unsigned)(s->local_port & 0xFFFFu), rhx, rp, st,
                0u, 0u, 0u, 0u, 0u, (int)t->euid, 0, inode);
            if (n < 0) return (ssize_t)w;
            w += (size_t)n;
            if (w + 256 >= size) return (ssize_t)w;
        }
    }
    return (ssize_t)w;
}

ssize_t procfs_net_snap_tcp6(char *buf, size_t size) {
    if (!buf || size < 80) return 0;
    return (ssize_t)snprintf((char *)buf, size,
        "sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n");
}

ssize_t procfs_net_snap_udp6(char *buf, size_t size) {
    if (!buf || size < 80) return 0;
    return (ssize_t)snprintf((char *)buf, size,
        "sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops\n");
}

ssize_t procfs_net_snap_raw(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    return (ssize_t)snprintf((char *)buf, size,
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
}

ssize_t procfs_net_snap_raw6(char *buf, size_t size) {
    return procfs_net_snap_raw(buf, size);
}

ssize_t procfs_net_snap_unix(char *buf, size_t size) {
    if (!buf || size < 64) return 0;
    return (ssize_t)snprintf((char *)buf, size,
        "Num       RefCount Protocol Flags    Type St Inode Path\n");
}

typedef struct __attribute__((packed)) {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t sin_zero[8];
} sockaddr_in_k;

typedef struct __attribute__((packed)) {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t sin6_addr[16];
} sockaddr_in6_k;

/* connect/sendto: Linux glibc often passes AF_INET6 (v4-mapped or ::1). Returns 0 or errno. */
static int user_sockaddr_to_ipv4_peer(const void *addr_u, size_t addrlen, sockaddr_in_k *out) {
    if (!out) return EFAULT;
    if (!addr_u || addrlen < 2) return EFAULT;
    if (!user_range_ok(addr_u, addrlen)) return EFAULT;
    uint16_t fam = 0;
    if (copy_from_user_raw(&fam, addr_u, sizeof(fam)) != 0) return EFAULT;
    if (fam == 1) return ECONNREFUSED;
    if (fam == AF_INET_LOCAL) {
        if (addrlen < sizeof(sockaddr_in_k)) return EINVAL;
        if (copy_from_user_raw(out, addr_u, sizeof(*out)) != 0) return EFAULT;
        /* Trust sa_family at addr_u; glibc padding/quirks can leave sin_family != 2 in the copy. */
        out->sin_family = AF_INET_LOCAL;
        return 0;
    }
    if (fam == AF_INET6) {
        if (addrlen < sizeof(sockaddr_in6_k)) return EINVAL;
        sockaddr_in6_k s6;
        if (copy_from_user_raw(&s6, addr_u, sizeof(s6)) != 0) return EFAULT;
        int v4m = 1;
        for (int i = 0; i < 10; i++) {
            if (s6.sin6_addr[i]) v4m = 0;
        }
        if (s6.sin6_addr[10] != 0xff || s6.sin6_addr[11] != 0xff) v4m = 0;
        memset(out, 0, sizeof(*out));
        out->sin_family = AF_INET_LOCAL;
        out->sin_port = s6.sin6_port;
        if (v4m) {
            memcpy(&out->sin_addr, s6.sin6_addr + 12, 4);
            return 0;
        }
        int lo6 = 1;
        for (int i = 0; i < 15; i++) {
            if (s6.sin6_addr[i]) lo6 = 0;
        }
        if (lo6 && s6.sin6_addr[15] == 1) {
            out->sin_addr = 0x0100007Fu; /* 127.0.0.1 s_addr as on Linux LE */
            return 0;
        }
        /* No IPv6 stack: not EAFNOSUPPORT — glibc/wget treats that as fatal and may surface bogus OOM. */
        return ENETUNREACH;
    }
    /* Same as IPv6: avoid EAFNOSUPPORT so glibc can try other addresses / paths. */
    return ENETUNREACH;
}

typedef struct __attribute__((packed)) {
    uint16_t nl_family;
    uint16_t nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
} sockaddr_nl_k;

typedef struct __attribute__((packed)) {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
} nlmsghdr_k;

typedef struct __attribute__((packed)) {
    uint8_t rtgen_family;
} rtgenmsg_k;

typedef struct __attribute__((packed)) {
    uint8_t  ifi_family;
    uint8_t  __ifi_pad;
    uint16_t ifi_type;
    int32_t  ifi_index;
    uint32_t ifi_flags;
    uint32_t ifi_change;
} ifinfomsg_k;

typedef struct __attribute__((packed)) {
    uint8_t  ifa_family;
    uint8_t  ifa_prefixlen;
    uint8_t  ifa_flags;
    uint8_t  ifa_scope;
    uint32_t ifa_index;
} ifaddrmsg_k;

typedef struct __attribute__((packed)) {
    uint8_t rtm_family;
    uint8_t rtm_dst_len;
    uint8_t rtm_src_len;
    uint8_t rtm_tos;
    uint8_t rtm_table;
    uint8_t rtm_protocol;
    uint8_t rtm_scope;
    uint8_t rtm_type;
    uint32_t rtm_flags;
} rtmsg_k;

typedef struct __attribute__((packed)) {
    uint16_t rta_len;
    uint16_t rta_type;
} rtattr_k;

static inline size_t nl_align4(size_t n) { return (n + 3u) & ~3u; }

static int nl_append_blob(uint8_t *buf, size_t cap, size_t *off, const void *data, size_t len) {
    if (!buf || !off || !data) return -1;
    if (*off + len > cap) return -1;
    memcpy(buf + *off, data, len);
    *off += len;
    return 0;
}

static int nl_append_attr_u32(uint8_t *buf, size_t cap, size_t *off, uint16_t type, uint32_t v) {
    rtattr_k a;
    a.rta_len = (uint16_t)(sizeof(rtattr_k) + sizeof(uint32_t));
    a.rta_type = type;
    size_t start = *off;
    if (nl_append_blob(buf, cap, off, &a, sizeof(a)) != 0) return -1;
    if (nl_append_blob(buf, cap, off, &v, sizeof(v)) != 0) return -1;
    size_t need = nl_align4(*off - start);
    while ((*off - start) < need) {
        uint8_t z = 0;
        if (nl_append_blob(buf, cap, off, &z, 1) != 0) return -1;
    }
    return 0;
}

static int nl_append_attr_blob(uint8_t *buf, size_t cap, size_t *off, uint16_t type, const void *data, size_t data_len) {
    rtattr_k a;
    a.rta_len = (uint16_t)(sizeof(rtattr_k) + data_len);
    a.rta_type = type;
    size_t start = *off;
    if (nl_append_blob(buf, cap, off, &a, sizeof(a)) != 0) return -1;
    if (data_len && nl_append_blob(buf, cap, off, data, data_len) != 0) return -1;
    size_t need = nl_align4(*off - start);
    while ((*off - start) < need) {
        uint8_t z = 0;
        if (nl_append_blob(buf, cap, off, &z, 1) != 0) return -1;
    }
    return 0;
}

static int nl_msg_begin(uint8_t *buf, size_t cap, size_t *off, size_t *msg_start, uint16_t type, uint16_t flags, uint32_t seq, uint32_t pid) {
    if (!buf || !off || !msg_start) return -1;
    *msg_start = *off;
    nlmsghdr_k h;
    memset(&h, 0, sizeof(h));
    h.nlmsg_type = type;
    h.nlmsg_flags = flags;
    h.nlmsg_seq = seq;
    h.nlmsg_pid = pid;
    return nl_append_blob(buf, cap, off, &h, sizeof(h));
}

static int nl_msg_end(uint8_t *buf, size_t cap, size_t *off, size_t msg_start) {
    if (!buf || !off || msg_start > *off || msg_start + sizeof(nlmsghdr_k) > cap) return -1;
    size_t mlen = *off - msg_start;
    ((nlmsghdr_k *)(buf + msg_start))->nlmsg_len = (uint32_t)mlen;
    size_t need = nl_align4(mlen);
    while ((*off - msg_start) < need) {
        uint8_t z = 0;
        if (nl_append_blob(buf, cap, off, &z, 1) != 0) return -1;
    }
    return 0;
}

static int netlink_build_route_dump(ksock_net_t *s, uint16_t req_type, uint32_t seq) {
    if (!s) return -1;
    if (net_stack_init() != 0) return -1;
    enum {
        NLMSG_DONE_LOCAL = 3,
        NLM_F_MULTI_LOCAL = 0x2,
        RTM_NEWLINK_LOCAL = 16, RTM_GETLINK_LOCAL = 18,
        RTM_NEWADDR_LOCAL = 20, RTM_GETADDR_LOCAL = 22,
        RTM_NEWROUTE_LOCAL = 24, RTM_GETROUTE_LOCAL = 26,
        IFLA_ADDRESS_LOCAL = 1, IFLA_BROADCAST_LOCAL = 2, IFLA_IFNAME_LOCAL = 3, IFLA_MTU_LOCAL = 4,
        IFLA_LINK_LOCAL = 5, IFLA_QDISC_LOCAL = 6, IFLA_STATS_LOCAL = 7, IFLA_TXQLEN_LOCAL = 13,
        IFLA_OPERSTATE_LOCAL = 16, IFLA_LINKMODE_LOCAL = 17, IFLA_GROUP_LOCAL = 27,
        IFA_ADDRESS_LOCAL = 1, IFA_LOCAL_LOCAL = 2, IFA_LABEL_LOCAL = 3, IFA_FLAGS_LOCAL = 8,
        RTA_DST_LOCAL = 1, RTA_OIF_LOCAL = 4, RTA_GATEWAY_LOCAL = 5, RTA_PREFSRC_LOCAL = 7,
        /* Interface flags */
        IFF_UP_LOCAL = 0x1, IFF_BROADCAST_LOCAL = 0x2, IFF_LOOPBACK_LOCAL = 0x8,
        IFF_RUNNING_LOCAL = 0x40, IFF_NOARP_LOCAL = 0x80, IFF_LOWER_UP_LOCAL = 0x10000,
        IFF_MULTICAST_LOCAL = 0x1000
    };
    size_t off = 0;
    uint16_t msg_type = 0;
    if (req_type == RTM_GETLINK_LOCAL) msg_type = RTM_NEWLINK_LOCAL;
    else if (req_type == RTM_GETADDR_LOCAL) msg_type = RTM_NEWADDR_LOCAL;
    else if (req_type == RTM_GETROUTE_LOCAL) msg_type = RTM_NEWROUTE_LOCAL;
    else return -1;

    if (req_type == RTM_GETLINK_LOCAL) {
        /* Interface 1: lo (loopback) */
        size_t mstart = 0;
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        ifinfomsg_k ifi;
        memset(&ifi, 0, sizeof(ifi));
        ifi.ifi_family = 0; /* AF_UNSPEC */
        ifi.ifi_type = 772; /* ARPHRD_LOOPBACK */
        ifi.ifi_index = 1;
        ifi.ifi_flags = IFF_UP_LOCAL | IFF_LOOPBACK_LOCAL | IFF_RUNNING_LOCAL | IFF_LOWER_UP_LOCAL;
        ifi.ifi_change = 0xFFFFFFFFu;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &ifi, sizeof(ifi)) != 0) return -1;
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_IFNAME_LOCAL, "lo", 3) != 0) return -1;
        { uint32_t mtu = 65536; if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_MTU_LOCAL, mtu) != 0) return -1; }
        { uint32_t qlen = 1000; if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_TXQLEN_LOCAL, qlen) != 0) return -1; }
        { uint8_t state = 0; /* IF_OPER_UNKNOWN */ if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_OPERSTATE_LOCAL, &state, 1) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_QDISC_LOCAL, "noqueue", 8) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;

        /* Interface 2: eth0 */
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        memset(&ifi, 0, sizeof(ifi));
        ifi.ifi_family = 0; /* AF_UNSPEC */
        ifi.ifi_type = 1; /* ARPHRD_ETHER */
        ifi.ifi_index = 2;
        ifi.ifi_flags = IFF_UP_LOCAL | IFF_BROADCAST_LOCAL | IFF_RUNNING_LOCAL | IFF_MULTICAST_LOCAL | IFF_LOWER_UP_LOCAL;
        ifi.ifi_change = 0xFFFFFFFFu;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &ifi, sizeof(ifi)) != 0) return -1;
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_IFNAME_LOCAL, "eth0", 5) != 0) return -1;
        { uint32_t mtu = 1500; if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_MTU_LOCAL, mtu) != 0) return -1; }
        { uint32_t qlen = 1000; if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_TXQLEN_LOCAL, qlen) != 0) return -1; }
        { uint8_t state = 6; /* IF_OPER_UP */ if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_OPERSTATE_LOCAL, &state, 1) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_ADDRESS_LOCAL, g_net.mac, 6) != 0) return -1;
        { uint8_t brd[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_BROADCAST_LOCAL, brd, 6) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFLA_QDISC_LOCAL, "fq_codel", 9) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;
    } else if (req_type == RTM_GETADDR_LOCAL) {
        /* Address for lo: 127.0.0.1/8 */
        size_t mstart = 0;
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        ifaddrmsg_k ifa;
        memset(&ifa, 0, sizeof(ifa));
        ifa.ifa_family = AF_INET_LOCAL;
        ifa.ifa_prefixlen = 8;
        ifa.ifa_scope = 254; /* RT_SCOPE_HOST */
        ifa.ifa_index = 1;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &ifa, sizeof(ifa)) != 0) return -1;
        { uint32_t ip = 0x0100007Fu; /* 127.0.0.1 in little-endian for network order */
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_ADDRESS_LOCAL, &ip, 4) != 0) return -1;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_LOCAL_LOCAL, &ip, 4) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_LABEL_LOCAL, "lo", 3) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;

        /* Address for eth0 */
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        memset(&ifa, 0, sizeof(ifa));
        ifa.ifa_family = AF_INET_LOCAL;
        ifa.ifa_prefixlen = (uint8_t)ip_mask_prefix_len(g_net.mask_be ? g_net.mask_be : 0xFFFFFF00u);
        ifa.ifa_scope = 0; /* RT_SCOPE_UNIVERSE */
        ifa.ifa_index = 2;
        ifa.ifa_flags = 0x80; /* IFA_F_PERMANENT */
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &ifa, sizeof(ifa)) != 0) return -1;
        { uint32_t ip = be32(g_net.ip_be);
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_ADDRESS_LOCAL, &ip, 4) != 0) return -1;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_LOCAL_LOCAL, &ip, 4) != 0) return -1; }
        { uint32_t brd = be32((g_net.ip_be & g_net.mask_be) | ~g_net.mask_be);
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, 4 /* IFA_BROADCAST */, &brd, 4) != 0) return -1; }
        if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, IFA_LABEL_LOCAL, "eth0", 5) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;
    } else {
        size_t mstart = 0;
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        rtmsg_k rm;
        memset(&rm, 0, sizeof(rm));
        rm.rtm_family = AF_INET_LOCAL;
        rm.rtm_table = 254;
        rm.rtm_protocol = 3;
        rm.rtm_scope = 0;
        rm.rtm_type = 1;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &rm, sizeof(rm)) != 0) return -1;
        { uint32_t gw = be32(g_net.gw_be); uint32_t oif = 2;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, RTA_GATEWAY_LOCAL, &gw, 4) != 0) return -1;
          if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, RTA_OIF_LOCAL, oif) != 0) return -1; }
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;

        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, msg_type, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        memset(&rm, 0, sizeof(rm));
        rm.rtm_family = AF_INET_LOCAL;
        rm.rtm_dst_len = (uint8_t)ip_mask_prefix_len(g_net.mask_be ? g_net.mask_be : 0xFFFFFF00u);
        rm.rtm_table = 254;
        rm.rtm_protocol = 2;
        rm.rtm_scope = 253;
        rm.rtm_type = 1;
        if (nl_append_blob(s->nl_rx, sizeof(s->nl_rx), &off, &rm, sizeof(rm)) != 0) return -1;
        { uint32_t dst = be32(g_net.ip_be & (g_net.mask_be ? g_net.mask_be : 0xFFFFFF00u));
          uint32_t src = be32(g_net.ip_be); uint32_t oif = 2;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, RTA_DST_LOCAL, &dst, 4) != 0) return -1;
          if (nl_append_attr_u32(s->nl_rx, sizeof(s->nl_rx), &off, RTA_OIF_LOCAL, oif) != 0) return -1;
          if (nl_append_attr_blob(s->nl_rx, sizeof(s->nl_rx), &off, RTA_PREFSRC_LOCAL, &src, 4) != 0) return -1; }
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;
    }

    {
        size_t mstart = 0;
        if (nl_msg_begin(s->nl_rx, sizeof(s->nl_rx), &off, &mstart, NLMSG_DONE_LOCAL, NLM_F_MULTI_LOCAL, seq, s->nl_pid) != 0) return -1;
        if (nl_msg_end(s->nl_rx, sizeof(s->nl_rx), &off, mstart) != 0) return -1;
    }
    s->nl_rx_len = off;
    s->nl_rx_off = 0;
    return 0;
}

static uint64_t last_syscall_debug = 0;
static inline int is_watch_proc(thread_t *t) {
    if (!t || !t->name[0]) return 0;
    const char *nm = t->name;
    /* BusyBox is a multicall binary: applets often run with name "busybox". */
    return (strstr(nm, "busybox") || strstr(nm, "wget") || strstr(nm, "adduser") || strstr(nm, "addgroup")) ? 1 : 0;
}

static inline int path_is_passwdish(const char *p) {
    if (!p) return 0;
    /* BusyBox update_passwd uses suffixes: /etc/passwd+, /etc/passwd- */
    return (strncmp(p, "/etc/passwd", 11) == 0) ||
           (strncmp(p, "/etc/group", 10) == 0) ||
           (strncmp(p, "/etc/shadow", 11) == 0) ||
           (strncmp(p, "/etc/gshadow", 12) == 0);
}

/* Syscall trace for debugging multicall userland (BusyBox). */
static int g_syscall_trace_on = 1;
static int g_syscall_trace_budget = 4000;
static inline int syscall_trace_pick(uint64_t num) {
    /* Keep this tight: only the syscalls that explain "hang" or "can't create user". */
    switch ((int)num) {
        case 0:  /* read */
        case 1:  /* write */
        case 3:  /* close */
        case 9:  /* mmap */
        case 10: /* mprotect */
        case 11: /* munmap */
        case 12: /* brk */
        case 16: /* ioctl */
        case 23: /* select */
        case 35: /* nanosleep */
        case 42: /* connect */
        case 57: /* fork */
        case 59: /* execve */
        case 60: /* exit */
        case 61: /* wait4 */
        case 72: /* fcntl */
        case 78: /* getdents */
        case 79: /* getcwd */
        case 87: /* unlink */
        case 89: /* readlink */
        case 97: /* getrlimit */
        case 158:/* arch_prctl */
        case 202:/* futex */
        case 231:/* exit_group */
        case 217:/* getdents64 */
        case 257:/* openat */
        case 258:/* mkdirat */
        case 259:/* mknodat */
        case 260:/* fchownat */
        case 262:/* newfstatat */
        case 263:/* unlinkat */
        case 264:/* renameat */
        case 265:/* linkat */
        case 268:/* fchmodat */
        case 271:/* ppoll */
        case 7:  /* poll */
            return 1;
        default:
            return 0;
    }
}
static inline uint64_t ret_err(int e) {
    /* Temporary diagnostics for userland failures (wget, adduser, addgroup). */
    thread_t *t = thread_get_current_user();
    if (!t) t = thread_current();
    if (t && t->name[0]) {
        const char *nm = t->name;
        int watch = 0;
        if (strstr(nm, "wget")) watch = 1;
        else if (strstr(nm, "addgroup")) watch = 1;
        else if (strstr(nm, "adduser")) watch = 1;
        if (watch) {
            /* close(3) + EBADF: часто двойной close в glibc при обходе резолвера — не путать с корнем ошибки. */
            if (last_syscall_debug == 3u && e == EBADF)
                return (uint64_t)(-(int64_t)e);
            kprintf("SYSCALL-ERR: syscall=%llu errno=%d pid=%s\n",
                (unsigned long long)last_syscall_debug, e, nm);
            qemu_debug_printf("SYSCALL-ERR: syscall=%llu err=%d tid=%llu name=%s brk=0x%llx mmap_next=0x%llx\n",
                (unsigned long long)last_syscall_debug,
                e,
                (unsigned long long)(t->tid ? t->tid : 1),
                nm,
                (unsigned long long)(uint64_t)t->user_brk_cur,
                (unsigned long long)(uint64_t)t->user_mmap_next);
        }
    }
    if (e == ENOMEM) {
        oom_serial_notify(last_syscall_debug, (t && t->name[0]) ? t->name : 0);
        kprintf("ENOMEM: syscall=%llu name=%s heap_used=%llu heap_total=%llu\n",
            (unsigned long long)last_syscall_debug,
            (t && t->name[0]) ? t->name : "(null)",
            (unsigned long long)heap_used_bytes(),
            (unsigned long long)heap_total_bytes());
        qemu_debug_printf("ENOMEM: syscall=%llu tid=%llu name=%s brk=0x%llx mmap_next=0x%llx heap_used=%llu heap_total=%llu heap_peak=%llu\n",
            (unsigned long long)last_syscall_debug,
            (unsigned long long)(t ? (t->tid ? t->tid : 1) : 0),
            (t && t->name[0]) ? t->name : "(null)",
            (unsigned long long)(t ? (uint64_t)t->user_brk_cur : 0),
            (unsigned long long)(t ? (uint64_t)t->user_mmap_next : 0),
            (unsigned long long)heap_used_bytes(),
            (unsigned long long)heap_total_bytes(),
            (unsigned long long)heap_peak_bytes());
    }
    return (uint64_t)(-(int64_t)e);
}

/* minimal signal numbers used */
#ifndef SIGCHLD
#define SIGCHLD 17
#endif
#ifndef SIGALRM
#define SIGALRM 14
#endif
#ifndef SIGINT
#define SIGINT 2
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
    const char *path = path_u;
    char path_local[256];
    if (path_u && user_range_ok(path_u, 1)) {
        size_t L = user_strnlen_bounded(path_u, sizeof(path_local) - 1);
        if (!user_range_ok(path_u, L + 1) || copy_from_user_raw(path_local, path_u, L + 1) != 0) {
            strncpy(out, "/", out_cap);
            out[out_cap - 1] = '\0';
            return;
        }
        path_local[L] = '\0';
        path = path_local;
    }
    if (!path || !path[0]) {
        strncpy(out, "/", out_cap);
        out[out_cap - 1] = '\0';
        return;
    }
    const char *cwd = (cur && cur->cwd[0]) ? cur->cwd : "/";
    if (path[0] == '/') {
        strncpy(out, path, out_cap);
        out[out_cap - 1] = '\0';
        if (path_needs_normalize(out)) normalize_path(out, out_cap);
        return;
    }
    /* "." means current directory. */
    if (strcmp(path, ".") == 0) {
        strncpy(out, cwd, out_cap);
        out[out_cap - 1] = '\0';
        return;
    }
    /* ".." means parent directory. */
    if (strcmp(path, "..") == 0) {
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
        snprintf(out, out_cap, "/%s", path);
    } else {
        snprintf(out, out_cap, "%s/%s", cwd, path);
    }
    if (path_needs_normalize(out)) normalize_path(out, out_cap);
}

/* Resolve path for openat: dirfd base or cwd. Returns 0 on success, negative errno on error. */
static int resolve_user_path_at(thread_t *cur, int dirfd, const char *path_u, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return -EFAULT;
    out[0] = '\0';
    const char *path = path_u;
    char path_local[256];
    if (path_u && user_range_ok(path_u, 1)) {
        size_t L = user_strnlen_bounded(path_u, sizeof(path_local) - 1);
        if (!user_range_ok(path_u, L + 1) || copy_from_user_raw(path_local, path_u, L + 1) != 0) return -EFAULT;
        path_local[L] = '\0';
        path = path_local;
    }
    if (!path || !path[0]) return -ENOENT;
    /* Absolute path: dirfd ignored, use standard resolve */
    if (path[0] == '/') {
        resolve_user_path(cur, path, out, out_cap);
        return 0;
    }
    /* AT_FDCWD = -100: use current working directory */
    enum { AT_FDCWD = -100 };
    if (dirfd == AT_FDCWD) {
        resolve_user_path(cur, path, out, out_cap);
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
    size_t pl = strlen(path);
    if (has_trailing) {
        snprintf(out, out_cap, "%s%s", base, path);
    } else {
        snprintf(out, out_cap, "%s/%s", base, path);
    }
    out[out_cap - 1] = '\0';
    if (path_needs_normalize(out)) normalize_path(out, out_cap);
    return 0;
}

static int copy_to_user_safe(void *uptr, const void *kptr, size_t n) {
    if (!uptr || !kptr) return -1;
    if (n == 0) return 0;
    thread_t *t = uaccess_thread();
    if (uaccess_arm(t, uptr, n, &&fault, 0) != 0) return -1;
    volatile uint8_t *dst = (volatile uint8_t *)uptr;
    const uint8_t *src = (const uint8_t *)kptr;
    for (size_t i = 0; i < n; i++) dst[i] = src[i];
    uaccess_clear(t);
    return 0;
fault:
    uaccess_clear(t);
    return -1;
}

static int copy_from_user_raw(void *kdst, const void *usrc, size_t n) {
    if (!kdst || !usrc) return -1;
    if (n == 0) return 0;
    thread_t *t = uaccess_thread();
    if (uaccess_arm(t, usrc, n, &&fault, 0) != 0) return -1;
    uint8_t *dst = (uint8_t *)kdst;
    const volatile uint8_t *src = (const volatile uint8_t *)usrc;
    for (size_t i = 0; i < n; i++) dst[i] = src[i];
    uaccess_clear(t);
    return 0;
fault:
    uaccess_clear(t);
    return -1;
}

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

static inline int user_recv_range_ok(const void *uaddr, size_t nbytes) {
    if (!uaddr) return 0;
    if (nbytes == 0) return 1;
    uintptr_t start = (uintptr_t)uaddr;
    uintptr_t end = start + nbytes;
    if (end < start) return 0;
    if (start < 0x00200000u) return 0;
    if (end > (uintptr_t)MMIO_IDENTITY_LIMIT) return 0;
    return 1;
}

static int copy_to_user_recv_safe(void *uptr, const void *kptr, size_t n) {
    if (!uptr || !kptr) return -1;
    if (n == 0) return 0;
    thread_t *t = uaccess_thread();
    if (uaccess_arm(t, uptr, n, &&fault, 1) != 0) return -1;
    volatile uint8_t *dst = (volatile uint8_t *)uptr;
    const uint8_t *src = (const uint8_t *)kptr;
    for (size_t i = 0; i < n; i++) dst[i] = src[i];
    uaccess_clear(t);
    return 0;
fault:
    uaccess_clear(t);
    return -1;
}

static int user_read_u64(const void *uaddr, uint64_t *out) {
    if (!out) return -1;
    if (!user_range_ok(uaddr, sizeof(uint64_t))) return -1;
    /* copy to avoid alignment surprises */
    if (copy_from_user_raw(out, uaddr, sizeof(uint64_t)) != 0) return -1;
    return 0;
}

static int user_write_u64(void *uaddr, uint64_t value) {
    return copy_to_user_safe(uaddr, &value, sizeof(value));
}

static int user_write_u8(void *uaddr, uint8_t value) {
    return copy_to_user_safe(uaddr, &value, sizeof(value));
}

static size_t user_strnlen_bounded(const char *s, size_t max) {
    if (!s) return 0;
    if (max == 0) return 0;
    thread_t *t = uaccess_thread();
    if (uaccess_arm(t, s, max, &&fault, 0) != 0) return max;
    const volatile char *p = (const volatile char *)s;
    for (size_t i = 0; i < max; i++) {
        if (p[i] == '\0') {
            uaccess_clear(t);
            return i;
        }
    }
    uaccess_clear(t);
    return max;
fault:
    uaccess_clear(t);
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

/* Signal delivery: handlers, restorers, and per-thread mask. */
typedef void (*user_sighandler_t)(int);
#define SA_SIGINFO 0x4
#define SIG_DFL ((user_sighandler_t)0)
#define SIG_IGN ((user_sighandler_t)1)
typedef struct {
    user_sighandler_t handler;
    uint64_t restorer;   /* glibc passes __restore_rt; we need it for sigreturn */
    uint64_t flags;      /* SA_SIGINFO etc. */
} user_sigaction_t;
static user_sigaction_t user_sig_actions[65]; /* 1..64 */
/* Legacy global mask; rt_sigprocmask uses per-thread saved_sig_mask when available */
static uint64_t user_sig_mask = 0;
/* Compatibility shim for tools (e.g. ping) that expect periodic SIGALRM. */
static uint32_t user_itimer_interval_ms = 0;

/* write()/writev() on sockets: glibc DNS may use writev; fs_write() does not handle SYSCALL_FTYPE_SOCKET. */
static ssize_t net_sock_write_userspace(thread_t *cur, int fd, ksock_net_t *s, const void *bufp, size_t cnt) {
    static int tcp_wr_dbg_left = 16;
    if (!s) return -EINVAL;
    if (s->unix_domain_stub) {
        if (!bufp || cnt == 0) return -EINVAL;
        if (!user_range_ok(bufp, cnt)) return -EFAULT;
        return (ssize_t)cnt;
    }
    if (s->sock_domain == AF_NETLINK_LOCAL) {
        if (!bufp || cnt == 0) return -EINVAL;
        if (cnt < sizeof(nlmsghdr_k) || !user_range_ok(bufp, cnt)) return -EFAULT;
        uint8_t pkt[256];
        size_t cp = (cnt > sizeof(pkt)) ? sizeof(pkt) : cnt;
        if (copy_from_user_raw(pkt, bufp, cp) != 0) return -EFAULT;
        nlmsghdr_k *h = (nlmsghdr_k *)pkt;
        if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > cnt) return -EINVAL;
        if (s->nl_pid == 0) s->nl_pid = (uint32_t)((cur && cur->tid) ? cur->tid : 1);
        (void)netlink_build_route_dump(s, h->nlmsg_type, h->nlmsg_seq);
        return (ssize_t)cnt;
    }
    if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
        if (s->dns_tcp_udp_bridge) {
            if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
            if (!s->connected) return -EDESTADDRREQ;
            if (cnt > 2048) return -EINVAL;
            if (s->local_port == 0)
                s->local_port = net_alloc_ephemeral_port();
            uint8_t *payload = (uint8_t *)kmalloc(cnt);
            if (!payload) return -ENOMEM;
            if (copy_from_user_raw(payload, bufp, cnt) != 0) {
                kfree(payload);
                return -EFAULT;
            }
            int r = net_send_udp_datagram(s->peer_ip_be, s->local_port, s->peer_port, payload, cnt);
            kfree(payload);
            if (r != 0) return (ssize_t)(e1000_is_ready() ? -EIO : -ENETDOWN);
            return (ssize_t)cnt;
        }
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        size_t total = 0;
        net_tcp_ops_t ops;
        net_make_tcp_ops(&ops);
        if (tcp_wr_dbg_left-- > 0) {
            klogprintf("tcp: write fd=%d cnt=%u dst=%u.%u.%u.%u:%u\n",
                fd, (unsigned)cnt,
                (unsigned)((s->peer_ip_be >> 24) & 0xFF), (unsigned)((s->peer_ip_be >> 16) & 0xFF),
                (unsigned)((s->peer_ip_be >> 8) & 0xFF), (unsigned)(s->peer_ip_be & 0xFF),
                (unsigned)s->peer_port);
        }
        while (total < cnt) {
            size_t chunk = cnt - total;
            if (chunk > 4096) chunk = 4096;
            uint8_t *tmp = (uint8_t *)kmalloc(chunk);
            if (!tmp) return (ssize_t)((total > 0) ? (ssize_t)total : -ENOMEM);
            if (copy_from_user_raw(tmp, (const uint8_t *)bufp + total, chunk) != 0) {
                kfree(tmp);
                return (ssize_t)((total > 0) ? (ssize_t)total : -EFAULT);
            }
            int wr = net_tcp_send(&s->tcp, &ops, tmp, chunk, 30000);
            kfree(tmp);
            if (wr < 0) {
                if (tcp_wr_dbg_left >= 0) klogprintf("tcp: write net_tcp_send failed wr=%d total=%u\n", wr, (unsigned)total);
                return (ssize_t)((total > 0) ? (ssize_t)total : -EIO);
            }
            total += (size_t)wr;
            if ((size_t)wr < chunk) break;
        }
        return (ssize_t)total;
    }
    if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        if (!s->connected) return -EDESTADDRREQ;
        if (cnt > 2048) return -EINVAL;
        if (s->local_port == 0)
            s->local_port = net_alloc_ephemeral_port();
        uint8_t *payload = (uint8_t *)kmalloc(cnt);
        if (!payload) return -ENOMEM;
        if (copy_from_user_raw(payload, bufp, cnt) != 0) {
            kfree(payload);
            return -EFAULT;
        }
        int r = net_send_udp_datagram(s->peer_ip_be, s->local_port, s->peer_port, payload, cnt);
        kfree(payload);
        if (r != 0) return (ssize_t)(e1000_is_ready() ? -EIO : -ENETDOWN);
        return (ssize_t)cnt;
    }
    return -EINVAL;
}

/* read()/readv() on sockets; readv uses repeated calls (UDP rx_pending_off preserves datagram). */
static ssize_t net_sock_read_userspace(thread_t *cur, ksock_net_t *s, void *bufp, size_t cnt) {
    (void)cur;
    if (!s) return -EINVAL;
    if (s->unix_domain_stub) {
        if (cnt == 0) return 0;
        if (!bufp || !user_range_ok(bufp, cnt)) return -EFAULT;
        return 0;
    }
    if (s->sock_domain == AF_NETLINK_LOCAL) {
        if (cnt == 0) return 0;
        if (!bufp || !user_range_ok(bufp, cnt)) return -EFAULT;
        if (s->nl_rx_off >= s->nl_rx_len) return -EAGAIN;
        size_t avail = s->nl_rx_len - s->nl_rx_off;
        size_t ncopy = (avail > cnt) ? cnt : avail;
        if (copy_to_user_safe(bufp, s->nl_rx + s->nl_rx_off, ncopy) != 0) return -EFAULT;
        s->nl_rx_off += ncopy;
        return (ssize_t)ncopy;
    }
    if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
        if (s->dns_tcp_udp_bridge) {
            if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
            size_t cap = cnt > 8192 ? 8192 : cnt;
            uint8_t *utmp = (uint8_t *)kmalloc(cap);
            if (!utmp) return -ENOMEM;
            if (!s->rx_has_pending) {
                int pr = net_udp_recv_into_pending(s);
                if (pr != 1) {
                    kfree(utmp);
                    if (pr == 0) return (ssize_t)(s->nonblock ? -EAGAIN : -ETIMEDOUT);
                    return -EIO;
                }
            }
            int n = 0;
            ksock_rx_pending_normalize(s);
            if (s->rx_has_pending) {
                size_t avail = ksock_rx_pending_avail(s);
                n = (int)((avail > cap) ? cap : avail);
                if (n > 0) memcpy(utmp, s->rx_pending + s->rx_pending_off, (size_t)n);
                s->rx_pending_off += (size_t)n;
                if (s->rx_pending_off >= s->rx_pending_len) {
                    s->rx_has_pending = 0;
                    s->rx_pending_off = 0;
                    s->rx_pending_len = 0;
                }
            }
            if (n > 0 && copy_to_user_safe(bufp, utmp, (size_t)n) != 0) {
                kfree(utmp);
                return -EFAULT;
            }
            kfree(utmp);
            if (n <= 0) return -EAGAIN;
            return (ssize_t)n;
        }
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        net_tcp_ops_t ops;
        net_make_tcp_ops(&ops);
        size_t chunk = cnt;
        if (chunk > 4096) chunk = 4096;
        uint8_t *tmp = (uint8_t *)kmalloc(chunk);
        if (!tmp) return -ENOMEM;
        int rr = net_tcp_recv(&s->tcp, &ops, tmp, chunk, 60000);
        if (rr > 0) {
            if (copy_to_user_safe(bufp, tmp, (size_t)rr) != 0) {
                kfree(tmp);
                return -EFAULT;
            }
            kfree(tmp);
            return (ssize_t)rr;
        }
        kfree(tmp);
        if (rr == 0) return 0;
        return (ssize_t)((rr == -2) ? -ETIMEDOUT : -EAGAIN);
    }
    if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        size_t cap = cnt > 8192 ? 8192 : cnt;
        uint8_t *tmp = (uint8_t *)kmalloc(cap);
        if (!tmp) return -ENOMEM;
        if (!s->rx_has_pending) {
            int pr = net_udp_recv_into_pending(s);
            if (pr != 1) {
                kfree(tmp);
                if (pr == 0) return (ssize_t)(s->nonblock ? -EAGAIN : -ETIMEDOUT);
                return -EIO;
            }
        }
        int n = 0;
        ksock_rx_pending_normalize(s);
        if (s->rx_has_pending) {
            size_t avail = ksock_rx_pending_avail(s);
            n = (int)((avail > cap) ? cap : avail);
            if (n > 0) memcpy(tmp, s->rx_pending + s->rx_pending_off, (size_t)n);
            s->rx_pending_off += (size_t)n;
            if (s->rx_pending_off >= s->rx_pending_len) {
                s->rx_has_pending = 0;
                s->rx_pending_off = 0;
                s->rx_pending_len = 0;
            }
        }
        if (n > 0 && copy_to_user_safe(bufp, tmp, (size_t)n) != 0) {
            kfree(tmp);
            return -EFAULT;
        }
        kfree(tmp);
        if (n <= 0) return -EAGAIN;
        return (ssize_t)n;
    }
    if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_ICMP_LOCAL) {
        if (!bufp || cnt == 0 || !user_range_ok(bufp, cnt)) return -EFAULT;
        size_t cap = cnt > 8192 ? 8192 : cnt;
        uint8_t *tmp = (uint8_t *)kmalloc(cap);
        if (!tmp) return -ENOMEM;
        uint32_t timeout_ms = user_itimer_interval_ms ? user_itimer_interval_ms : 2500u;
        int n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, NULL);
        if (n < 0) {
            kfree(tmp);
            return -EIO;
        }
        if (n == 0) {
            kfree(tmp);
            return -ETIMEDOUT;
        }
        if (copy_to_user_safe(bufp, tmp, (size_t)n) != 0) {
            kfree(tmp);
            return -EFAULT;
        }
        kfree(tmp);
        return (ssize_t)n;
    }
    return -EINVAL;
}

/* Linux x86_64 rt_sigframe layout for signal delivery. */
#pragma pack(push, 1)
typedef struct {
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rdi, rsi, rbp, rbx, rdx, rax, rcx;
    uint64_t rsp, rip, eflags;
    uint16_t cs, gs, fs;
    uint16_t ss;
    uint64_t err, trapno, oldmask, cr2;
    uint64_t fpstate;
    uint64_t reserved1[8];
} k_sigcontext_t;
typedef struct {
    uint64_t uc_flags;
    uint64_t uc_link;
    uint64_t uc_stack_ss_sp, uc_stack_ss_size;
    uint32_t uc_stack_ss_flags, uc_pad;
    uint64_t uc_sigmask[2];
    k_sigcontext_t uc_mcontext;
} k_ucontext_t;
#pragma pack(pop)
#define RT_SIGFRAME_UC_OFF  8
#define RT_SIGFRAME_SIZE   (8 + sizeof(k_ucontext_t))

static int mark_user_identity_range_2m_sys(uint64_t va_begin, uint64_t va_end);

/* Build signal frame and patch syscall return for delivery. Called from syscall_entry64. */
int maybe_deliver_pending_signal(void) {
    thread_t *cur = thread_get_current_user();
    if (!cur) cur = thread_current();
    if (!cur || cur->ring != 3) return 0;
    uint64_t blocked = cur->saved_sig_mask;
    uint64_t pending = cur->pending_signals & ~blocked;
    if (!pending) return 0;
    int sig = 0;
    for (int s = 1; s <= 63 && !sig; s++) {
        if (pending & (1ULL << (s - 1))) sig = s;
    }
    if (sig <= 0) return 0;
    user_sigaction_t *sa = &user_sig_actions[sig];
    user_sighandler_t h = sa->handler;
    uint64_t restorer = sa->restorer;
    if (h == SIG_IGN) {
        cur->pending_signals &= ~(1ULL << (sig - 1));
        return maybe_deliver_pending_signal();
    }
    if (h == SIG_DFL) {
        cur->pending_signals &= ~(1ULL << (sig - 1));
        /* Default action Term: terminate process (SIGINT, SIGQUIT, SIGTERM, SIGPIPE, etc.).
           Process must actually exit so parent's wait() returns and shell gets control back. */
        if (sig == SIGINT || sig == 3 /*SIGQUIT*/ || sig == 15 /*SIGTERM*/ || sig == 13 /*SIGPIPE*/) {
            cur->exit_status = sig; /* WIFSIGNALED, WTERMSIG = sig */
            for (int i = 0; i < THREAD_MAX_FD; i++) {
                if (cur->fds[i]) {
                    struct fs_file *f = cur->fds[i];
                    cur->fds[i] = NULL;
                    fs_file_free(f);
                }
            }
            thread_yield(); /* let pipe reader run before waking parent */
            if (cur->parent_tid >= 0) {
                thread_t *pt = thread_get(cur->parent_tid);
                if (pt) {
                    thread_set_pending_signal(pt, SIGCHLD);
                    if (cur->attached_tty >= 0 && pt->attached_tty == cur->attached_tty)
                        devfs_set_tty_fg_pgrp(cur->attached_tty, pt->pgid);
                }
            }
            if (cur->vfork_parent_tid >= 0) {
                vfork_restore_parent_memory(cur);
                vfork_restore_parent_stack(cur);
                thread_unblock(cur->vfork_parent_tid);
                cur->vfork_parent_tid = -1;
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
            if (cur->mm && cur->mm != mm_kernel()) {
                mm_release(cur->mm);
                cur->mm = mm_kernel();
            }
            thread_yield();
            for (;;) asm volatile("sti; hlt" ::: "memory");
        }
        return maybe_deliver_pending_signal();
    }
    if (!restorer) return 0;
    uint64_t old_rsp = cur->saved_user_rsp;
    uint64_t old_rip = cur->saved_user_rip;
    if (!old_rsp || !old_rip) return 0;
    uintptr_t frame_start = ((uintptr_t)old_rsp - RT_SIGFRAME_SIZE) & ~15ULL;
    if (frame_start < 0x200000ULL) return 0;
    if (mark_user_identity_range_2m_sys((uint64_t)frame_start, (uint64_t)(frame_start + RT_SIGFRAME_SIZE)) != 0)
        return 0;
    k_ucontext_t uc;
    memset(&uc, 0, sizeof(uc));
    uc.uc_mcontext.r8  = cur->saved_user_r8;
    uc.uc_mcontext.r9  = cur->saved_user_r9;
    uc.uc_mcontext.r10 = cur->saved_user_r10;
    uc.uc_mcontext.r11 = cur->saved_user_r11;
    uc.uc_mcontext.r12 = cur->saved_user_r12;
    uc.uc_mcontext.r13 = cur->saved_user_r13;
    uc.uc_mcontext.r14 = cur->saved_user_r14;
    uc.uc_mcontext.r15 = cur->saved_user_r15;
    uc.uc_mcontext.rdi = cur->saved_user_rdi;
    uc.uc_mcontext.rsi = cur->saved_user_rsi;
    uc.uc_mcontext.rbp = cur->saved_user_rbp;
    uc.uc_mcontext.rbx = cur->saved_user_rbx;
    uc.uc_mcontext.rdx = cur->saved_user_rdx;
    uc.uc_mcontext.rax = syscall_user_return_rax;
    uc.uc_mcontext.rcx = cur->saved_user_rcx;
    uc.uc_mcontext.rsp = old_rsp;
    uc.uc_mcontext.rip = old_rip;
    uc.uc_mcontext.eflags = cur->saved_user_r11;
    uc.uc_mcontext.cs = 0x1B;
    uc.uc_mcontext.gs = 0;
    uc.uc_mcontext.fs = 0;
    uc.uc_mcontext.ss = 0x23;
    uc.uc_sigmask[0] = blocked;
    if (copy_to_user_safe((void *)(uintptr_t)(frame_start + RT_SIGFRAME_UC_OFF), &uc, sizeof(uc)) != 0)
        return 0;
    if (copy_to_user_safe((void *)(uintptr_t)frame_start, &restorer, sizeof(restorer)) != 0)
        return 0;
    cur->pending_signals &= ~(1ULL << (sig - 1));
    uint64_t *frame = cur->saved_syscall_frame;
    if (!frame) return 0;
    frame[8]  = (uint64_t)sig;
    frame[13] = (uint64_t)(uintptr_t)h;
    frame[15] = (uint64_t)frame_start;
    syscall_user_rsp_saved = (uint64_t)frame_start;
    asm volatile("mfence" ::: "memory");
    return 1;
}

/* Simple getrandom() state (non-crypto). */
static uint32_t user_rand_state = 0xA53C9E11u;

/* Very small user VM allocator (identity-mapped).
   We keep it below the user stack region and below the kernel heap floor. */
static uintptr_t user_mmap_next = 0;
static uintptr_t user_mmap_hi = 0;
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
        /* Reset mmap cursor on exec so new program gets fresh mmap region below top_limit.
           Parent (sh) may have bumped user_mmap_next above heap_lo (64 MiB), causing
           ENOMEM for child (wget) on first mmap. */
        tcur->user_mmap_next = 0;
        tcur->user_mmap_hi = 0;
    } else {
        user_brk_base = base;
        user_brk_cur = base;
        user_mmap_next = 0;
        user_mmap_hi = 0;
    }
}

int fault_try_grow_user_heap(uint64_t cr2) {
    thread_t *tcur = thread_get_current_user();
    if (!tcur) tcur = thread_current();
    if (!tcur) return 0;
    uintptr_t brk_base = tcur->user_brk_base;
    uintptr_t brk_cur = tcur->user_brk_cur;
    if (brk_base == 0) brk_base = brk_cur = 8u * 1024u * 1024u;
    uintptr_t top_limit = (uintptr_t)USER_TLS_BASE;
    uintptr_t tls_base = user_tls_base_for_tid_local(tcur->tid);
    if (tls_base > 0x200000 && tls_base < (uintptr_t)MMIO_IDENTITY_LIMIT)
        top_limit = tls_base;
    uintptr_t heap_lo = (uintptr_t)heap_base_addr();
    if (heap_lo > brk_base && heap_lo < top_limit) {
        uintptr_t guard = 0x10000u;
        top_limit = (heap_lo > guard) ? (heap_lo - guard) : heap_lo;
    }
    uintptr_t page_va = (uintptr_t)cr2 & ~((uintptr_t)PAGE_SIZE_2M - 1);
    /* Heap and lazy brk live only in low canonical identity map. Faults at high
     * canonical addresses (e.g. 0xffffffffffe00000) come from corrupted malloc state;
     * treating them as brk growth would memset() outside the identity map and #PF in CPL0.
     * Also reject unsigned wrap on page_va + PAGE_SIZE_2M. */
    if (page_va >= (uintptr_t)MMIO_IDENTITY_LIMIT) return 0;
    if (page_va + PAGE_SIZE_2M < page_va) return 0;
    if (page_va < brk_base || page_va + PAGE_SIZE_2M > top_limit) return 0;
    if (page_va < brk_cur) return 0; /* should already be mapped */
    if (map_page_2m(page_va, page_va, PG_PRESENT | PG_RW | PG_US) != 0) return 0;
    memset((void*)(uintptr_t)page_va, 0, PAGE_SIZE_2M);
    if (page_va + PAGE_SIZE_2M > brk_cur)
        tcur->user_brk_cur = page_va + PAGE_SIZE_2M;
    return 1;
}

static inline uintptr_t align_up_u(uintptr_t v, uintptr_t a) { return (v + (a - 1)) & ~(a - 1); }

/* Unmap [va_begin, va_end) in current CR3. Clears PTE so user access faults.
   Range must be page-aligned and within user identity map. */
static int unmap_user_range_sys(uint64_t va_begin, uint64_t va_end) {
    if (va_end < va_begin) return -1;
    if (va_begin >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t begin = va_begin & ~0xFFFULL;
    uint64_t end = (va_end + 0xFFFULL) & ~0xFFFULL;
    uint64_t cr3 = paging_read_cr3();
    uint64_t *l4 = (uint64_t*)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!l4) return -1;
    for (uint64_t va = begin; va < end; va += 0x1000ULL) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        uint64_t l1i = (va >> 12) & 0x1FF;
        if (!(l4[l4i] & PG_PRESENT)) continue;
        uint64_t *l3 = (uint64_t*)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) continue;
        uint64_t l3e = l3[l3i];
        if (l3e & PG_PS_2M) continue; /* 1G page; cannot partially unmap */
        uint64_t l2_phys = l3e & ~0xFFFULL;
        uint64_t *l2 = (uint64_t*)(uintptr_t)l2_phys;
        if (!(l2[l2i] & PG_PRESENT)) continue;
        uint64_t l2e = l2[l2i];
        if (l2e & PG_PS_2M) {
            /* Don't unmap 2MB page that contains L2/L3/L4 tables (would #PF on next access) */
            uint64_t page_lo = va & ~((uint64_t)(PAGE_SIZE_2M - 1));
            uint64_t page_hi = page_lo + PAGE_SIZE_2M;
            uint64_t l3_phys = l4[l4i] & ~0xFFFULL;
            uint64_t l4_phys = cr3 & ~0xFFFULL;
            if ((l2_phys >= page_lo && l2_phys < page_hi) ||
                (l3_phys >= page_lo && l3_phys < page_hi) ||
                (l4_phys >= page_lo && l4_phys < page_hi))
                continue;
            l2[l2i] = 0;
            invlpg((void*)(uintptr_t)va);
            continue;
        }
        uint64_t *l1 = (uint64_t*)(uintptr_t)(l2e & ~0xFFFULL);
        l1[l1i] = 0;
        invlpg((void*)(uintptr_t)va);
    }
    return 0;
}

/* User program region: .data/GOT can be anywhere from 0x200000 to USER_STACK_TOP.
   mprotect(PROT_READ) must not remove PG_RW from this range - lazy PLT binding writes to GOT. */
#define USER_DATA_REGION_LO 0x200000ULL
#define USER_DATA_REGION_HI ((uint64_t)0x10000000ULL)  /* USER_STACK_TOP */

/* Change [va_begin, va_end) protection. prot: 0=PROT_NONE, 1=READ, 2=WRITE, 4=EXEC (combine). */
static int mprotect_user_range_sys(uint64_t va_begin, uint64_t va_end, int prot) {
    if (va_end < va_begin) return -1;
    if (va_begin >= (uint64_t)MMIO_IDENTITY_LIMIT) return -1;
    if (va_end > (uint64_t)MMIO_IDENTITY_LIMIT) va_end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t begin = va_begin & ~((uint64_t)(PAGE_SIZE_2M - 1));
    uint64_t end = (va_end + PAGE_SIZE_2M - 1) & ~((uint64_t)(PAGE_SIZE_2M - 1));
    if (end > (uint64_t)MMIO_IDENTITY_LIMIT) end = (uint64_t)MMIO_IDENTITY_LIMIT;
    uint64_t cr3 = paging_read_cr3();
    uint64_t *l4 = (uint64_t*)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!l4) return -1;
    uint64_t new_flags = 0;
    if (prot != 0) {
        new_flags = PG_PRESENT | PG_US | PG_PS_2M;
        if (prot & 2) new_flags |= PG_RW;
        if (!(prot & 4)) new_flags |= PG_NX;
        /* .data/GOT region must stay writable for lazy PLT binding; mprotect(PROT_READ) would break it */
        if (va_begin < USER_DATA_REGION_HI && va_end > USER_DATA_REGION_LO)
            new_flags |= PG_RW;
    }
    for (uint64_t va = begin; va < end; va += PAGE_SIZE_2M) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        if (!(l4[l4i] & PG_PRESENT)) return -1;
        uint64_t *l3 = (uint64_t*)(uintptr_t)(l4[l4i] & ~0xFFFULL);
        if (!(l3[l3i] & PG_PRESENT)) return -1;
        uint64_t l3e = l3[l3i];
        if (l3e & PG_PS_2M) return -1;  /* 1G page; cannot change */
        uint64_t *l2 = (uint64_t*)(uintptr_t)(l3e & ~0xFFFULL);
        if (!(l2[l2i] & PG_PRESENT)) return -1;
        uint64_t l2e = l2[l2i];
        if (l2e & PG_PS_2M) {
            uint64_t pa = l2e & ~(PAGE_SIZE_2M - 1) & ~0xFFFULL;
            l2[l2i] = pa | new_flags;
        } else {
            uint64_t *l1 = (uint64_t*)(uintptr_t)(l2e & ~0xFFFULL);
            for (uint64_t v = va; v < va + PAGE_SIZE_2M && v < (uint64_t)MMIO_IDENTITY_LIMIT; v += 0x1000ULL) {
                uint64_t l1i = (v >> 12) & 0x1FF;
                uint64_t pa = l1[l1i] & ~0xFFFULL;
                uint64_t f = new_flags & ~PG_PS_2M;  /* L1 uses 4K, no PS */
                l1[l1i] = pa | f;
                invlpg((void*)(uintptr_t)v);
            }
        }
        invlpg((void*)(uintptr_t)va);
    }
    return 0;
}

static int mark_user_identity_range_2m_sys(uint64_t va_begin, uint64_t va_end) {
    if (va_end < va_begin) return -1;
    uint64_t cr3 = paging_read_cr3();
    uint64_t *active_l4 = (uint64_t*)(uintptr_t)(cr3 & ~0xFFFULL);
    if (!active_l4) return -1;
    uint64_t begin = va_begin & ~((uint64_t)(PAGE_SIZE_2M - 1));
    uint64_t end = (va_end + PAGE_SIZE_2M - 1) & ~((uint64_t)(PAGE_SIZE_2M - 1));
    for (uint64_t va = begin; va < end; va += PAGE_SIZE_2M) {
        uint64_t l4i = (va >> 39) & 0x1FF;
        uint64_t l3i = (va >> 30) & 0x1FF;
        uint64_t l2i = (va >> 21) & 0x1FF;
        uint64_t *l4 = active_l4;
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
                t->sleep_until = 0;
                thread_note_ready(t);
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

static uint64_t syscall_do_inner(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6);

/* Verbose per-syscall trace for /usr/bin/wget (budget-limited). Set left=0 to disable. */
static void axon_wget_sc_log(uint64_t num, uint64_t rax, uint64_t a1, uint64_t a2, uint64_t a3) {
    thread_t *t = thread_get_current_user();
    if (!t) t = thread_current();
    if (!t || !t->name[0]) return;
    if (!strstr(t->name, "wget")) return;
    static int wget_sc_left = 512;
    static int wget_sc_warned;
    if (wget_sc_left <= 0) {
        if (!wget_sc_warned) {
            wget_sc_warned = 1;
            kprintf("WGET-SC: trace budget exhausted (disable in axon_wget_sc_log)\n");
        }
        return;
    }
    wget_sc_left--;
    int64_t sr = (int64_t)rax;
    if (sr < 0 && sr >= -4096) {
        kprintf("WGET-SC nr=%llu ERR=%d a1=0x%llx a2=0x%llx a3=0x%llx\n",
            (unsigned long long)num, (int)(-sr),
            (unsigned long long)a1, (unsigned long long)a2, (unsigned long long)a3);
    } else {
        kprintf("WGET-SC nr=%llu rax=0x%llx a1=0x%llx a2=0x%llx\n",
            (unsigned long long)num, (unsigned long long)rax,
            (unsigned long long)a1, (unsigned long long)a2);
    }
}

/* Common syscall dispatcher used by both int0x80 and SYSCALL.
   Calling convention follows Linux x86_64: num + up to 6 args. */  
static uint64_t syscall_do_inner(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
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
    /* Keep global current_user synchronized with the actually running user thread.
       Exec/job-control code reads thread_get_current_user(); stale value here can
       put parent and child into the same pgrp and break Ctrl+C behavior. */
    if (cur->ring == 3) {
        thread_set_current_user(cur);
    }
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

    //if (num != 1) kprintf("syscall: num=%llu\n", (unsigned long long)num);

    switch (num) {
        case SYS_clone: {
            /* Minimal compatibility: treat clone() without complex flags as fork(). */
            return syscall_do_inner(SYS_fork, 0, 0, 0, 0, 0, 0);
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
            /* clone3 with stack: create thread sharing parent's mm (CLONE_VM). */
            if (stack != 0) {
                /* clone3 stack conventions differ across libc wrappers.
                   Choose child RSP adaptively:
                   - classic clone3: rsp = stack + stack_size (stack is low address)
                   - wrapper/prebuilt-frame style: rsp = stack (stack is already top) */
                uintptr_t rsp_from_top = (uintptr_t)stack;
                uintptr_t rsp_from_size = (uintptr_t)stack;
                if (stack_size != 0 && stack <= (UINT64_MAX - stack_size)) {
                    rsp_from_size = (uintptr_t)(stack + stack_size);
                }
                uintptr_t child_rsp = rsp_from_size;
                if ((flags & 0x00080000u) && tls != 0) { /* CLONE_SETTLS */
                    uint64_t d_top = (rsp_from_top > (uintptr_t)tls)
                        ? (uint64_t)(rsp_from_top - (uintptr_t)tls)
                        : (uint64_t)((uintptr_t)tls - rsp_from_top);
                    uint64_t d_size = (rsp_from_size > (uintptr_t)tls)
                        ? (uint64_t)(rsp_from_size - (uintptr_t)tls)
                        : (uint64_t)((uintptr_t)tls - rsp_from_size);
                    if (d_top < d_size) child_rsp = rsp_from_top;
                }
                if (child_rsp < 0x1000 || child_rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EINVAL);
                /* Ensure saved_rcx (return site) is user-accessible - otherwise child #PF on first instruction */
                {
                    uintptr_t begin = (uintptr_t)saved_rcx & ~((uintptr_t)PAGE_SIZE_2M - 1);
                    uintptr_t end = begin + (uintptr_t)PAGE_SIZE_2M;
                    if (mark_user_identity_range_2m_sys((uint64_t)begin, (uint64_t)end) != 0) {
                        kprintf("clone3: saved return site 0x%llx unmapped/privileged\n", (unsigned long long)saved_rcx);
                        return ret_err(EINVAL);
                    }
                    /* Broad user range (like vfork) - helps code/TLS near saved_rcx and general bootstrap */
                    (void)mark_user_identity_range_2m_sys(0x200000, (uint64_t)USER_STACK_TOP);
                }
                /* RSP must be 16-byte aligned per x86-64 ABI (child may use movdqa/call) */
                child_rsp &= ~(uintptr_t)0xFULL;
                
                uintptr_t lo = rsp_from_top < rsp_from_size ? rsp_from_top : rsp_from_size;
                uintptr_t hi = rsp_from_top > rsp_from_size ? rsp_from_top : rsp_from_size;
                uintptr_t map_lo = lo & ~((uintptr_t)PAGE_SIZE_2M - 1);
                uintptr_t map_hi = hi + 4096;
                if (map_hi <= map_lo || map_hi >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                if (mark_user_identity_range_2m_sys((uint64_t)map_lo, (uint64_t)map_hi) != 0) return ret_err(EFAULT);
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
                child->user_stack_base = (uint64_t)stack;
                child->user_stack_limit = (stack_size != 0 && stack <= (UINT64_MAX - stack_size))
                    ? (uint64_t)(stack + stack_size)
                    : (uint64_t)child_rsp;
                child->ring = 3;
                if ((flags & 0x00080000u) && tls != 0 && tls >= 0x1000 && tls < (uint64_t)MMIO_IDENTITY_LIMIT) {
                    child->user_fs_base = tls;
                    /* Ensure TLS region is user-accessible */
                    uintptr_t tls_lo = ((uintptr_t)tls - 0x1000u) & ~((uintptr_t)PAGE_SIZE_2M - 1);
                    uintptr_t tls_hi = ((uintptr_t)tls + 0x3000u + PAGE_SIZE_2M - 1) & ~((uintptr_t)PAGE_SIZE_2M - 1);
                    (void)mark_user_identity_range_2m_sys((uint64_t)tls_lo, (uint64_t)tls_hi);
                } else {
                    child->user_fs_base = cur->user_fs_base;
                }
                child->uid = cur->uid;
                child->euid = cur->euid;
                child->suid = cur->suid;
                child->gid = cur->gid;
                child->egid = cur->egid;
                child->sgid = cur->sgid;
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
                /* Shared mm (CLONE_VM): inherit brk/mmap state so child mmap doesn't overwrite parent's regions. */
                child->user_brk_base = cur->user_brk_base;
                child->user_brk_cur = cur->user_brk_cur;
                child->user_mmap_next = cur->user_mmap_next;
                child->user_mmap_hi = cur->user_mmap_hi;
                /* Parent must not mmap into child's stack; bump parent's user_mmap_next above stack region. */
                {
                    uintptr_t stack_end = child->user_stack_limit;
                    uintptr_t min_next = align_up_u(stack_end, (uintptr_t)PAGE_SIZE_2M);
                    if (cur->user_mmap_next < min_next)
                        cur->user_mmap_next = min_next;
                }
                /* clone3 semantics: touch TID pointers only when the matching flags are set. */
                enum {
                    CLONE_PARENT_SETTID = 0x00100000u,
                    CLONE_CHILD_CLEARTID = 0x00200000u,
                    CLONE_CHILD_SETTID = 0x01000000u
                };
                if ((flags & CLONE_PARENT_SETTID) &&
                    parent_tid_ptr && parent_tid_ptr < (uint64_t)MMIO_IDENTITY_LIMIT - 4) {
                    copy_to_user_safe((void*)(uintptr_t)parent_tid_ptr, &child->tid, 4);
                }
                if ((flags & CLONE_CHILD_SETTID) &&
                    child_tid_ptr && child_tid_ptr < (uint64_t)MMIO_IDENTITY_LIMIT - 4) {
                    copy_to_user_safe((void*)(uintptr_t)child_tid_ptr, &child->tid, 4);
                }
                if ((flags & CLONE_CHILD_CLEARTID) &&
                    child_tid_ptr && child_tid_ptr < (uint64_t)MMIO_IDENTITY_LIMIT - 4) {
                    child->clear_child_tid = child_tid_ptr;
                }
                thread_unblock((int)(child->tid ? child->tid : 1));
                return (uint64_t)(child->tid ? child->tid : 1);
            }
            return syscall_do_inner(SYS_fork, 0, 0, 0, 0, 0, 0);
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
                /* Relocate pointers inside the copied stack slice itself.
                   Use nv = child_rsp + (vv - parent_lo) so a lower child_rsp than parent_lo
                   never triggers unsigned wrap (was: vv + (uintptr_t)(child - parent)). */
                {
                    const uintptr_t parent_lo = (uintptr_t)saved_rsp;
                    const uintptr_t parent_hi = parent_lo + (uintptr_t)copy_bytes;
                    uintptr_t pp = (uintptr_t)child_rsp;
                    uintptr_t end = (uintptr_t)child_rsp + (uintptr_t)copy_bytes;
                    for (; pp + 8 <= end; pp += 8) {
                        uint64_t v = 0;
                        if (user_read_u64((const void *)(uintptr_t)pp, &v) != 0) return ret_err(EFAULT);
                        uintptr_t vv = (uintptr_t)v;
                        if ((vv & 7u) == 0 && vv >= parent_lo && vv < parent_hi) {
                            uintptr_t nv = (uintptr_t)child_rsp + (uintptr_t)(vv - parent_lo);
                            if (user_write_u64((void *)(uintptr_t)pp, (uint64_t)nv) != 0)
                                return ret_err(EFAULT);
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
                if (user_write_u64((void *)(uintptr_t)(child_fs - 0x78u), (uint64_t)child_pthread_fake) != 0)
                    return ret_err(EFAULT);
                /* Provide default "C" locale string for specifics[5] (see core/elf.c). */
                {
                    const uintptr_t c_str = child_tls_region + 0x2800u;
                    if (c_str + 2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                        if (user_write_u8((void *)(uintptr_t)(c_str + 0), (uint8_t)'C') != 0) return ret_err(EFAULT);
                        if (user_write_u8((void *)(uintptr_t)(c_str + 1), 0) != 0) return ret_err(EFAULT);
                        const uintptr_t specific5_slot = child_pthread_fake + 0x80u + (uintptr_t)(5u * 8u);
                        /* The TLS region may have been cloned from parent and contain garbage/non-canonical
                           pointers in the specifics area. Clear a small window and force slot 5. */
                        for (int si = 0; si < 32; si++) {
                            if (user_write_u64((void *)(uintptr_t)(child_pthread_fake + 0x80u + (uintptr_t)(si * 8u)), 0) != 0)
                                return ret_err(EFAULT);
                        }
                        if (user_write_u64((void *)(uintptr_t)specific5_slot, (uint64_t)c_str) != 0)
                            return ret_err(EFAULT);
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
            child->uid = p->uid; child->euid = p->euid; child->suid = p->suid;
            child->gid = p->gid; child->egid = p->egid; child->sgid = p->sgid;
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
                /* Backup only up to the end of *heap/program* used memory.
                   IMPORTANT: user_mmap_next can jump high due to large device mmaps
                   (e.g. /dev/fb0 mapping the whole framebuffer). Backing up to that
                   address makes every vfork copy tens/hundreds of MiB and effectively
                   stalls boot. We therefore only extend backup to mmap_next when it is
                   close to brk (heuristic for small anon/file-private mmaps). */
                uintptr_t used_end = (uintptr_t)p->user_brk_cur;
                /* Minimum: cover program load + small heap (busybox ~2MB at 0x400000) */
                const uintptr_t min_backup = base + (8u * 1024u * 1024u);
                if (used_end < min_backup || used_end == 0) used_end = min_backup;
                /* Heuristic: include mmap area only if it's not "far away" (avoid fb0/VRAM-sized mappings). */
                if (p->user_mmap_next != 0) {
                    const uintptr_t mmap_next = (uintptr_t)p->user_mmap_next;
                    const uintptr_t slack = (8u * 1024u * 1024u);
                    if (mmap_next > used_end && mmap_next - used_end <= slack) {
                        used_end = mmap_next;
                    }
                }
                if (used_end > end) used_end = end;
                uint64_t len64 = (uint64_t)(used_end - base);
                qemu_debug_printf("vfork-backup: parent=%llu brk=0x%llx mmap_next=0x%llx used_end=0x%llx len=%llu\n",
                    (unsigned long long)(p->tid ? p->tid : 1),
                    (unsigned long long)p->user_brk_cur,
                    (unsigned long long)p->user_mmap_next,
                    (unsigned long long)used_end,
                    (unsigned long long)len64);
                if (len64 == 0 || len64 > (uint64_t)(256u * 1024u * 1024u)) {
                    qemu_debug_printf("vfork-backup: invalid len=%llu -> ENOMEM\n", (unsigned long long)len64);
                    return ret_err(ENOMEM);
                }
                child->vfork_parent_mem_backup = kmalloc((size_t)len64);
                if (!child->vfork_parent_mem_backup) {
                    qemu_debug_printf("OOM vfork-backup: kmalloc(%llu) failed heap_used=%llu heap_total=%llu\n",
                        (unsigned long long)len64, (unsigned long long)heap_used_bytes(),
                        (unsigned long long)heap_total_bytes());
                    return ret_err(ENOMEM);
                }
                /* Small backup: single copy. Large: chunk with yields to avoid freeze. */
                const size_t chunk = 512u * 1024u;
                if ((size_t)len64 <= chunk) {
                    memcpy(child->vfork_parent_mem_backup, (void*)base, (size_t)len64);
                    qemu_debug_printf("COPIED WHITOUT CHUNKS\n");
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

            char kpath[256];
            resolve_user_path(cur, path, kpath, sizeof(kpath));

            /* Workaround: realpath/canonicalize and Busybox adduser readlink paths to resolve
               them. When a path exists as regular file or dir (not symlink), POSIX readlink
               would fail with EINVAL. Return the path as link target so programs succeed. */
            {
                struct stat st;
                if (vfs_lstat(kpath, &st) == 0 && (st.st_mode & S_IFLNK) != S_IFLNK) {
                    if (bufsiz == 0) return ret_err(EINVAL);
                    size_t L = strlen(kpath);
                    if (L > bufsiz) L = bufsiz;
                    memcpy(buf, kpath, L);
                    return (uint64_t)L;
                }
            }

            ssize_t rr = vfs_readlink(kpath, buf, bufsiz);
            if (rr >= 0) return (uint64_t)rr;

            /* Fallbacks for common procfs symlinks used by libc/busybox. */
            if (strcmp(kpath, "/proc/self/exe") == 0) {
                const char *target = cur->name[0] ? cur->name : "/bin/busybox";
                size_t L = strlen(target);
                if (bufsiz == 0) return ret_err(EINVAL);
                if (L > bufsiz) L = bufsiz;
                memcpy(buf, target, L);
                return (uint64_t)L; /* no NUL terminator */
            }
            if (strncmp(kpath, "/proc/", 6) == 0) {
                const char *p = kpath + 6;
                int self_ok = 0;
                if (strncmp(p, "self/", 5) == 0) {
                    p += 5;
                    self_ok = 1;
                } else {
                    /* /proc/<pid>/... */
                    int saw_digit = 0;
                    while (*p >= '0' && *p <= '9') { p++; saw_digit = 1; }
                    if (saw_digit && *p == '/') {
                        p++;
                        self_ok = 1; /* best-effort: map any pid to current process view */
                    }
                }
                if (self_ok) {
                    if (strcmp(p, "exe") == 0) {
                        const char *target = cur->name[0] ? cur->name : "/bin/busybox";
                        size_t L = strlen(target);
                        if (bufsiz == 0) return ret_err(EINVAL);
                        if (L > bufsiz) L = bufsiz;
                        memcpy(buf, target, L);
                        return (uint64_t)L;
                    }
                    if (strncmp(p, "fd/", 3) == 0) {
                        int fd = 0;
                        const char *q = p + 3;
                        if (!*q) return ret_err(ENOENT);
                        while (*q >= '0' && *q <= '9') {
                            fd = fd * 10 + (*q - '0');
                            q++;
                        }
                        if (*q == '\0' && fd >= 0 && fd < THREAD_MAX_FD) {
                            struct fs_file *ff = cur->fds[fd];
                            const char *target = (ff && ff->path) ? ff->path : NULL;
                            if (!target) return ret_err(ENOENT);
                            size_t L = strlen(target);
                            if (bufsiz == 0) return ret_err(EINVAL);
                            if (L > bufsiz) L = bufsiz;
                            memcpy(buf, target, L);
                            return (uint64_t)L;
                        }
                    }
                }
            }
            if (cur && cur->name[0]) {
                if (strstr(cur->name, "addgroup") || strstr(cur->name, "adduser") || strstr(cur->name, "wget")) {
                    kprintf("READLINK-ENOENT: %s path=%s\n", cur->name, kpath);
                    qemu_debug_printf("READLINK-ENOENT: name=%s path=%s\n", cur->name, kpath);
                }
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
        case 87: { /* unlink(path) */
            const char *path_u = (const char*)(uintptr_t)a1;
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            resolve_user_path(cur, path_u, path, sizeof(path));
            int r = fs_unlink(path);
            if (r == 0) return 0;
            if (r == -3) return ret_err(ENOENT);
            if (r == -2) return ret_err(EPERM);
            if (r == -1) return ret_err(EPERM);
            return ret_err(r < 0 ? -r : EIO);
        }
        case 263: { /* unlinkat(dirfd, path, flags) */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            int flags = (int)a3;
            (void)flags; /* we don't support AT_REMOVEDIR etc yet */
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            int rc = resolve_user_path_at(cur, dirfd, path_u, path, sizeof(path));
            if (rc != 0) return ret_err(-rc);
            int r = fs_unlink(path);
            if (r == 0) return 0;
            if (r == -3) return ret_err(ENOENT);
            if (r == -2) return ret_err(EPERM);
            if (r == -1) return ret_err(EPERM);
            return ret_err(r < 0 ? -r : EIO);
        }
        case 265: { /* linkat(olddirfd, oldpath, newdirfd, newpath, flags) */
            int olddirfd = (int)a1;
            const char *oldpath_u = (const char*)(uintptr_t)a2;
            int newdirfd = (int)a3;
            const char *newpath_u = (const char*)(uintptr_t)a4;
            int flags = (int)a5;
            (void)flags;
            if (!oldpath_u || !newpath_u) return ret_err(EFAULT);
            if ((uintptr_t)oldpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)newpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char oldpath[256], newpath[256];
            int rc1 = resolve_user_path_at(cur, olddirfd, oldpath_u, oldpath, sizeof(oldpath));
            if (rc1 != 0) return ret_err(-rc1);
            int rc2 = resolve_user_path_at(cur, newdirfd, newpath_u, newpath, sizeof(newpath));
            if (rc2 != 0) return ret_err(-rc2);
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
        case 264: { /* renameat(olddirfd, oldpath, newdirfd, newpath) */
            int olddirfd = (int)a1;
            const char *oldpath_u = (const char*)(uintptr_t)a2;
            int newdirfd = (int)a3;
            const char *newpath_u = (const char*)(uintptr_t)a4;
            if (!oldpath_u || !newpath_u) return ret_err(EFAULT);
            if ((uintptr_t)oldpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            if ((uintptr_t)newpath_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char oldpath[256], newpath[256];
            int rc1 = resolve_user_path_at(cur, olddirfd, oldpath_u, oldpath, sizeof(oldpath));
            if (rc1 != 0) return ret_err(-rc1);
            int rc2 = resolve_user_path_at(cur, newdirfd, newpath_u, newpath, sizeof(newpath));
            if (rc2 != 0) return ret_err(-rc2);
            int r = fs_rename(oldpath, newpath);
            if (r == 0) return 0;
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
        case 268: { /* fchmodat(dirfd, pathname, mode, flags) */
            int dirfd = (int)a1;
            const char *path_u = (const char*)(uintptr_t)a2;
            mode_t mode = (mode_t)a3;
            int flags = (int)a4;
            (void)flags; /* AT_SYMLINK_NOFOLLOW not supported yet */
            if (!path_u) return ret_err(EFAULT);
            if ((uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char path[256];
            int rc = resolve_user_path_at(cur, dirfd, path_u, path, sizeof(path));
            if (rc != 0) return ret_err(-rc);
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
            if (!user_range_ok(tp, 16)) return ret_err(EFAULT);
            /* Linux clock ids (glibc wget uses MONOTONIC_RAW, COARSE, BOOTTIME, …). */
            enum {
                CLOCK_REALTIME = 0,
                CLOCK_MONOTONIC = 1,
                CLOCK_PROCESS_CPUTIME_ID = 2,
                CLOCK_THREAD_CPUTIME_ID = 3,
                CLOCK_MONOTONIC_RAW = 4,
                CLOCK_REALTIME_COARSE = 5,
                CLOCK_MONOTONIC_COARSE = 6,
                CLOCK_BOOTTIME = 7
            };
            if (clk < 0 || clk > 15) return ret_err(EINVAL);
            int64_t sec, nsec;
            if (clk == CLOCK_REALTIME || clk == CLOCK_REALTIME_COARSE) {
                rtc_datetime_t dt;
                rtc_read_datetime(&dt);
                uint64_t secs = rtc_datetime_to_epoch(&dt);
                uint64_t sub = pit_get_time_ms() % 1000ULL;
                sec = (int64_t)secs;
                nsec = (int64_t)(sub * 1000000ULL);
            } else {
                /* Monotonic, raw, coarse, boottime, thread/process CPU: PIT since boot */
                uint64_t ms = pit_get_time_ms();
                sec = (int64_t)(ms / 1000ULL);
                nsec = (int64_t)((ms % 1000ULL) * 1000000ULL);
            }
            struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
            ts.tv_sec = sec;
            ts.tv_nsec = nsec;
            if (copy_to_user_safe(tp, &ts, sizeof(ts)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 96: /* Linux uses 96 for gettimeofday; glibc may call it */
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
            snprintf(u.nodename, sizeof(u.nodename), "axoniso");
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
            /* Don't trust f->type: some drivers don't set it consistently.
               Use stat mode to decide directory-ness so chdir("/") never regresses. */
            struct stat st;
            int is_dir = 0;
            if (vfs_fstat(f, &st) == 0) {
                is_dir = ((st.st_mode & S_IFDIR) == S_IFDIR);
            } else {
                is_dir = (f->type == FS_TYPE_DIR);
            }
            fs_file_free(f);
            if (!is_dir) return ret_err(EINVAL);
            size_t n = strlen(path);
            while (n > 1 && path[n - 1] == '/') path[--n] = '\0';
            strncpy(cur->cwd, path, sizeof(cur->cwd));
            cur->cwd[sizeof(cur->cwd) - 1] = '\0';
            return 0;
        }
        case SYS_syslog: {

            return ENOSYS;
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

            if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                uint64_t sum64 = 0;
                for (int i = 0; i < iovcnt; i++) sum64 += (uint64_t)iov[i].len;
                if (sum64 == 0) return 0;
                if (sum64 > 65536u) return ret_err(EINVAL);
                size_t sum = (size_t)sum64;
                uint8_t *flat = (uint8_t *)kmalloc(sum);
                if (!flat) return ret_err(ENOMEM);
                size_t at = 0;
                for (int i = 0; i < iovcnt; i++) {
                    size_t len = (size_t)iov[i].len;
                    if (len == 0) continue;
                    const void *base = (const void *)(uintptr_t)iov[i].base;
                    if (!user_range_ok(base, len)) {
                        kfree(flat);
                        return ret_err(EFAULT);
                    }
                    if (copy_from_user_raw(flat + at, base, len) != 0) {
                        kfree(flat);
                        return ret_err(EFAULT);
                    }
                    at += len;
                }
                ssize_t wr = net_sock_write_userspace(cur, fd, s, flat, sum);
                kfree(flat);
                if (wr < 0) return ret_err((int)-wr);
                return (uint64_t)wr;
            }

            uint64_t total = 0;
            for (int i = 0; i < iovcnt; i++) {
                const void *base = (const void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                if (!user_range_ok(base, len)) return (total > 0) ? (uint64_t)total : ret_err(EFAULT);
                /* Clamp per-chunk to avoid huge kmalloc; write in pieces. */
                size_t off = 0;
                while (off < len) {
                    size_t chunk = len - off;
                    if (chunk > 4096) chunk = 4096;
                    size_t copied = 0;
                    void *tmp = copy_from_user_safe((const uint8_t*)base + off, chunk, 4096, &copied);
                    if (!tmp && chunk > 512) { chunk = 512; tmp = copy_from_user_safe((const uint8_t*)base + off, chunk, 512, &copied); }
                    if (!tmp) return (total > 0) ? (uint64_t)total : ret_err(EFAULT);
                    ssize_t wr;
                    if (f->type == FS_TYPE_PIPE && f->fs_private == (void *)1 && f->driver_private) {
                        wr = pipe_write_bytes((pipe_t *)f->driver_private, tmp, copied, cur);
                    } else {
                        wr = fs_write(f, tmp, copied, f->pos);
                    }
                    kfree(tmp);
                    if (wr <= 0) return (total > 0) ? total : ret_err((int)(-wr ? -wr : EINVAL));
                    if (f->type != FS_TYPE_PIPE) f->pos += (size_t)wr;
                    total += (uint64_t)wr;
                    off += (size_t)wr;
                    if ((size_t)wr < copied) break;
                }
            }
            return total;
        }
        case SYS_pwritev: {
            /* pwritev(fd, const struct iovec *iov, int iovcnt, off_t offset) — Linux x86_64 296 */
            int fd = (int)a1;
            const void *iov_u = (const void*)(uintptr_t)a2;
            int iovcnt = (int)a3;
            int64_t off_in = (int64_t)a4;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!iov_u) return ret_err(EFAULT);
            if (iovcnt <= 0 || iovcnt > 64) return ret_err(EINVAL);
            if (off_in < 0) return ret_err(EINVAL);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);

            struct iovec_k { uint64_t base; uint64_t len; };
            struct iovec_k iov[64];
            size_t bytes = (size_t)iovcnt * sizeof(iov[0]);
            if (copy_from_user_raw(iov, iov_u, bytes) != 0) return ret_err(EFAULT);

            uint64_t total = 0;
            size_t cur_off = (size_t)off_in;
            for (int i = 0; i < iovcnt; i++) {
                const void *base = (const void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                if (!user_range_ok(base, len)) return (total > 0) ? total : ret_err(EFAULT);
                /* Clamp per-chunk to avoid huge kmalloc; write in pieces. */
                size_t off = 0;
                while (off < len) {
                    size_t chunk = len - off;
                    if (chunk > 4096) chunk = 4096;
                    size_t copied = 0;
                    void *tmp = copy_from_user_safe((const uint8_t*)base + off, chunk, 4096, &copied);
                    if (!tmp) return (total > 0) ? total : ret_err(EFAULT);
                    ssize_t wr = fs_write(f, tmp, copied, cur_off);
                    kfree(tmp);
                    if (wr <= 0) return (total > 0) ? total : ret_err(EINVAL);
                    cur_off += (size_t)wr;
                    total += (uint64_t)wr;
                    off += (size_t)wr;
                    if ((size_t)wr < copied) break;
                }
            }
            return total;
        }
        case SYS_dup3: {
            /* dup3(oldfd, newfd, flags) — Linux x86_64 292.
               Many tools (including busybox applets) use dup3() internally. */
            int oldfd = (int)a1;
            int newfd = (int)a2;
            int flags = (int)a3;
            /* Only allow O_CLOEXEC (ignored) or 0. */
            const int O_CLOEXEC = 02000000;
            if (flags & ~O_CLOEXEC) return ret_err(EINVAL);
            if (oldfd == newfd) return ret_err(EINVAL);
            int r = thread_fd_dup2(oldfd, newfd);
            if (r < 0) return ret_err(EBADF);
            return (uint64_t)r;
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
            return (uint64_t)cur->uid;
        case SYS_geteuid:
            return (uint64_t)cur->euid;
        case SYS_getgid:
            return (uint64_t)cur->gid;
        case SYS_getegid:
            return (uint64_t)cur->egid;
        case SYS_setuid: {
            /* setuid(uid): set uid, euid, suid. Root can set any; otherwise uid must equal uid/euid/suid. */
            uid_t uid = (uid_t)a1;
            if (cur->euid == 0) {
                cur->uid = cur->euid = cur->suid = uid;
                return 0;
            }
            if (uid != cur->uid && uid != cur->euid && uid != cur->suid)
                return ret_err(EPERM);
            cur->uid = cur->euid = cur->suid = uid;
            return 0;
        }
        case SYS_setgid: {
            /* setgid(gid): same as setuid for groups. */
            gid_t gid = (gid_t)a1;
            if (cur->euid == 0) {
                cur->gid = cur->egid = cur->sgid = gid;
                return 0;
            }
            if (gid != cur->gid && gid != cur->egid && gid != cur->sgid)
                return ret_err(EPERM);
            cur->gid = cur->egid = cur->sgid = gid;
            return 0;
        }
        case SYS_setreuid: {
            /* setreuid(ruid, euid): -1 means don't change. seteuid(uid) = setreuid(-1, uid). */
            uid_t ruid = (uid_t)(int)a1;
            uid_t euid = (uid_t)(int)a2;
            int do_ruid = (int)a1 != -1;
            int do_euid = (int)a2 != -1;
            if (cur->euid == 0) {
                if (do_ruid) cur->uid = ruid;
                if (do_euid) cur->euid = euid;
                cur->suid = cur->euid; /* Linux: suid = new euid when euid changed */
                return 0;
            }
            if (do_ruid && ruid != cur->uid && ruid != cur->euid && ruid != cur->suid)
                return ret_err(EPERM);
            if (do_euid && euid != cur->uid && euid != cur->euid && euid != cur->suid)
                return ret_err(EPERM);
            if (do_ruid) cur->uid = ruid;
            if (do_euid) { cur->euid = euid; cur->suid = euid; }
            return 0;
        }
        case SYS_setregid: {
            /* setregid(rgid, egid): -1 means don't change. */
            gid_t rgid = (gid_t)(int)a1;
            gid_t egid = (gid_t)(int)a2;
            int do_rgid = (int)a1 != -1;
            int do_egid = (int)a2 != -1;
            if (cur->euid == 0) {
                if (do_rgid) cur->gid = rgid;
                if (do_egid) cur->egid = egid;
                cur->sgid = cur->egid;
                return 0;
            }
            if (do_rgid && rgid != cur->gid && rgid != cur->egid && rgid != cur->sgid)
                return ret_err(EPERM);
            if (do_egid && egid != cur->gid && egid != cur->egid && egid != cur->sgid)
                return ret_err(EPERM);
            if (do_rgid) cur->gid = rgid;
            if (do_egid) { cur->egid = egid; cur->sgid = egid; }
            return 0;
        }
        case SYS_setsid:
            if (cur) {
                cur->sid = (int)(cur->tid ? cur->tid : 1);
                cur->pgid = (int)(cur->tid ? cur->tid : 1);
                user_pgrp = (uint64_t)cur->pgid;
            }
            return user_pgrp;
        case 37: /* alarm(seconds) - compatibility shim */
            if (a1 == 0) {
                user_itimer_interval_ms = 0;
            } else {
                uint64_t ms = a1 * 1000ULL;
                if (ms > 0xFFFFFFFFULL) ms = 0xFFFFFFFFULL;
                user_itimer_interval_ms = (uint32_t)ms;
            }
            return 0;
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
                        //kprintf("sys_setpgid: pid=%d pgid=%d -> ESRCH (not found)\n", pid, pgid);
                        return ret_err(ESRCH);
                    }
                    /* simple permission: only parent can change child's pgid */
                    if (t->parent_tid != (int)self) {
                        //kprintf("sys_setpgid: pid=%d pgid=%d -> EPERM (not parent)\n", pid, pgid);
                        return ret_err(EPERM);
                    }
                    /* Additional guard: do not allow setting arbitrary pgid==1 (init) unless
                       caller is pid 1. This avoids user processes mistakenly moving into
                       init's pgrp which later confuses job control and can cause shells to exit. */
                    if (pgid == 1 && (int)self != 1 && !is_init_user(cur)) {
                        //kprintf("sys_setpgid: pid=%d attempted to set pgid=1 -> EPERM (denied)\n", pid);
                        return ret_err(EPERM);
                    }
                    /* Additional guard: do not allow setting arbitrary pgid different from current
                       unless caller is session leader. */
                    int caller_tid = (int)self;
                    int caller_sid = cur ? cur->sid : -1;
                    if ((int)pgid != t->pgid && caller_sid != caller_tid) {
                        //kprintf("sys_setpgid: pid=%d pgid=%d -> EPERM (not session leader)\n", pid, pgid);
                        return ret_err(EPERM);
                    }
                    t->pgid = pgid;
                } else {
                    if (cur) cur->pgid = pgid;
                }
                if (pgid != 0) user_pgrp = (uint64_t)pgid;
                //kprintf("sys_setpgid: pid=%d pgid=%d -> OK (user_pgrp=%llu)\n", pid, pgid, (unsigned long long)user_pgrp);
                return 0;
            }
        case SYS_tgkill: {
            /* tgkill(tgid, tid, sig): used by glibc for raise()/pthread_kill()/abort().
               We must make self-targeted SIGABRT actually terminate; otherwise glibc
               falls back to ud2 in userspace -> #GP. */
            uint64_t tgid = a1;
            uint64_t tid  = a2;
            uint64_t sig  = a3;
            uint64_t self = (uint64_t)(cur->tid ? cur->tid : 1);
            if (tgid == self && tid == self && sig == 6 /* SIGABRT */) {
                return syscall_do_inner(SYS_exit_group, 134, 0, 0, 0, 0, 0);  /* 134 = 128+SIGABRT */
            }
            if (tgid == self && tid == self) return 0;
            return ret_err(ESRCH);
        }
        case SYS_select: { /* select(nfds, readfds, writefds, exceptfds, timeout) - minimal stub */
            /* Minimal but functional select():
               - supports readfds/writefds (exceptfds ignored)
               - readiness model mirrors SYS_poll implementation (TTY/pipe/file/socket)
               - services TCP (net_tcp_service) and polls e1000 while blocking */
            int nfds = (int)a1;
            void *readfds_u  = (void*)(uintptr_t)a2;
            void *writefds_u = (void*)(uintptr_t)a3;
            (void)a4; /* exceptfds */
            void *timeout_u  = (void*)(uintptr_t)a5;
            if (nfds < 0 || nfds > THREAD_MAX_FD) return ret_err(EINVAL);

            /* fd_set is a bitset; assume Linux layout with 64-bit words. */
            size_t nwords = (nfds <= 0) ? 0 : (size_t)((nfds + 63) / 64);
            size_t bytes = nwords * sizeof(uint64_t);

            uint64_t *rin = NULL, *win = NULL;
            uint64_t *rout = NULL, *wout = NULL;
            if (bytes) {
                if (readfds_u)  { rin  = (uint64_t*)kmalloc(bytes); rout = (uint64_t*)kmalloc(bytes); }
                if (writefds_u) { win  = (uint64_t*)kmalloc(bytes); wout = (uint64_t*)kmalloc(bytes); }
                if ((readfds_u && (!rin || !rout)) || (writefds_u && (!win || !wout))) {
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return ret_err(ENOMEM);
                }
                if (readfds_u)  { if (copy_from_user_raw(rin,  readfds_u,  bytes) != 0) { kfree(rin); kfree(rout); if (win) kfree(win); if (wout) kfree(wout); return ret_err(EFAULT); } }
                if (writefds_u) { if (copy_from_user_raw(win,  writefds_u, bytes) != 0) { if (rin) kfree(rin); if (rout) kfree(rout); kfree(win); kfree(wout); return ret_err(EFAULT); } }
            }

            int timeout_ms = -1; /* NULL => infinite */
            if (timeout_u && (uintptr_t)timeout_u < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                struct timeval_k { int64_t tv_sec; int64_t tv_usec; } tv;
                if (copy_from_user_raw(&tv, timeout_u, sizeof(tv)) != 0) {
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return ret_err(EFAULT);
                }
                if (tv.tv_sec < 0 || tv.tv_usec < 0) {
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return ret_err(EINVAL);
                }
                uint64_t ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000ULL);
                if (ms == 0 && tv.tv_usec > 0) ms = 1;
                if (ms > 0x7FFFFFFFULL) ms = 0x7FFFFFFFULL;
                timeout_ms = (int)ms;
            }

            thread_t *curth = thread_get_current_user();
            if (!curth) curth = thread_current();

            auto_select_check:
            {
                if (rout) memset(rout, 0, bytes);
                if (wout) memset(wout, 0, bytes);
                int ready = 0;
                int has_net_socket = 0;

                for (int fd = 0; fd < nfds; fd++) {
                    int want_r = 0, want_w = 0;
                    if (rin)  want_r = (int)((rin[fd / 64]  >> (fd % 64)) & 1ULL);
                    if (win)  want_w = (int)((win[fd / 64]  >> (fd % 64)) & 1ULL);
                    if (!want_r && !want_w) continue;

                    struct fs_file *f = curth ? curth->fds[fd] : NULL;
                    int can_r = 0, can_w = 0;
                    if (!f) {
                        /* invalid fd: POSIX would error via EBADF; keep it simple for now */
                        continue;
                    }

                    if (want_r) {
                        if (devfs_is_tty_file(f)) {
                            int tidx = devfs_get_tty_index_from_file(f);
                            if (tidx < 0) tidx = devfs_get_active();
                            if (devfs_tty_available(tidx) > 0) can_r = 1;
                        } else if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                            ksock_net_t *s = (ksock_net_t *)f->driver_private;
                            if ((s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) ||
                                (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL))
                                has_net_socket = 1;

                            if (s->sock_domain == AF_NETLINK_LOCAL) {
                                if (s->nl_rx_off < s->nl_rx_len) can_r = 1;
                            } else if (s->unix_domain_stub && s->connected) {
                                can_r = 1;
                            } else if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                                       (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge)) {
                                if (s->rx_has_pending) can_r = 1;
                                else {
                                    uint32_t sip = 0;
                                    uint16_t sport = 0;
                                    int rn = net_recv_udp_datagram(s, s->rx_pending, sizeof(s->rx_pending), 0, &sip, &sport);
                                    if (rn > 0) {
                                        ksock_rx_pending_install(s, rn);
                                        s->rx_pending_src_ip_be = sip;
                                        s->rx_pending_src_port = sport;
                                        can_r = 1;
                                    }
                                }
                            } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                                net_tcp_ops_t ops;
                                net_make_tcp_ops(&ops);
                                (void)net_tcp_service(&s->tcp, &ops, 4);
                                if (s->tcp.rx_len > 0 || s->tcp.peer_fin) can_r = 1;
                            }
                        } else if (f->type == FS_TYPE_PIPE && f->driver_private) {
                            pipe_t *p = (pipe_t *)f->driver_private;
                            unsigned long fl = 0;
                            acquire_irqsave(&p->lock, &fl);
                            size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
                            int is_write_end = (f->fs_private == (void *)1);
                            release_irqrestore(&p->lock, fl);
                            if (!is_write_end && used > 0) can_r = 1;
                        } else {
                            if (f->type == FS_TYPE_DIR) can_r = 1;
                            else if ((size_t)f->pos < (size_t)f->size) can_r = 1;
                        }
                    }

                    if (want_w) {
                        if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                            ksock_net_t *s = (ksock_net_t *)f->driver_private;
                            if ((s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) ||
                                (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL))
                                has_net_socket = 1;
                            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge) {
                                can_w = 1;
                            } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                                net_tcp_ops_t ops;
                                net_make_tcp_ops(&ops);
                                (void)net_tcp_service(&s->tcp, &ops, 4);
                                if (s->tcp.established) can_w = 1;
                            } else {
                                can_w = 1;
                            }
                        } else if (f->type == FS_TYPE_PIPE && f->driver_private) {
                            pipe_t *p = (pipe_t *)f->driver_private;
                            unsigned long fl = 0;
                            acquire_irqsave(&p->lock, &fl);
                            size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
                            size_t free = (p->size > 1) ? ((p->size - 1) - used) : 0;
                            int is_write_end = (f->fs_private == (void *)1);
                            release_irqrestore(&p->lock, fl);
                            if (is_write_end && free > 0) can_w = 1;
                        } else {
                            /* regular files: writable */
                            can_w = 1;
                        }
                    }

                    if (can_r && rout) { rout[fd / 64] |= (1ULL << (fd % 64)); ready++; }
                    if (can_w && wout) { wout[fd / 64] |= (1ULL << (fd % 64)); if (!can_r) ready++; }
                }

                if (ready > 0) {
                    if (readfds_u && rout)  { if (copy_to_user_safe(readfds_u,  rout, bytes) != 0) { if (rin) kfree(rin); if (rout) kfree(rout); if (win) kfree(win); if (wout) kfree(wout); return ret_err(EFAULT); } }
                    if (writefds_u && wout) { if (copy_to_user_safe(writefds_u, wout, bytes) != 0) { if (rin) kfree(rin); if (rout) kfree(rout); if (win) kfree(win); if (wout) kfree(wout); return ret_err(EFAULT); } }
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return (uint64_t)ready;
                }

                if (timeout_ms == 0) {
                    if (readfds_u && rout)  (void)copy_to_user_safe(readfds_u,  rout, bytes);
                    if (writefds_u && wout) (void)copy_to_user_safe(writefds_u, wout, bytes);
                    if (rin) kfree(rin); if (rout) kfree(rout);
                    if (win) kfree(win); if (wout) kfree(wout);
                    return 0;
                }

                int step = 10;
                if (timeout_ms > 0 && timeout_ms < step) step = timeout_ms;
                if (has_net_socket) e1000_poll();
                thread_sleep((uint32_t)step);
                if (timeout_ms > 0) timeout_ms -= step;
                goto auto_select_check;
            }
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
        case 222: { /* timer_create(clockid, sevp, timerid) - stub for vim E1286 */
            void *tid_u = (void*)(uintptr_t)a3;
            if (!tid_u) return ret_err(EFAULT);
            static int32_t stub_timer_id = 1;
            if (copy_to_user_safe(tid_u, &stub_timer_id, sizeof(stub_timer_id)) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 223: { /* timer_settime(timerid, flags, new_value, old_value) - no-op */
            return 0;
        }
        case 226: { /* timer_delete(timerid) - no-op */
            return 0;
        }
        case 38: { /* setitimer(which, new_value, old_value) - compatibility shim */
            const int ITIMER_REAL_LOCAL = 0;
            int which = (int)a1;
            const void *new_u = (const void *)(uintptr_t)a2;
            void *old_u = (void *)(uintptr_t)a3;
            if (which != ITIMER_REAL_LOCAL) return ret_err(EINVAL);
            struct timeval_k { int64_t tv_sec; int64_t tv_usec; };
            struct itimerval_k {
                struct timeval_k it_interval;
                struct timeval_k it_value;
            } nv, ov;
            memset(&ov, 0, sizeof(ov));
            ov.it_interval.tv_sec = (int64_t)(user_itimer_interval_ms / 1000u);
            ov.it_interval.tv_usec = (int64_t)((user_itimer_interval_ms % 1000u) * 1000u);
            ov.it_value = ov.it_interval;
            if (old_u && user_range_ok(old_u, sizeof(ov))) {
                (void)copy_to_user_safe(old_u, &ov, sizeof(ov));
            }
            if (!new_u) return 0;
            if (!user_range_ok(new_u, sizeof(nv))) return ret_err(EFAULT);
            if (copy_from_user_raw(&nv, new_u, sizeof(nv)) != 0) return ret_err(EFAULT);
            if (nv.it_interval.tv_sec < 0 || nv.it_interval.tv_usec < 0 ||
                nv.it_value.tv_sec < 0 || nv.it_value.tv_usec < 0) return ret_err(EINVAL);
            uint64_t interval_ms = (uint64_t)nv.it_interval.tv_sec * 1000ULL + (uint64_t)(nv.it_interval.tv_usec / 1000ULL);
            uint64_t value_ms = (uint64_t)nv.it_value.tv_sec * 1000ULL + (uint64_t)(nv.it_value.tv_usec / 1000ULL);
            uint64_t chosen = interval_ms ? interval_ms : value_ms;
            if (chosen > 0xFFFFFFFFULL) chosen = 0xFFFFFFFFULL;
            user_itimer_interval_ms = (uint32_t)chosen;
            return 0;
        }
        case SYS_socket: { /* socket(domain, type, protocol) */
            int domain = (int)a1;
            int type = (int)a2;
            int protocol = (int)a3;
            int unix_stub = 0;
            int type_base = type & 0x0F; /* mask SOCK_NONBLOCK/CLOEXEC flags */
            if (domain == AF_INET_LOCAL) {
                if (!(type_base == SOCK_RAW_LOCAL || type_base == SOCK_DGRAM_LOCAL || type_base == SOCK_STREAM_LOCAL)) return ret_err(ESOCKTNOSUPPORT);
                if (type_base == SOCK_RAW_LOCAL) {
                    if (!(protocol == 0 || protocol == IPPROTO_ICMP_LOCAL)) return ret_err(EPROTONOSUPPORT);
                } else if (type_base == SOCK_DGRAM_LOCAL) {
                    /* Protocol is normalized when storing s->protocol (glibc IPv6 path may pass 41, etc.). */
                } else { /* SOCK_STREAM_LOCAL */
                    if (!(protocol == 0 || protocol == IPPROTO_TCP_LOCAL)) return ret_err(EPROTONOSUPPORT);
                }
            } else if (domain == AF_NETLINK_LOCAL) {
                if (!(type_base == SOCK_RAW_LOCAL || type_base == SOCK_DGRAM_LOCAL)) return ret_err(ESOCKTNOSUPPORT);
                if (!(protocol == 0 || protocol == NETLINK_ROUTE_LOCAL)) return ret_err(EPROTONOSUPPORT);
                protocol = NETLINK_ROUTE_LOCAL;
            } else if (domain == AF_INET6) {
                /* Stub: create IPv4 socket when tools (wget) request IPv6 */
                domain = AF_INET_LOCAL;
            } else if (domain == AF_UNSPEC) {
                /* getaddrinfo/glibc may pass AF_UNSPEC; treat as IPv4 */
                domain = AF_INET_LOCAL;
            } else if (domain == 1) {
                /* AF_UNIX: stub as AF_INET in the kernel, but emulate connect/send/recv so nss/glibc
                   does not see ECONNREFUSED on nscd-style unix sockets (that breaks getaddrinfo). */
                unix_stub = 1;
                domain = AF_INET_LOCAL;
            } else {
                /* Compatibility: map any other domain to IPv4 (AF_PACKET, odd values from getaddrinfo, etc).
                   Avoids EAFNOSUPPORT causing wget to fail with "out of memory" (fdopen path). */
                domain = AF_INET_LOCAL;
            }
            ksock_net_t *s = (ksock_net_t *)kmalloc(sizeof(*s));
            struct fs_file *f = (struct fs_file *)kmalloc(sizeof(*f));
            char *p = (char *)kmalloc(24);
            if (!s || !f || !p) {
                if (s) kfree(s);
                if (f) kfree(f);
                if (p) kfree(p);
                return ret_err(ENOMEM);
            }
            memset(s, 0, sizeof(*s));
            memset(f, 0, sizeof(*f));
            if (domain == AF_NETLINK_LOCAL) snprintf(p, 24, "socket:[netlink]");
            else snprintf(p, 24, "socket:[icmp]");
            s->sock_domain = domain;
            s->unix_domain_stub = unix_stub;
            s->type_base = type_base;
            if (domain == AF_NETLINK_LOCAL) {
                s->protocol = NETLINK_ROUTE_LOCAL;
            } else if (type_base == SOCK_RAW_LOCAL) s->protocol = (protocol == 0) ? IPPROTO_ICMP_LOCAL : protocol;
            else if (type_base == SOCK_DGRAM_LOCAL) {
                /* Only SOCK_DGRAM + IPPROTO_ICMP is ping; everything else is UDP (DNS, resolver IPv6 sockets). */
                s->protocol = (protocol == IPPROTO_ICMP_LOCAL) ? IPPROTO_ICMP_LOCAL : IPPROTO_UDP_LOCAL;
            } else s->protocol = (protocol == 0) ? IPPROTO_TCP_LOCAL : protocol;
            s->connected = 0;
            s->peer_ip_be = 0;
            s->peer_port = 0;
            s->local_port = 0;
            s->next_echo_seq = 0;
            s->nonblock = (type & O_NONBLOCK_LINUX) ? 1 : 0;
            f->path = p;
            f->type = SYSCALL_FTYPE_SOCKET;
            f->driver_private = s;
            f->refcount = 1;
            int fd = thread_fd_alloc(f);
            if (fd < 0) {
                kfree(s);
                kfree((void *)f->path);
                kfree(f);
                return ret_err(EMFILE);
            }
            return (uint64_t)fd;
        }
        case 49: { /* bind */
            int fd = (int)a1;
            const void *addr_u = (const void *)(uintptr_t)a2;
            size_t addrlen = (size_t)a3;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (!addr_u || addrlen < sizeof(sockaddr_nl_k) || !user_range_ok(addr_u, sizeof(sockaddr_nl_k))) return ret_err(EFAULT);
                sockaddr_nl_k sa;
                if (copy_from_user_raw(&sa, addr_u, sizeof(sa)) != 0) return ret_err(EFAULT);
                if (sa.nl_family != AF_NETLINK_LOCAL) return ret_err(EAFNOSUPPORT);
                s->nl_pid = sa.nl_pid ? sa.nl_pid : (uint32_t)((t && t->tid) ? t->tid : 1);
                s->nl_groups = sa.nl_groups;
                return 0;
            }
            return 0;
        }
        case 42: { /* connect */
            int fd = (int)a1;
            const void *addr_u = (const void *)(uintptr_t)a2;
            size_t addrlen = (size_t)a3;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (!addr_u || addrlen < sizeof(sockaddr_nl_k) || !user_range_ok(addr_u, sizeof(sockaddr_nl_k))) return ret_err(EFAULT);
                sockaddr_nl_k sa;
                if (copy_from_user_raw(&sa, addr_u, sizeof(sa)) != 0) return ret_err(EFAULT);
                if (sa.nl_family != AF_NETLINK_LOCAL) return ret_err(EAFNOSUPPORT);
                s->nl_peer_pid = sa.nl_pid;
                s->connected = 1;
                if (s->nl_pid == 0) s->nl_pid = (uint32_t)((t && t->tid) ? t->tid : 1);
                return 0;
            }
            if (s->unix_domain_stub) {
                if (!addr_u || addrlen < sizeof(uint16_t) || !user_range_ok(addr_u, addrlen))
                    return ret_err(EFAULT);
                uint16_t fam = 0;
                if (copy_from_user_raw(&fam, addr_u, sizeof(fam)) != 0) return ret_err(EFAULT);
                if (fam == 1) { /* AF_UNIX */
                    s->connected = 1;
                    return 0;
                }
                /* Stub socket is backed by real IPv4 ksock; glibc may connect(AF_INET*) on this fd. */
            }
            sockaddr_in_k to;
            {
                int pa = user_sockaddr_to_ipv4_peer(addr_u, addrlen, &to);
                if (pa != 0) return ret_err(pa);
            }
            /* Inet peer: must not leave unix stub short-circuit in read/write/sendto paths. */
            s->unix_domain_stub = 0;
            if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                s->connected = 1;
                uint32_t pip = be32(to.sin_addr);
                uint16_t pp = be16(to.sin_port);
                /* resolv.conf on Linux often uses 127.0.0.53/127.0.0.1 — redirect to real DNS. */
                if (pp == 53u && (pip & 0xFF000000u) == 0x7F000000u) {
                    if (net_stack_init() == 0) {
                        uint32_t ns = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
                        if (ns) pip = ns;
                    }
                }
                s->peer_ip_be = pip;
                s->peer_port = pp;
                if (s->local_port == 0)
                    s->local_port = net_alloc_ephemeral_port();
                return 0;
            }
            if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                /* Userspace ABI: real Linux passes sin_addr in network byte order.
                   Our historical userland (netdiag) passed a swapped value.
                   To support both, try both interpretations on timeout. */
                uint32_t dst_ip_be = be32(to.sin_addr);
                uint32_t dst_ip_be_alt = to.sin_addr;
                uint16_t dport = be16(to.sin_port);
                /* glibc may try TCP to 127.0.0.1/127.0.0.53 :53 first; bridge to real nameserver over UDP. */
                if (dport == 53u) {
                    if (net_stack_init() != 0) return ret_err(ENETDOWN);
                    uint32_t peer = dst_ip_be;
                    if ((dst_ip_be & 0xFF000000u) == 0x7F000000u) {
                        peer = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
                        if (peer == 0) return ret_err(ENETDOWN);
                    }
                    s->connected = 1;
                    s->peer_ip_be = peer;
                    s->peer_port = dport;
                    if (s->local_port == 0)
                        s->local_port = net_alloc_ephemeral_port();
                    s->dns_tcp_udp_bridge = 1;
                    memset(&s->tcp, 0, sizeof(s->tcp));
                    return 0;
                }
                /* 127.0.0.1: loopback not implemented; return ECONNREFUSED immediately
                   instead of EIO timeout (no server listens on localhost). */
                if (dst_ip_be == 0x7F000001u)
                    return ret_err(ECONNREFUSED);
                if (net_stack_init() != 0) return ret_err(ENETDOWN);
                { uint8_t drain[256]; for (int d = 0; d < 64; d++) { e1000_poll(); if (e1000_recv_frame(drain, sizeof(drain)) <= 0) break; } }
                s->connected = 1;
                s->peer_ip_be = dst_ip_be;
                s->peer_port = be16(to.sin_port);
                if (s->local_port == 0)
                    s->local_port = net_alloc_ephemeral_port();
                net_tcp_ops_t ops;
                net_make_tcp_ops(&ops);
                int rc = net_tcp_connect(&s->tcp, &ops, s->peer_ip_be, s->peer_port, s->local_port, 45000);
                if (rc == -2 && dst_ip_be_alt != dst_ip_be) {
                    /* Retry with alternate byte order for glibc/wget sockaddr. */
                    s->peer_ip_be = dst_ip_be_alt;
                    rc = net_tcp_connect(&s->tcp, &ops, s->peer_ip_be, s->peer_port, s->local_port, 45000);
                }
                if (rc == -2) return ret_err(ETIMEDOUT);
                if (rc != 0) return ret_err(EIO);
                return 0;
            }
            return 0;
        }
        case 51: { /* getsockname */
            int fd = (int)a1;
            void *addr_u = (void *)(uintptr_t)a2;
            void *addrlen_u = (void *)(uintptr_t)a3;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (!addr_u || !addrlen_u || !user_range_ok(addrlen_u, 4)) return ret_err(EFAULT);
            uint32_t ulen = 0;
            if (copy_from_user_raw(&ulen, addrlen_u, 4) != 0) return ret_err(EFAULT);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                sockaddr_nl_k sa;
                memset(&sa, 0, sizeof(sa));
                sa.nl_family = AF_NETLINK_LOCAL;
                sa.nl_pid = s->nl_pid ? s->nl_pid : (uint32_t)((t && t->tid) ? t->tid : 1);
                sa.nl_groups = s->nl_groups;
                uint32_t copy_len = (ulen < (uint32_t)sizeof(sa)) ? ulen : (uint32_t)sizeof(sa);
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, &sa, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = (uint32_t)sizeof(sa);
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }

            sockaddr_in_k sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET_LOCAL;
            sa.sin_addr = be32(g_net.ip_be);
            if ((s->type_base == SOCK_DGRAM_LOCAL || s->type_base == SOCK_STREAM_LOCAL) && s->local_port) {
                sa.sin_port = be16(s->local_port);
            }

            uint32_t copy_len = (ulen < (uint32_t)sizeof(sa)) ? ulen : (uint32_t)sizeof(sa);
            if (copy_len > 0) {
                if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                if (copy_to_user_safe(addr_u, &sa, copy_len) != 0) return ret_err(EFAULT);
            }
            ulen = (uint32_t)sizeof(sa);
            if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 52: { /* getpeername */
            int fd = (int)a1;
            void *addr_u = (void *)(uintptr_t)a2;
            void *addrlen_u = (void *)(uintptr_t)a3;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (!s->connected) return ret_err(ENOTCONN);
            if (!addr_u || !addrlen_u || !user_range_ok(addrlen_u, 4)) return ret_err(EFAULT);
            uint32_t ulen = 0;
            if (copy_from_user_raw(&ulen, addrlen_u, 4) != 0) return ret_err(EFAULT);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                sockaddr_nl_k sa;
                memset(&sa, 0, sizeof(sa));
                sa.nl_family = AF_NETLINK_LOCAL;
                sa.nl_pid = s->nl_peer_pid;
                sa.nl_groups = 0;
                uint32_t copy_len = (ulen < (uint32_t)sizeof(sa)) ? ulen : (uint32_t)sizeof(sa);
                if (copy_len > 0) {
                    if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                    if (copy_to_user_safe(addr_u, &sa, copy_len) != 0) return ret_err(EFAULT);
                }
                ulen = (uint32_t)sizeof(sa);
                if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
                return 0;
            }

            sockaddr_in_k sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET_LOCAL;
            sa.sin_port = be16(s->peer_port);
            sa.sin_addr = be32(s->peer_ip_be);

            uint32_t copy_len = (ulen < (uint32_t)sizeof(sa)) ? ulen : (uint32_t)sizeof(sa);
            if (copy_len > 0) {
                if (!user_range_ok(addr_u, copy_len)) return ret_err(EFAULT);
                if (copy_to_user_safe(addr_u, &sa, copy_len) != 0) return ret_err(EFAULT);
            }
            ulen = (uint32_t)sizeof(sa);
            if (copy_to_user_safe(addrlen_u, &ulen, 4) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 54: { /* setsockopt */
            int fd = (int)a1;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            /* Minimal implementation: accept common ping options. */
            return 0;
        }
        case 55: { /* getsockopt */
            int fd = (int)a1;
            void *optval_u = (void *)(uintptr_t)a4;
            void *optlen_u = (void *)(uintptr_t)a5;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (!optlen_u || !user_range_ok(optlen_u, 4)) return ret_err(EFAULT);
            uint32_t olen = 0;
            if (copy_from_user_raw(&olen, optlen_u, 4) != 0) return ret_err(EFAULT);
            if (optval_u && olen >= 4) {
                uint32_t zero = 0;
                if (copy_to_user_safe(optval_u, &zero, 4) != 0) return ret_err(EFAULT);
                olen = 4;
            } else {
                olen = 0;
            }
            if (copy_to_user_safe(optlen_u, &olen, 4) != 0) return ret_err(EFAULT);
            return 0;
        }
        case 44: { /* sendto */
            int fd = (int)a1;
            const void *buf_u = (const void *)(uintptr_t)a2;
            size_t len = (size_t)a3;
            const void *to_u = (const void *)(uintptr_t)a5;
            size_t tolen = (size_t)a6;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            int dbg_wget = AXON_WGET_DNS_TRACE && t && t->name[0] && strstr(t->name, "wget");
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (!buf_u || len == 0) return ret_err(EINVAL);
                if (len < sizeof(nlmsghdr_k) || !user_range_ok(buf_u, len)) return ret_err(EFAULT);
                uint8_t pkt[256];
                size_t cp = (len > sizeof(pkt)) ? sizeof(pkt) : len;
                if (copy_from_user_raw(pkt, buf_u, cp) != 0) return ret_err(EFAULT);
                nlmsghdr_k *h = (nlmsghdr_k *)pkt;
                if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > len) return ret_err(EINVAL);
                if (s->nl_pid == 0) s->nl_pid = (uint32_t)((t && t->tid) ? t->tid : 1);
                (void)netlink_build_route_dump(s, h->nlmsg_type, h->nlmsg_seq);
                return (uint64_t)len;
            }
            if (s->unix_domain_stub) {
                if (!buf_u || len == 0 || len > 2048) return ret_err(EINVAL);
                if (!user_range_ok(buf_u, len)) return ret_err(EFAULT);
                return (uint64_t)len;
            }
            if (!buf_u || len == 0 || len > 2048) return ret_err(EINVAL);
            if (!user_range_ok(buf_u, len)) return ret_err(EFAULT);
            uint32_t dst_ip_be = 0;
            uint16_t dst_port = 0;
            if (to_u) {
                if (tolen < 2u || !user_range_ok(to_u, tolen)) return ret_err(EFAULT);
                sockaddr_in_k to;
                int pa = user_sockaddr_to_ipv4_peer(to_u, (size_t)tolen, &to);
                if (pa != 0) return ret_err(pa);
                dst_ip_be = be32(to.sin_addr); /* user sockaddr stores network-order bytes */
                dst_port = be16(to.sin_port);
                if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                    if (dst_port == 53u && (dst_ip_be & 0xFF000000u) == 0x7F000000u && net_stack_init() == 0) {
                        uint32_t ns = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
                        if (ns) dst_ip_be = ns;
                    }
                }
            } else if (s->connected) {
                dst_ip_be = s->peer_ip_be;
                dst_port = s->peer_port;
            } else {
                return ret_err(EDESTADDRREQ);
            }
            if (dbg_wget && s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL && dst_port == 53u) {
                klogprintf("WGET-DNS: sendto fd=%d len=%u dst=%u.%u.%u.%u:%u\n",
                    fd, (unsigned)len,
                    (unsigned)((dst_ip_be >> 24) & 0xFF), (unsigned)((dst_ip_be >> 16) & 0xFF),
                    (unsigned)((dst_ip_be >> 8) & 0xFF), (unsigned)(dst_ip_be & 0xFF),
                    (unsigned)dst_port);
            }
            uint8_t *icmp = (uint8_t *)kmalloc(len);
            if (!icmp) return ret_err(ENOMEM);
            if (copy_from_user_raw(icmp, buf_u, len) != 0) { kfree(icmp); return ret_err(EFAULT); }
            if (dbg_wget && s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL && dst_port == 53u && len >= 12) {
                uint16_t id = (uint16_t)(((uint16_t)icmp[0] << 8) | (uint16_t)icmp[1]);
                uint16_t flags_d = (uint16_t)(((uint16_t)icmp[2] << 8) | (uint16_t)icmp[3]);
                uint16_t qd = (uint16_t)(((uint16_t)icmp[4] << 8) | (uint16_t)icmp[5]);
                uint16_t an = (uint16_t)(((uint16_t)icmp[6] << 8) | (uint16_t)icmp[7]);
                uint16_t ns = (uint16_t)(((uint16_t)icmp[8] << 8) | (uint16_t)icmp[9]);
                uint16_t ar = (uint16_t)(((uint16_t)icmp[10] << 8) | (uint16_t)icmp[11]);
                klogprintf("WGET-DNS: qhdr id=0x%04x flags=0x%04x qd=%u an=%u ns=%u ar=%u\n",
                    (unsigned)id, (unsigned)flags_d,
                    (unsigned)qd, (unsigned)an, (unsigned)ns, (unsigned)ar);
            }
            int r = -1;
            if (s->protocol == IPPROTO_ICMP_LOCAL) {
                if (s->type_base == SOCK_RAW_LOCAL && len > 8) s->last_req_ts_fmt = net_detect_ping_ts_fmt(icmp + 8, len - 8);
                else s->last_req_ts_fmt = net_detect_ping_ts_fmt(icmp, len);
                s->last_req_len = len;
                memcpy(s->last_req, icmp, len);
                r = net_send_icmp_echo(s, dst_ip_be, icmp, len);
            } else if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                if (s->local_port == 0)
                    s->local_port = net_alloc_ephemeral_port();
                r = net_send_udp_datagram(dst_ip_be, s->local_port, dst_port, icmp, len);
            }
            kfree(icmp);
            if (dbg_wget && s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL && dst_port == 53u) {
                klogprintf("WGET-DNS: sendto result r=%d local_port=%u\n", r, (unsigned)s->local_port);
            }
            if (r != 0) return ret_err(e1000_is_ready() ? EIO : ENETDOWN);
            return (uint64_t)len;
        }
        case 45: { /* recvfrom */
            int fd = (int)a1;
            void *buf_u = (void *)(uintptr_t)a2;
            size_t len = (size_t)a3;
            int flags = (int)a4;
            void *from_u = (void *)(uintptr_t)a5;
            void *fromlen_u = (void *)(uintptr_t)a6;
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            int dbg_wget = AXON_WGET_DNS_TRACE && t && t->name[0] && strstr(t->name, "wget");
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (len == 0) return 0;
                if (!buf_u || !user_range_ok(buf_u, len)) return ret_err(EFAULT);
                if (s->nl_rx_off >= s->nl_rx_len) return ret_err(EAGAIN);
                size_t avail = s->nl_rx_len - s->nl_rx_off;
                size_t ncopy = (avail > len) ? len : avail;
                if (copy_to_user_safe(buf_u, s->nl_rx + s->nl_rx_off, ncopy) != 0) return ret_err(EFAULT);
                if (!(flags & 0x2)) s->nl_rx_off += ncopy; /* MSG_PEEK=0x2 */
                if (from_u && fromlen_u && user_range_ok(fromlen_u, 4)) {
                    uint32_t flen = 0;
                    if (copy_from_user_raw(&flen, fromlen_u, 4) == 0 && flen >= sizeof(sockaddr_nl_k) && user_range_ok(from_u, sizeof(sockaddr_nl_k))) {
                        sockaddr_nl_k sa;
                        memset(&sa, 0, sizeof(sa));
                        sa.nl_family = AF_NETLINK_LOCAL;
                        sa.nl_pid = 0; /* kernel */
                        sa.nl_groups = 0;
                        (void)copy_to_user_safe(from_u, &sa, sizeof(sa));
                        flen = sizeof(sa);
                        (void)copy_to_user_safe(fromlen_u, &flen, 4);
                    }
                }
                return (uint64_t)ncopy;
            }
            /* Linux-compatible: zero-length recv is valid even with NULL buffer. */
            if (len == 0) return 0;
            if (s->unix_domain_stub) {
                if (!buf_u || !user_range_ok(buf_u, len)) return ret_err(EFAULT);
                if (!s->connected) return ret_err(ENOTCONN);
                return 0;
            }
            if (!buf_u) {
                if (dbg_wget) qemu_debug_printf("RECVFROM-EFAULT: null buf with len=%llu\n", (unsigned long long)len);
                return ret_err(EFAULT);
            }
            size_t cap = len;
            if (cap > 8192) cap = 8192; /* defensive cap to avoid huge temporary allocations */
            uint8_t *tmp = (uint8_t *)kmalloc(cap);
            if (!tmp) return ret_err(ENOMEM);
            uint32_t src_ip = 0;
            uint16_t src_port = 0;
            int n = 0;
            enum { MSG_PEEK_LOCAL = 0x2, MSG_TRUNC_LOCAL = 0x20 };
            int is_peek = (flags & MSG_PEEK_LOCAL) ? 1 : 0;
            int want_trunc_len = (flags & MSG_TRUNC_LOCAL) ? 1 : 0;
            if (s->protocol == IPPROTO_ICMP_LOCAL) {
                uint32_t timeout_ms = user_itimer_interval_ms ? user_itimer_interval_ms : 2500u;
                int retries_left = 8; /* block longer: ~20s total before giving up */
                n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, &src_ip);
                while (n == 0 && retries_left-- > 0) {
                    if (user_itimer_interval_ms && s->last_dst_ip_be && s->last_req_len > 0)
                        (void)net_send_icmp_echo_timer_compat(s);
                    n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, &src_ip);
                }
            } else if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                if (dbg_wget && s->connected && s->peer_port == 53u) {
                    klogprintf("WGET-DNS: recvfrom fd=%d want=%u nonblock=%d\n",
                        fd, (unsigned)len, s->nonblock);
                }
                if (!s->rx_has_pending) {
                    int pr = net_udp_recv_into_pending(s);
                    if (pr != 1) n = (pr < 0) ? -1 : 0;
                }
                ksock_rx_pending_normalize(s);
                if (s->rx_has_pending) {
                    src_ip = s->rx_pending_src_ip_be;
                    src_port = s->rx_pending_src_port;
                    if (len == 0) {
                        n = want_trunc_len ? (int)s->rx_pending_len : 0;
                    } else {
                        size_t avail = ksock_rx_pending_avail(s);
                        n = (int)((avail > cap) ? cap : avail);
                        if (n > 0) memcpy(tmp, s->rx_pending + s->rx_pending_off, (size_t)n);
                    }
                    if (!is_peek) {
                        if (len == 0) {
                            s->rx_has_pending = 0;
                            s->rx_pending_off = 0;
                            s->rx_pending_len = 0;
                        } else {
                            s->rx_pending_off += (size_t)n;
                            if (s->rx_pending_off >= s->rx_pending_len) {
                                s->rx_has_pending = 0;
                                s->rx_pending_off = 0;
                                s->rx_pending_len = 0;
                            }
                        }
                    }
                }
                if (dbg_wget && s->connected && s->peer_port == 53u) {
                    klogprintf("WGET-DNS: recvfrom got=%d src=%u.%u.%u.%u:%u\n",
                        n,
                        (unsigned)((src_ip >> 24) & 0xFF), (unsigned)((src_ip >> 16) & 0xFF),
                        (unsigned)((src_ip >> 8) & 0xFF), (unsigned)(src_ip & 0xFF),
                        (unsigned)src_port);
                    if (n >= 12) {
                        /* DNS header: id, flags, qd, an, ns, ar */
                        uint16_t id = (uint16_t)(((uint16_t)tmp[0] << 8) | (uint16_t)tmp[1]);
                        uint16_t flags_d = (uint16_t)(((uint16_t)tmp[2] << 8) | (uint16_t)tmp[3]);
                        uint8_t rcode = (uint8_t)(flags_d & 0x0Fu);
                        uint16_t qd = (uint16_t)(((uint16_t)tmp[4] << 8) | (uint16_t)tmp[5]);
                        uint16_t an = (uint16_t)(((uint16_t)tmp[6] << 8) | (uint16_t)tmp[7]);
                        uint16_t ns = (uint16_t)(((uint16_t)tmp[8] << 8) | (uint16_t)tmp[9]);
                        uint16_t ar = (uint16_t)(((uint16_t)tmp[10] << 8) | (uint16_t)tmp[11]);
                        klogprintf("WGET-DNS: hdr id=0x%04x flags=0x%04x rcode=%u qd=%u an=%u ns=%u ar=%u\n",
                            (unsigned)id, (unsigned)flags_d, (unsigned)rcode,
                            (unsigned)qd, (unsigned)an, (unsigned)ns, (unsigned)ar);
                        int dump = (n < 32) ? n : 32;
                        klogprintf("WGET-DNS: hex0..%d:", dump - 1);
                        for (int i = 0; i < dump; i++) kprintf(" %02x", (unsigned)tmp[i]);
                        kprintf("\n");
                    }
                }
            } else {
                kfree(tmp);
                return ret_err(EOPNOTSUPP);
            }
            if (n == -4) {
                kfree(tmp);
                return syscall_do_inner(SYS_exit_group, 130, 0, 0, 0, 0, 0);
            }
            if (n < 0) { kfree(tmp); return ret_err(EIO); }
            if (n == 0) {
                kfree(tmp);
                if (s->protocol == IPPROTO_ICMP_LOCAL) return ret_err(ETIMEDOUT);
                if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL)
                    return ret_err(s->nonblock ? EAGAIN : ETIMEDOUT);
                return ret_err(EAGAIN);
            }
            if (copy_to_user_recv_safe(buf_u, tmp, (size_t)n) != 0) {
                if (dbg_wget) {
                    uintptr_t us = (uintptr_t)buf_u;
                    uintptr_t ue = us + (size_t)n;
                    qemu_debug_printf("RECVFROM-EFAULT: copy buf=%p n=%d us=0x%llx ue=0x%llx\n",
                        buf_u, n, (unsigned long long)us, (unsigned long long)ue);
                }
                kfree(tmp);
                return ret_err(EFAULT);
            }
            kfree(tmp);
            if (from_u && fromlen_u && user_range_ok(fromlen_u, 4)) {
                uint32_t flen = 0;
                if (copy_from_user_raw(&flen, fromlen_u, 4) == 0 && flen >= sizeof(sockaddr_in_k) && user_range_ok(from_u, sizeof(sockaddr_in_k))) {
                    sockaddr_in_k sa;
                    memset(&sa, 0, sizeof(sa));
                    sa.sin_family = AF_INET_LOCAL;
                    sa.sin_port = be16(src_port);
                    sa.sin_addr = be32(src_ip); /* keep sockaddr in network byte order */
                    (void)copy_to_user_safe(from_u, &sa, sizeof(sa));
                    uint32_t out_len = sizeof(sa);
                    (void)copy_to_user_safe(fromlen_u, &out_len, 4);
                }
            }
            return (uint64_t)n;
        }
        case 46: { /* sendmsg -> map to sendto for first iov */
            int fd = (int)a1;
            const void *msg_u = (const void *)(uintptr_t)a2;
            if (!msg_u || !user_range_ok(msg_u, 56)) return ret_err(EFAULT);
            struct msghdr_k {
                void *msg_name;
                uint32_t msg_namelen;
                uint32_t __pad0;
                void *msg_iov;
                uint64_t msg_iovlen;
                void *msg_control;
                uint64_t msg_controllen;
                int32_t msg_flags;
                int32_t __pad1;
            } m;
            if (copy_from_user_raw(&m, msg_u, sizeof(m)) != 0) return ret_err(EFAULT);
            if (!m.msg_iov || m.msg_iovlen < 1 || !user_range_ok(m.msg_iov, 16)) return ret_err(EFAULT);
            struct iovec_k { void *base; uint64_t len; } iov;
            if (copy_from_user_raw(&iov, m.msg_iov, sizeof(iov)) != 0) return ret_err(EFAULT);
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (!iov.base || iov.len < sizeof(nlmsghdr_k) || !user_range_ok(iov.base, (size_t)iov.len)) return ret_err(EFAULT);
                uint8_t pkt[256];
                size_t cp = ((size_t)iov.len > sizeof(pkt)) ? sizeof(pkt) : (size_t)iov.len;
                if (copy_from_user_raw(pkt, iov.base, cp) != 0) return ret_err(EFAULT);
                nlmsghdr_k *h = (nlmsghdr_k *)pkt;
                if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > (size_t)iov.len) return ret_err(EINVAL);
                if (s->nl_pid == 0) s->nl_pid = (uint32_t)((t && t->tid) ? t->tid : 1);
                (void)netlink_build_route_dump(s, h->nlmsg_type, h->nlmsg_seq);
                return (uint64_t)iov.len;
            }
            if (!iov.base || iov.len == 0 || iov.len > 2048 || !user_range_ok(iov.base, (size_t)iov.len)) return ret_err(EFAULT);
            if (s->unix_domain_stub)
                return (uint64_t)iov.len;
            uint32_t dst_ip_be = 0;
            uint16_t dst_port = 0;
            if (m.msg_name && m.msg_namelen >= 2u && user_range_ok(m.msg_name, (size_t)m.msg_namelen)) {
                sockaddr_in_k to;
                int pa = user_sockaddr_to_ipv4_peer(m.msg_name, (size_t)m.msg_namelen, &to);
                if (pa != 0) return ret_err(pa);
                dst_ip_be = be32(to.sin_addr);
                dst_port = be16(to.sin_port);
                if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) &&
                    dst_port == 53u && (dst_ip_be & 0xFF000000u) == 0x7F000000u && net_stack_init() == 0) {
                    uint32_t ns = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
                    if (ns) dst_ip_be = ns;
                }
            } else if (s->connected) {
                dst_ip_be = s->peer_ip_be;
                dst_port = s->peer_port;
            } else {
                return ret_err(EDESTADDRREQ);
            }
            uint8_t *icmp = (uint8_t *)kmalloc((size_t)iov.len);
            if (!icmp) return ret_err(ENOMEM);
            if (copy_from_user_raw(icmp, iov.base, (size_t)iov.len) != 0) { kfree(icmp); return ret_err(EFAULT); }
            int r = -1;
            if (s->protocol == IPPROTO_ICMP_LOCAL) {
                if (s->type_base == SOCK_RAW_LOCAL && (size_t)iov.len > 8) s->last_req_ts_fmt = net_detect_ping_ts_fmt(icmp + 8, (size_t)iov.len - 8);
                else s->last_req_ts_fmt = net_detect_ping_ts_fmt(icmp, (size_t)iov.len);
                s->last_req_len = (size_t)iov.len;
                memcpy(s->last_req, icmp, (size_t)iov.len);
                r = net_send_icmp_echo(s, dst_ip_be, icmp, (size_t)iov.len);
            } else if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                       (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge)) {
                if (s->local_port == 0)
                    s->local_port = net_alloc_ephemeral_port();
                r = net_send_udp_datagram(dst_ip_be, s->local_port, dst_port, icmp, (size_t)iov.len);
            }
            kfree(icmp);
            if (r != 0) return ret_err(e1000_is_ready() ? EIO : ENETDOWN);
            return iov.len;
        }
        case 307: { /* sendmmsg: minimal, first message only */
            int fd = (int)a1;
            const void *mmsg_u = (const void *)(uintptr_t)a2;
            uint32_t vlen = (uint32_t)a3;
            (void)a4; /* flags */
            if (!mmsg_u || vlen == 0) return ret_err(EFAULT);
            struct msghdr_k {
                void *msg_name;
                uint32_t msg_namelen;
                uint32_t __pad0;
                void *msg_iov;
                uint64_t msg_iovlen;
                void *msg_control;
                uint64_t msg_controllen;
                int32_t msg_flags;
                int32_t __pad1;
            };
            struct mmsghdr_k {
                struct msghdr_k msg_hdr;
                uint32_t msg_len;
                uint32_t __pad;
            } mm;
            if (!user_range_ok(mmsg_u, sizeof(mm))) return ret_err(EFAULT);
            if (copy_from_user_raw(&mm, mmsg_u, sizeof(mm)) != 0) return ret_err(EFAULT);
            if (!mm.msg_hdr.msg_iov || mm.msg_hdr.msg_iovlen < 1 || !user_range_ok(mm.msg_hdr.msg_iov, 16)) return ret_err(EFAULT);
            struct iovec_k { void *base; uint64_t len; } iov;
            if (copy_from_user_raw(&iov, mm.msg_hdr.msg_iov, sizeof(iov)) != 0) return ret_err(EFAULT);
            if (!iov.base || iov.len == 0 || iov.len > 2048 || !user_range_ok(iov.base, (size_t)iov.len)) return ret_err(EFAULT);

            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (!iov.base || iov.len < sizeof(nlmsghdr_k) || !user_range_ok(iov.base, (size_t)iov.len)) return ret_err(EFAULT);
                uint8_t pkt[256];
                size_t cp = ((size_t)iov.len > sizeof(pkt)) ? sizeof(pkt) : (size_t)iov.len;
                if (copy_from_user_raw(pkt, iov.base, cp) != 0) return ret_err(EFAULT);
                nlmsghdr_k *h = (nlmsghdr_k *)pkt;
                if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > (size_t)iov.len) return ret_err(EINVAL);
                if (s->nl_pid == 0) s->nl_pid = (uint32_t)((t && t->tid) ? t->tid : 1);
                (void)netlink_build_route_dump(s, h->nlmsg_type, h->nlmsg_seq);
                mm.msg_len = (uint32_t)iov.len;
                (void)copy_to_user_safe((void *)mmsg_u, &mm, sizeof(mm));
                return 1;
            }
            if (s->unix_domain_stub) {
                mm.msg_len = (uint32_t)iov.len;
                (void)copy_to_user_safe((void *)mmsg_u, &mm, sizeof(mm));
                return 1;
            }

            uint32_t dst_ip_be = 0;
            uint16_t dst_port = 0;
            if (mm.msg_hdr.msg_name && mm.msg_hdr.msg_namelen >= 2u && user_range_ok(mm.msg_hdr.msg_name, (size_t)mm.msg_hdr.msg_namelen)) {
                sockaddr_in_k to;
                int pa = user_sockaddr_to_ipv4_peer(mm.msg_hdr.msg_name, (size_t)mm.msg_hdr.msg_namelen, &to);
                if (pa != 0) return ret_err(pa);
                dst_ip_be = be32(to.sin_addr);
                dst_port = be16(to.sin_port);
                if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) &&
                    dst_port == 53u && (dst_ip_be & 0xFF000000u) == 0x7F000000u && net_stack_init() == 0) {
                    uint32_t ns = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
                    if (ns) dst_ip_be = ns;
                }
            } else if (s->connected) {
                dst_ip_be = s->peer_ip_be;
                dst_port = s->peer_port;
            } else {
                return ret_err(EDESTADDRREQ);
            }

            uint8_t *pkt = (uint8_t *)kmalloc((size_t)iov.len);
            if (!pkt) return ret_err(ENOMEM);
            if (copy_from_user_raw(pkt, iov.base, (size_t)iov.len) != 0) { kfree(pkt); return ret_err(EFAULT); }

            int r = -1;
            /* ICMP first (sendmsg order); UDP for datagram != ICMP or DNS-over-UDP TCP bridge. */
            if (s->protocol == IPPROTO_ICMP_LOCAL) {
                r = net_send_icmp_echo(s, dst_ip_be, pkt, (size_t)iov.len);
            } else if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol != IPPROTO_ICMP_LOCAL) ||
                       (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge)) {
                if (s->local_port == 0)
                    s->local_port = net_alloc_ephemeral_port();
                r = net_send_udp_datagram(dst_ip_be, s->local_port, dst_port, pkt, (size_t)iov.len);
            }
            kfree(pkt);
            if (r != 0) return ret_err(e1000_is_ready() ? EIO : ENETDOWN);

            mm.msg_len = (uint32_t)iov.len;
            (void)copy_to_user_safe((void *)mmsg_u, &mm, sizeof(mm));
            return 1; /* one message sent */
        }
        case 47: { /* recvmsg -> map to recvfrom for first iov */
            int fd = (int)a1;
            void *msg_u = (void *)(uintptr_t)a2;
            int flags = (int)a3;
            if (!msg_u || !user_range_ok(msg_u, 56)) return ret_err(EFAULT);
            struct msghdr_k {
                void *msg_name;
                uint32_t msg_namelen;
                uint32_t __pad0;
                void *msg_iov;
                uint64_t msg_iovlen;
                void *msg_control;
                uint64_t msg_controllen;
                int32_t msg_flags;
                int32_t __pad1;
            } m;
            if (copy_from_user_raw(&m, msg_u, sizeof(m)) != 0) return ret_err(EFAULT);
            if (!m.msg_iov || m.msg_iovlen < 1 || !user_range_ok(m.msg_iov, 16)) return ret_err(EFAULT);
            struct iovec_k { void *base; uint64_t len; } iov;
            if (copy_from_user_raw(&iov, m.msg_iov, sizeof(iov)) != 0) return ret_err(EFAULT);
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            int dbg_wget = AXON_WGET_DNS_TRACE && t && t->name[0] && strstr(t->name, "wget");
            ksock_net_t *s = NULL;
            if (!socket_file_get(t, fd, &s) || !s) return ret_err(EBADF);
            if (s->sock_domain == AF_NETLINK_LOCAL) {
                if (iov.len == 0) return 0;
                if (!iov.base || !user_range_ok(iov.base, (size_t)iov.len)) return ret_err(EFAULT);
                if (s->nl_rx_off >= s->nl_rx_len) return ret_err(EAGAIN);
                size_t avail = s->nl_rx_len - s->nl_rx_off;
                size_t ncopy = (avail > (size_t)iov.len) ? (size_t)iov.len : avail;
                if (copy_to_user_safe(iov.base, s->nl_rx + s->nl_rx_off, ncopy) != 0) return ret_err(EFAULT);
                if (!(flags & 0x2)) s->nl_rx_off += ncopy; /* MSG_PEEK */
                if (m.msg_name && m.msg_namelen >= sizeof(sockaddr_nl_k) && user_range_ok(m.msg_name, sizeof(sockaddr_nl_k))) {
                    sockaddr_nl_k sa;
                    memset(&sa, 0, sizeof(sa));
                    sa.nl_family = AF_NETLINK_LOCAL;
                    sa.nl_pid = 0; /* kernel */
                    (void)copy_to_user_safe(m.msg_name, &sa, sizeof(sa));
                }
                if (m.msg_name && user_range_ok(msg_u, sizeof(m))) {
                    m.msg_namelen = sizeof(sockaddr_nl_k);
                    (void)copy_to_user_safe(msg_u, &m, sizeof(m));
                }
                return (uint64_t)ncopy;
            }
            /* Linux-compatible: zero-length recvmsg iov is valid. */
            if (iov.len == 0) return 0;
            if (s->unix_domain_stub) {
                if (!iov.base || !user_range_ok(iov.base, (size_t)iov.len)) return ret_err(EFAULT);
                if (!s->connected) return ret_err(ENOTCONN);
                return 0;
            }
            if (!iov.base) {
                if (dbg_wget) qemu_debug_printf("RECVMSG-EFAULT: null base with len=%llu\n", (unsigned long long)iov.len);
                return ret_err(EFAULT);
            }
            size_t cap = (size_t)iov.len;
            if (cap > 8192) cap = 8192;
            uint8_t *tmp = (uint8_t *)kmalloc(cap);
            if (!tmp) return ret_err(ENOMEM);
            uint32_t src_ip = 0;
            uint16_t src_port = 0;
            int n = 0;
            enum { MSG_PEEK_LOCAL = 0x2, MSG_TRUNC_LOCAL = 0x20 };
            int is_peek = (flags & MSG_PEEK_LOCAL) ? 1 : 0;
            int want_trunc_len = (flags & MSG_TRUNC_LOCAL) ? 1 : 0;
            if (s->protocol == IPPROTO_ICMP_LOCAL) {
                uint32_t timeout_ms = user_itimer_interval_ms ? user_itimer_interval_ms : 2500u;
                int retries_left = 8; /* block longer: ~20s total before giving up */
                n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, &src_ip);
                while (n == 0 && retries_left-- > 0) {
                    if (user_itimer_interval_ms && s->last_dst_ip_be && s->last_req_len > 0)
                        (void)net_send_icmp_echo_timer_compat(s);
                    n = net_recv_icmp_echo_reply(s, tmp, cap, timeout_ms, &src_ip);
                }
            } else if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                       (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge)) {
                if (dbg_wget && s->connected && s->peer_port == 53u) {
                    klogprintf("WGET-DNS: recvmsg fd=%d want=%u nonblock=%d\n",
                        fd, (unsigned)iov.len, s->nonblock);
                }
                if (!s->rx_has_pending) {
                    int pr = net_udp_recv_into_pending(s);
                    if (pr != 1) n = (pr < 0) ? -1 : 0;
                }
                ksock_rx_pending_normalize(s);
                if (s->rx_has_pending) {
                    src_ip = s->rx_pending_src_ip_be;
                    src_port = s->rx_pending_src_port;
                    if (iov.len == 0) {
                        n = want_trunc_len ? (int)s->rx_pending_len : 0;
                    } else {
                        size_t avail = ksock_rx_pending_avail(s);
                        n = (int)((avail > cap) ? cap : avail);
                        if (n > 0) memcpy(tmp, s->rx_pending + s->rx_pending_off, (size_t)n);
                    }
                    if (!is_peek) {
                        if (iov.len == 0) {
                            s->rx_has_pending = 0;
                            s->rx_pending_off = 0;
                            s->rx_pending_len = 0;
                        } else {
                            s->rx_pending_off += (size_t)n;
                            if (s->rx_pending_off >= s->rx_pending_len) {
                                s->rx_has_pending = 0;
                                s->rx_pending_off = 0;
                                s->rx_pending_len = 0;
                            }
                        }
                    }
                }
                if (dbg_wget && s->connected && s->peer_port == 53u) {
                    klogprintf("WGET-DNS: recvmsg got=%d src=%u.%u.%u.%u:%u\n",
                        n,
                        (unsigned)((src_ip >> 24) & 0xFF), (unsigned)((src_ip >> 16) & 0xFF),
                        (unsigned)((src_ip >> 8) & 0xFF), (unsigned)(src_ip & 0xFF),
                        (unsigned)src_port);
                }
            } else {
                kfree(tmp);
                return ret_err(EOPNOTSUPP);
            }
            if (n == -4) {
                kfree(tmp);
                return syscall_do_inner(SYS_exit_group, 130, 0, 0, 0, 0, 0);
            }
            if (n < 0) { kfree(tmp); return ret_err(EIO); }
            if (n == 0) {
                kfree(tmp);
                if (s->protocol == IPPROTO_ICMP_LOCAL) return ret_err(ETIMEDOUT);
                if ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                    (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge))
                    return ret_err(s->nonblock ? EAGAIN : ETIMEDOUT);
                return ret_err(EAGAIN);
            }
            if (copy_to_user_recv_safe(iov.base, tmp, (size_t)n) != 0) {
                if (dbg_wget) {
                    uintptr_t us = (uintptr_t)iov.base;
                    uintptr_t ue = us + (size_t)n;
                    qemu_debug_printf("RECVMSG-EFAULT: copy base=%p n=%d us=0x%llx ue=0x%llx\n",
                        iov.base, n, (unsigned long long)us, (unsigned long long)ue);
                }
                kfree(tmp);
                return ret_err(EFAULT);
            }
            kfree(tmp);
            uint32_t fromlen = sizeof(sockaddr_in_k);
            if (m.msg_name && m.msg_namelen >= sizeof(sockaddr_in_k) && user_range_ok(m.msg_name, sizeof(sockaddr_in_k))) {
                sockaddr_in_k sa;
                memset(&sa, 0, sizeof(sa));
                sa.sin_family = AF_INET_LOCAL;
                sa.sin_port = be16(src_port);
                sa.sin_addr = be32(src_ip);
                (void)copy_to_user_safe(m.msg_name, &sa, sizeof(sa));
            }
            /* keep msg_namelen in sync */
            if (m.msg_name && user_range_ok(msg_u, sizeof(m))) {
                m.msg_namelen = fromlen;
                (void)copy_to_user_safe(msg_u, &m, sizeof(m));
            }
            return (uint64_t)n;
        }
        case 299: { /* recvmmsg — Linux x86_64; glibc resolver may batch reads */
            int fd = (int)a1;
            void *mmsg_u = (void *)(uintptr_t)a2;
            unsigned int vlen = (unsigned int)a3;
            int flags = (int)a4;
            (void)a5;
            if (!mmsg_u || vlen == 0) return ret_err(EINVAL);
            /* One struct mmsghdr: msghdr (matches our msghdr_k) + msg_len */
            if (!user_range_ok(mmsg_u, 64)) return ret_err(EFAULT);
            uint64_t r = syscall_do_inner(47, (uint64_t)fd, (uint64_t)mmsg_u, (uint64_t)flags, 0, 0, 0);
            if ((int64_t)r < 0) return r;
            uint32_t mlen = (uint32_t)r;
            /* After Linux struct msghdr (56 bytes on x86_64) */
            if (copy_to_user_safe((uint8_t *)mmsg_u + 56, &mlen, sizeof(mlen)) != 0) return ret_err(EFAULT);
            return 1;
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
            unsigned long loads[3];
            loadavg_get_user(loads);
            memcpy(buf + 8, loads, 24);
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
            uint64_t mask = smp_default_affinity_mask();
            size_t copy = len < 8 ? len : 8;
            if (copy_to_user_safe(mask_u, &mask, copy) != 0) return ret_err(EFAULT);
            for (size_t i = 8; i < len; i++) {
                char zero = 0;
                if (copy_to_user_safe((char*)mask_u + i, &zero, 1) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
#ifndef PRIO_PROCESS
#define PRIO_PROCESS 0
#endif
        case SYS_getpriority: { /* getpriority(which, who) */
            int which = (int)a1;
            int who = (int)a2;
            if (which != PRIO_PROCESS) return ret_err(EINVAL);
            thread_t *t = (who == 0) ? cur : thread_get(who);
            if (!t) return ret_err(ESRCH);
            return (uint64_t)(int64_t)t->nice;
        }
        case SYS_setpriority: { /* setpriority(which, who, prio) — Linux nice -20..19 */
            int which = (int)a1;
            int who = (int)a2;
            int nicev = (int)a3;
            if (which != PRIO_PROCESS) return ret_err(EINVAL);
            if (thread_nice_set(who, nicev) != 0) return ret_err(ESRCH);
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
                F_GETLK = 5,
                F_SETLK = 6,
                F_SETLKW = 7,
                F_DUPFD_CLOEXEC = 1030,
            };
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (cmd == F_DUPFD_CLOEXEC) {
                /* Same as F_DUPFD; we do not track FD_CLOEXEC, accept for compatibility */
                cmd = F_DUPFD;
            }
            if (cmd == F_SETLK || cmd == F_SETLKW || cmd == F_GETLK) {
                /* File locking: stub as success (no-op). Busybox adduser uses flock on /etc/passwd;
                   without this it gets EINVAL and exits silently. */
                (void)arg;
                if (cmd == F_GETLK && arg) {
                    /* F_GETLK: write flock struct with l_type=F_UNLCK to indicate "not locked" */
                    if (user_range_ok((void*)(uintptr_t)arg, 32)) {
                        uint8_t zeros[32];
                        memset(zeros, 0, sizeof(zeros));
                        copy_to_user_safe((void*)(uintptr_t)arg, zeros, 32);
                    }
                }
                return 0;
            }
            if (cmd == F_GETFD) {
                /* return flags (no FD_CLOEXEC support) */
                return 0;
            } else if (cmd == F_SETFD) {
                /* accept silently */
                (void)arg;
                return 0;
            } else if (cmd == F_GETFL) {
                if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                    ksock_net_t *sk = (ksock_net_t *)f->driver_private;
                    int fl = O_RDWR_LINUX;
                    if (sk->nonblock) fl |= O_NONBLOCK_LINUX;
                    return (uint64_t)(unsigned)fl;
                }
                /* For regular files/dirs/pipes: we don't track flags yet; return accmode only so fdopen() works. */
                return (uint64_t)(unsigned)O_RDWR_LINUX;
            } else if (cmd == F_SETFL) {
                if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                    ksock_net_t *sk = (ksock_net_t *)f->driver_private;
                    sk->nonblock = (arg & O_NONBLOCK_LINUX) ? 1 : 0;
                }
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
        case 73: { /* flock(fd, operation) - stub as success. Busybox adduser uses flock on /etc/passwd. */
            (void)a1; (void)a2;
            return 0;
        }
        case 74: /* fsync(fd) */
        case 75: { /* fdatasync(fd) - adduser syncs passwd before rename */
            int fd = (int)a1;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!cur->fds[fd]) return ret_err(EBADF);
            return 0;
        }
        case 162: { /* sync() - no-op */
            return 0;
        }
        case 270: {
            /* pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask).
             * Convert fd_sets to pollfds and delegate to poll logic so vim blocks on TTY input. */
            int nfds = (int)a1;
            void *readfds_u = (void*)(uintptr_t)a2;
            void *writefds_u = (void*)(uintptr_t)a3;
            void *exceptfds_u = (void*)(uintptr_t)a4;
            const void *tmo_u = (const void*)(uintptr_t)a5;
            (void)a6; /* sigmask - ignore */
            if (nfds < 0 || nfds > 1024) return ret_err(EINVAL);
            size_t fdset_size = 128; /* fd_set is 16*8 bytes */
            uint64_t read_buf[16], write_buf[16], except_buf[16];
            if (copy_from_user_raw(read_buf, readfds_u, fdset_size) != 0) return ret_err(EFAULT);
            if (copy_from_user_raw(write_buf, writefds_u, fdset_size) != 0) return ret_err(EFAULT);
            if (copy_from_user_raw(except_buf, exceptfds_u, fdset_size) != 0) return ret_err(EFAULT);
            int timeout_ms = -1;
            if (tmo_u) {
                struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
                if (copy_from_user_raw(&ts, tmo_u, sizeof(ts)) != 0) return ret_err(EFAULT);
                if (ts.tv_sec < 0 || ts.tv_nsec < 0) return ret_err(EINVAL);
                uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
                if (ms == 0 && ts.tv_nsec > 0) ms = 1;
                if (ms > 0x7FFFFFFFULL) ms = 0x7FFFFFFFULL;
                timeout_ms = (int)ms;
            }
            /* Build pollfd array from fd_sets */
            struct pollfd_k { int fd; short events; short revents; } pollfds[256];
            int npoll = 0;
            for (int fd = 0; fd < nfds && npoll < 256; fd++) {
                int w = fd / 64; int b = fd % 64;
                short ev = 0;
                if ((read_buf[w] >> b) & 1) ev |= 0x001;  /* POLLIN */
                if ((write_buf[w] >> b) & 1) ev |= 0x004; /* POLLOUT */
                if ((except_buf[w] >> b) & 1) ev |= 0x008;/* POLLERR */
                if (ev) { pollfds[npoll].fd = fd; pollfds[npoll].events = ev; pollfds[npoll].revents = 0; npoll++; }
            }
            if (npoll == 0) {
                if (timeout_ms <= 0) return 0;
                if (timeout_ms < 0) { for (;;) thread_sleep(10); }
                int waited = 0;
                while (waited < timeout_ms) { thread_sleep(10); waited += 10; }
                return 0;
            }
            /* Poll loop: check readiness, block on TTY if needed */
            enum { POLLIN_K = 0x001, POLLOUT_K = 0x004, POLLERR_K = 0x008 };
            thread_t *curth = thread_get_current_user();
            if (!curth) curth = thread_current();
            int tty_waiting[16], n_tty = 0;
            for (;;) {
                int ready = 0;
                for (int i = 0; i < npoll; i++) {
                    int fd = pollfds[i].fd;
                    short ev = pollfds[i].events;
                    short rev = 0;
                    if (fd < 0 || fd >= THREAD_MAX_FD) { rev = 0x020; }
                    else {
                        struct fs_file *f = curth ? curth->fds[fd] : NULL;
                        if (!f) rev = 0x020;
                        else if (devfs_is_tty_file(f)) {
                            int tidx = devfs_get_tty_index_from_file(f);
                            if (tidx < 0) tidx = devfs_get_active();
                            if ((ev & POLLIN_K) && devfs_tty_available(tidx) > 0) rev |= POLLIN_K;
                        } else if (f->type == FS_TYPE_PIPE && f->driver_private) {
                            pipe_t *p = (pipe_t *)f->driver_private;
                            unsigned long fl; acquire_irqsave(&p->lock, &fl);
                            size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
                            int is_we = (f->fs_private == (void *)1);
                            release_irqrestore(&p->lock, fl);
                            if (!is_we && (ev & POLLIN_K) && used > 0) rev |= POLLIN_K;
                            if (is_we && (ev & POLLOUT_K) && (p->size - 1 - used) > 0) rev |= POLLOUT_K;
                        } else if (ev & POLLIN_K && f->type != FS_TYPE_DIR && (size_t)f->pos < (size_t)f->size) rev |= POLLIN_K;
                    }
                    pollfds[i].revents = rev;
                    if (rev) ready++;
                }
                if (ready > 0) {
                    memset(read_buf, 0, sizeof(read_buf));
                    memset(write_buf, 0, sizeof(write_buf));
                    memset(except_buf, 0, sizeof(except_buf));
                    for (int i = 0; i < npoll; i++) {
                        int fd = pollfds[i].fd;
                        short rev = pollfds[i].revents;
                        int w = fd / 64, b = fd % 64;
                        if (rev & POLLIN_K) read_buf[w] |= (1ULL << b);
                        if (rev & POLLOUT_K) write_buf[w] |= (1ULL << b);
                        if (rev & POLLERR_K) except_buf[w] |= (1ULL << b);
                    }
                    if (copy_to_user_safe(readfds_u, read_buf, fdset_size) != 0) return ret_err(EFAULT);
                    if (copy_to_user_safe(writefds_u, write_buf, fdset_size) != 0) return ret_err(EFAULT);
                    if (copy_to_user_safe(exceptfds_u, except_buf, fdset_size) != 0) return ret_err(EFAULT);
                    return (uint64_t)ready;
                }
                if (timeout_ms == 0) return 0;
                n_tty = 0;
                int cur_tid = curth ? (int)curth->tid : -1;
                for (int i = 0; i < npoll && n_tty < 16; i++) {
                    if (!(pollfds[i].events & POLLIN_K)) continue;
                    int fd = pollfds[i].fd;
                    if (fd < 0 || fd >= THREAD_MAX_FD) continue;
                    struct fs_file *f = curth ? curth->fds[fd] : NULL;
                    if (!f || !devfs_is_tty_file(f)) continue;
                    int tidx = devfs_get_tty_index_from_file(f);
                    if (tidx < 0) tidx = devfs_get_active();
                    if (devfs_tty_add_waiter(tidx, cur_tid) == 0) tty_waiting[n_tty++] = tidx;
                }
                if (n_tty > 0 && timeout_ms < 0) {
                    thread_block(cur_tid);
                    thread_yield();
                    for (int w = 0; w < n_tty; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                    continue;
                }
                if (n_tty > 0 && timeout_ms > 0) {
                    thread_block_with_timeout(cur_tid, (uint32_t)timeout_ms);
                    thread_yield();
                    for (int w = 0; w < n_tty; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                    continue;
                }
                thread_sleep(10);
                if (timeout_ms > 0) {
                    timeout_ms -= 10;
                    if (timeout_ms <= 0) return 0;
                }
            }
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
            if (signum <= 0 || signum >= (int)(sizeof(user_sig_actions)/sizeof(user_sig_actions[0]))) return ret_err(EINVAL);

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
                sa.handler = (uint64_t)(uintptr_t)user_sig_actions[signum].handler;
                sa.flags = user_sig_actions[signum].flags;
                sa.restorer = user_sig_actions[signum].restorer;
                if (copy_to_user_safe(old_u, &sa, act_sz) != 0) return ret_err(EFAULT);
            }
            if (act_u) {
                memset(&sa, 0, sizeof(sa));
                if (copy_from_user_raw(&sa, act_u, act_sz) != 0) return ret_err(EFAULT);
                user_sig_actions[signum].handler = (user_sighandler_t)(uintptr_t)sa.handler;
                user_sig_actions[signum].flags = sa.flags;
                user_sig_actions[signum].restorer = sa.restorer;
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
            if (!path) { qemu_debug_printf("OOM execve: path plen=%llu\n", (unsigned long long)(plen+1)); return ret_err(ENOMEM); }
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
            if (!kargv) { qemu_debug_printf("OOM execve: kargv argc=%d\n", argc); kfree(path); return ret_err(ENOMEM); }
            for (int i = 0; i < argc; i++) {
                uint64_t a_up = 0;
                if (user_read_u64((const void*)(uintptr_t)(&argv_u[i]), &a_up) != 0) {
                    kfree((void*)kargv); kfree(path); return ret_err(EFAULT);
                }
                const char *a_u = (const char*)(uintptr_t)a_up;
                if (!a_u || !user_range_ok(a_u, 1)) { kfree((void*)kargv); kfree(path); return ret_err(EFAULT); }
                size_t L = user_strnlen_bounded(a_u, 4096);
                char *ks = (char*)kmalloc(L + 1);
                if (!ks) { qemu_debug_printf("OOM execve: argv[%d] L=%llu\n", i, (unsigned long long)(L+1)); for (int j=0;j<i;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(ENOMEM); }
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
                if (!kenvp) { qemu_debug_printf("OOM execve: kenvp envc=%d\n", envc); for (int j=0;j<argc;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(ENOMEM); }
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
                    if (!ks) { qemu_debug_printf("OOM execve: envp[%d] L=%llu\n", i, (unsigned long long)(L+1)); for (int j=0;j<i;j++) kfree((void*)kenvp[j]); kfree(kenvp); for (int j=0;j<argc;j++) kfree((void*)kargv[j]); kfree((void*)kargv); kfree(path); return ret_err(ENOMEM); }
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
               Per-thread signal mask; use cur->saved_sig_mask for user threads. */
            int how = (int)a1;
            const void *set_u = (const void*)(uintptr_t)a2;
            void *old_u = (void*)(uintptr_t)a3;
            (void)a4;
            uint64_t *p_mask = (cur && cur->ring == 3) ? &cur->saved_sig_mask : &user_sig_mask;

            if (old_u) {
                uint64_t old = *p_mask;
                if (copy_to_user_safe(old_u, &old, sizeof(old)) != 0) return ret_err(EFAULT);
            }
            if (set_u) {
                uint64_t setv = 0;
                if (copy_from_user_raw(&setv, set_u, sizeof(setv)) != 0) return ret_err(EFAULT);
                if (how == 0 /* SIG_BLOCK */) *p_mask |= setv;
                else if (how == 1 /* SIG_UNBLOCK */) *p_mask &= ~setv;
                else if (how == 2 /* SIG_SETMASK */) *p_mask = setv;
                else return ret_err(EINVAL);
            }
            return 0;
        }
        case SYS_fork: {
            /* Full fork: child gets its own mm, private copy of heap/stack/TLS.
               Parent returns immediately with child pid; child runs concurrently. */
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
            }
            char child_name[32];
            snprintf(child_name, sizeof(child_name), "%s.child", cur->name);
            // kprintf("DBG: fork: syscall_user_return_rip=0x%llx syscall_user_rsp_saved=0x%llx (saved_rcx=0x%llx saved_rsp=0x%llx)\n",
            //         (unsigned long long)syscall_user_return_rip, (unsigned long long)syscall_user_rsp_saved,
            //         (unsigned long long)saved_rcx, (unsigned long long)saved_rsp);
            /* Create BLOCKED first to avoid running before initialization. */
            thread_t *child = thread_create_blocked(user_thread_entry, child_name);
            if (!child) return ret_err(ENOMEM);
            /* Iteration 1: fork gets its own CR3 root (user pages still shared until remapped). */
            {
                mm_t *child_mm = mm_clone_current();
                if (!child_mm) return ret_err(ENOMEM);
                if (child->mm) mm_release(child->mm);
                child->mm = child_mm;
            }
            /* clone parent's active stack slice into child's own stack (like vfork safe variant) */
            {
                uintptr_t parent_fs = (uintptr_t)cur->user_fs_base;
                uintptr_t parent_tls_region = (parent_fs >= 0x1000u) ? (parent_fs - 0x1000u) : 0;
                if ((uintptr_t)saved_rsp == 0 || (uintptr_t)saved_rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    return ret_err(EINVAL);
                }
                /* Hot path optimization:
                   copying a fixed 1 MiB on every fork is very expensive on real HW.
                   Copy only active parent stack tail (bounded). */
                uintptr_t max_copy = (uintptr_t)(128 * 1024); /* hard cap for fork latency */
                uintptr_t parent_stack_top = user_stack_top_for_tid_like_exec(cur->tid ? cur->tid : 1);
                uintptr_t used_tail = 0;
                if (parent_stack_top > (uintptr_t)saved_rsp) used_tail = parent_stack_top - (uintptr_t)saved_rsp;
                if (used_tail == 0) used_tail = (uintptr_t)(32 * 1024);
                if (used_tail < 4096) used_tail = 4096;
                if (used_tail < max_copy) max_copy = used_tail;
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
                    uintptr_t pp = (uintptr_t)child_rsp;
                    uintptr_t end = (uintptr_t)child_rsp + (uintptr_t)copy_bytes;
                    for (; pp + 8 <= end; pp += 8) {
                        uint64_t v = 0;
                        if (user_read_u64((const void *)(uintptr_t)pp, &v) != 0) return ret_err(EFAULT);
                        uintptr_t vv = (uintptr_t)v;
                        if ((vv & 7u) == 0 && vv >= parent_lo && vv < parent_hi) {
                            uintptr_t nv = (uintptr_t)child_rsp + (uintptr_t)(vv - parent_lo);
                            if (user_write_u64((void *)(uintptr_t)pp, (uint64_t)nv) != 0)
                                return ret_err(EFAULT);
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
                if (user_write_u64((void *)(uintptr_t)(child_fs - 0x78u), (uint64_t)child_pthread_fake) != 0)
                    return ret_err(EFAULT);
                {
                    const uintptr_t c_str = child_tls_region + 0x2800u;
                    if (c_str + 2 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                        if (user_write_u8((void *)(uintptr_t)(c_str + 0), (uint8_t)'C') != 0) return ret_err(EFAULT);
                        if (user_write_u8((void *)(uintptr_t)(c_str + 1), 0) != 0) return ret_err(EFAULT);
                        const uintptr_t specific5_slot = child_pthread_fake + 0x80u + (uintptr_t)(5u * 8u);
                        for (int si = 0; si < 32; si++) {
                            if (user_write_u64((void *)(uintptr_t)(child_pthread_fake + 0x80u + (uintptr_t)(si * 8u)), 0) != 0)
                                return ret_err(EFAULT);
                        }
                        if (user_write_u64((void *)(uintptr_t)specific5_slot, (uint64_t)c_str) != 0)
                            return ret_err(EFAULT);
                    }
                }
                child->user_fs_base = (uint64_t)child_fs;

                /* inherit parent's brk and mmap cursor so child has valid heap/mmap state before exec */
                child->user_brk_base = cur->user_brk_base;
                child->user_brk_cur = cur->user_brk_cur;
                if (cur->user_mmap_next) child->user_mmap_next = cur->user_mmap_next;
                child->user_mmap_hi = cur->user_mmap_hi;

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
            /* Iteration 1 deep-copy fork:
               materialize private writable pages for child mm (no COW yet). */
            {
                const uintptr_t base = (uintptr_t)0x00200000u;
                uintptr_t used_end = (uintptr_t)cur->user_brk_cur;
                /* Extend to anon mmap high-water (real addr+len ends), not mmap_next alone:
                   mmap_next is a bump cursor (often 32MiB on first mmap) and forced huge
                   fork copies (mm_make_private_range per 4K) that look like a deadlock. */
                if (cur->user_mmap_hi > used_end) used_end = cur->user_mmap_hi;
                const uintptr_t min_copy_end = base + (1u * 1024u * 1024u);
                if (used_end < min_copy_end || used_end == 0) used_end = min_copy_end;
                if (used_end > (uintptr_t)USER_TLS_BASE) used_end = (uintptr_t)USER_TLS_BASE;
                /* Deep-copy [base, used_end): must cover brk so child malloc isn't shared with parent. */
                qemu_debug_printf("fork: copying heap 0x%lx..0x%lx (%lu pages)\n",
                                 (unsigned long)base, (unsigned long)used_end,
                                 (unsigned long)((used_end - base) / 4096));
                if (used_end > base) {
                    if (mm_make_private_range(child->mm, (uint64_t)base, (uint64_t)used_end, 1, cur->mm) != 0) {
                        return ret_err(ENOMEM);
                    }
                }
                qemu_debug_printf("fork: heap done\n");
                uintptr_t c_top = user_stack_top_for_tid_like_exec(child->tid ? child->tid : 1);
                uintptr_t c_stack_base = (c_top - (uintptr_t)USER_STACK_SIZE) & ~0xFFFULL;
                uintptr_t c_tls_base = c_top - (uintptr_t)USER_STACK_SIZE - (uintptr_t)USER_TLS_SIZE;
                if (mm_make_private_range(child->mm, (uint64_t)c_stack_base, (uint64_t)c_top, 1, cur->mm) != 0) {
                    return ret_err(ENOMEM);
                }
                if (mm_make_private_range(child->mm, (uint64_t)c_tls_base, (uint64_t)(c_tls_base + 0x3000u), 1, cur->mm) != 0) {
                    return ret_err(ENOMEM);
                }
                if (mm_make_private_range(child->mm, (uint64_t)USER_VFORK_TRAMP, (uint64_t)(USER_VFORK_TRAMP + 0x1000u), 1, cur->mm) != 0) {
                    return ret_err(ENOMEM);
                }
                qemu_debug_printf("fork: private ranges done, unblocking child\n");
            }
            /* Retain parent mm for mm_make_private_range COW table splits (e.g. exec); cleared in elf enter_user_mode. */
            if (child->mm_ptemplate)
                mm_release(child->mm_ptemplate);
            child->mm_ptemplate = mm_retain(cur->mm);
            /* inherit credentials */
            child->uid = cur->uid;
            child->euid = cur->euid;
            child->suid = cur->suid;
            child->gid = cur->gid;
            child->egid = cur->egid;
            child->sgid = cur->sgid;
            child->attached_tty = cur->attached_tty;
            /* Keep child->user_fs_base from the fork child TLS setup above.
               Overwriting it with parent's FS base breaks child's TLS context. */
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
                /* Trace selection for debugging hangs (limited by global trace budget anyway). */
                if (g_syscall_trace_on && g_syscall_trace_budget > 0 && is_watch_proc(tcur)) {
                    kprintf("wait4: parent=%llu name=%s pid_arg=%d -> child=%llu state=%d exit_status=0x%x reaped=%d\n",
                        (unsigned long long)(tcur->tid ? tcur->tid : 1),
                        (tcur->name[0] ? tcur->name : "(noname)"),
                        pid,
                        (unsigned long long)(found->tid ? found->tid : 1),
                        (int)found->state,
                        (unsigned)found->exit_status,
                        (found->exit_status == 0x80000000));
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
                /* Unconditional marker when we really block in wait4. */
                kprintf("wait4: block parent=%llu name=%s child=%llu child_state=%d\n",
                    (unsigned long long)(tcur->tid ? tcur->tid : 1),
                    (tcur->name[0] ? tcur->name : "(noname)"),
                    (unsigned long long)(found->tid ? found->tid : 1),
                    (int)found->state);
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
                TIOCSTI   = 0x5412, /* inject byte into tty input queue (terminal ioctls) */
                TIOCSCTTY = 0x540E,
                TIOCGPGRP = 0x540F,
                TIOCSPGRP = 0x5410,
                TIOCGWINSZ= 0x5413,
                TIOCSWINSZ= 0x5414,
                /* Linux block ioctls commonly used by mkfs/mount utilities */
                BLKGETSIZE   = 0x1260,       /* get device size in 512-byte sectors (unsigned long*) */
                BLKSSZGET    = 0x1268,       /* get logical sector size (int*) */
                BLKBSZGET    = 0x80081270,   /* get block size (int*) */
                BLKGETSIZE64 = 0x80081272,   /* get device size in bytes (uint64_t*) */
                FIONREAD  = 0x541B,
                FIONBIO   = 0x5421,
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

            /* usbdevfs subset for /dev/bus/usb/BBB/DDD */
            if (usb_is_devfs_file(f)) {
                const usb_device_t *cd = usb_device_from_file(f);
                usb_device_t *dev = (usb_device_t *)cd;
                if (!dev) return ret_err(ENOENT);

                if (req == USBDEVFS_CLAIMINTERFACE || req == USBDEVFS_RELEASEINTERFACE) {
                    if (!argp) return ret_err(EFAULT);
                    int ifnum = 0;
                    if (copy_from_user_raw(&ifnum, argp, sizeof(ifnum)) != 0) return ret_err(EFAULT);
                    int rc = (req == USBDEVFS_CLAIMINTERFACE) ? usb_claim_interface(dev, ifnum)
                                                               : usb_release_interface(dev, ifnum);
                    return (rc == 0) ? 0 : ret_err(EINVAL);
                }
                if (req == USBDEVFS_RESET) {
                    return (usb_reset_device(dev) == 0) ? 0 : ret_err(EIO);
                }
                if (req == USBDEVFS_CONTROL) {
                    if (!argp || !user_range_ok(argp, sizeof(usbdevfs_ctrltransfer_t))) return ret_err(EFAULT);
                    usbdevfs_ctrltransfer_t ctl;
                    if (copy_from_user_raw(&ctl, argp, sizeof(ctl)) != 0) return ret_err(EFAULT);
                    if (ctl.wLength > 4096) return ret_err(EINVAL);
                    void *kbuf = NULL;
                    if (ctl.wLength > 0) {
                        if (!ctl.data || !user_range_ok(ctl.data, ctl.wLength)) return ret_err(EFAULT);
                        kbuf = kmalloc(ctl.wLength);
                        if (!kbuf) return ret_err(ENOMEM);
                        if ((ctl.bRequestType & 0x80) == 0) {
                            if (copy_from_user_raw(kbuf, ctl.data, ctl.wLength) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                        } else {
                            memset(kbuf, 0, ctl.wLength);
                        }
                    }
                    usb_setup_packet_t s;
                    s.bmRequestType = ctl.bRequestType;
                    s.bRequest = ctl.bRequest;
                    s.wValue = ctl.wValue;
                    s.wIndex = ctl.wIndex;
                    s.wLength = ctl.wLength;
                    int rc = usb_control_transfer(dev, &s, kbuf, ctl.wLength, ctl.timeout ? ctl.timeout : 1000);
                    if (rc >= 0 && (ctl.bRequestType & 0x80) && ctl.wLength > 0) {
                        if (copy_to_user_safe(ctl.data, kbuf, ctl.wLength) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                    }
                    if (kbuf) kfree(kbuf);
                    if (rc < 0) return ret_err(EIO);
                    return (uint64_t)rc;
                }
                if (req == USBDEVFS_BULK) {
                    if (!argp || !user_range_ok(argp, sizeof(usbdevfs_bulktransfer_t))) return ret_err(EFAULT);
                    usbdevfs_bulktransfer_t b;
                    if (copy_from_user_raw(&b, argp, sizeof(b)) != 0) return ret_err(EFAULT);
                    if (b.len > 65536u) return ret_err(EINVAL);
                    if (b.len > 0 && (!b.data || !user_range_ok(b.data, b.len))) return ret_err(EFAULT);
                    void *kbuf = NULL;
                    if (b.len > 0) {
                        kbuf = kmalloc(b.len);
                        if (!kbuf) return ret_err(ENOMEM);
                    }
                    int is_in = (b.ep & 0x80u) ? 1 : 0;
                    if (!is_in && b.len > 0) {
                        if (copy_from_user_raw(kbuf, b.data, b.len) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                    }
                    int rc = usb_bulk_transfer(dev, (uint8_t)(b.ep & 0x0Fu), is_in, kbuf, b.len, b.timeout ? b.timeout : 1000);
                    if (rc >= 0 && is_in && b.len > 0) {
                        if (copy_to_user_safe(b.data, kbuf, b.len) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                    }
                    if (kbuf) kfree(kbuf);
                    if (rc < 0) return ret_err(EIO);
                    return (uint64_t)rc;
                }
                return ret_err(ENOTTY);
            }

            /* Block-device ioctls for /dev/sdX,/dev/hdX (needed by mkfs.vfat and friends). */
            if (req == BLKSSZGET || req == BLKBSZGET || req == BLKGETSIZE || req == BLKGETSIZE64) {
                if (!argp) return ret_err(EFAULT);
                if (!f->path || devfs_get_device_id(f->path) < 0) return ret_err(ENOTTY);
                uint64_t bytes = (uint64_t)f->size;
                if (req == BLKSSZGET || req == BLKBSZGET) {
                    int v = 512;
                    if (copy_to_user_safe(argp, &v, sizeof(v)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                if (req == BLKGETSIZE64) {
                    uint64_t v = bytes;
                    if (copy_to_user_safe(argp, &v, sizeof(v)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                /* BLKGETSIZE -> number of 512-byte sectors (unsigned long on x86_64) */
                {
                    uint64_t sectors = bytes / 512u;
                    if (copy_to_user_safe(argp, &sectors, sizeof(sectors)) != 0) return ret_err(EFAULT);
                    return 0;
                }
            }

            /* Important: libc frequently probes terminal state on stdout/stderr very early
               (e.g. ld.lld does ioctl(TCGETS) on fd=2). Do NOT require tty classification
               for these "query" ioctls; return sensible defaults even if the fd isn't a tty.
               This avoids hangs if a file->path pointer is corrupted and devfs_is_tty_file()
               would fault while doing strcmp(). */
            if (req == TIOCGWINSZ) {
                if (!argp) return ret_err(EFAULT);
                uint16_t rows = (uint16_t)console_max_rows();
                uint16_t cols = (uint16_t)console_max_cols();
                if (rows == 0) rows = 25;
                if (cols == 0) cols = 80;
                struct winsize ws = { .ws_row = rows,
                                      .ws_col = cols,
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

            /* Socket ioctls often used by wget/getaddrinfo paths. */
            if (f->type == SYSCALL_FTYPE_SOCKET) {
                if (req == FIONBIO) {
                    if (!argp || !user_range_ok(argp, sizeof(uint32_t))) return ret_err(EFAULT);
                    /* Non-blocking flag is accepted; sockets remain effectively blocking/minimally polled. */
                    return 0;
                }
                if (req == FIONREAD) {
                    if (!argp || !user_range_ok(argp, sizeof(uint32_t))) return ret_err(EFAULT);
                    ksock_net_t *s = (ksock_net_t *)f->driver_private;
                    uint32_t nb = 0;
                    if (s) {
                        if (s->sock_domain == AF_NETLINK_LOCAL) {
                            if (s->nl_rx_off < s->nl_rx_len)
                                nb = (uint32_t)(s->nl_rx_len - s->nl_rx_off);
                        } else if (s->unix_domain_stub && s->connected) {
                            /* libc may ioctl before recv on nscd stub; >0 nudges read path (recv returns 0). */
                            nb = 1u;
                        } else if (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) {
                            ksock_rx_pending_normalize(s);
                            size_t a = ksock_rx_pending_avail(s);
                            if (a > 0) nb = (uint32_t)((a > 0xFFFFFFFFu) ? 0xFFFFFFFFu : a);
                            else {
                                int pl = net_rxq_peek_udp_payload_for_sock(s);
                                if (pl > 0) nb = (uint32_t)pl;
                            }
                        } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL &&
                                   s->dns_tcp_udp_bridge) {
                            ksock_rx_pending_normalize(s);
                            size_t a = ksock_rx_pending_avail(s);
                            if (a > 0) nb = (uint32_t)((a > 0xFFFFFFFFu) ? 0xFFFFFFFFu : a);
                            else {
                                int pl = net_rxq_peek_udp_payload_for_sock(s);
                                if (pl > 0) nb = (uint32_t)pl;
                            }
                        } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                            nb = (s->tcp.rx_len > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (uint32_t)s->tcp.rx_len;
                        }
                    }
                    if (copy_to_user_safe(argp, &nb, sizeof(nb)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                /* Network interface ioctls (SIOCxxx) - used by ip, ifconfig, etc. */
                enum {
                    SIOCGIFNAME    = 0x8910,
                    SIOCGIFCONF    = 0x8912,
                    SIOCGIFFLAGS   = 0x8913,
                    SIOCSIFFLAGS   = 0x8914,
                    SIOCGIFADDR    = 0x8915,
                    SIOCSIFADDR    = 0x8916,
                    SIOCGIFDSTADDR = 0x8917,
                    SIOCSIFDSTADDR = 0x8918,
                    SIOCGIFBRDADDR = 0x8919,
                    SIOCSIFBRDADDR = 0x891A,
                    SIOCGIFNETMASK = 0x891B,
                    SIOCSIFNETMASK = 0x891C,
                    SIOCGIFMETRIC  = 0x891D,
                    SIOCSIFMETRIC  = 0x891E,
                    SIOCGIFMTU     = 0x8921,
                    SIOCSIFMTU     = 0x8922,
                    SIOCGIFHWADDR  = 0x8927,
                    SIOCSIFHWADDR  = 0x8928,
                    SIOCGIFINDEX   = 0x8933,
                    SIOCGIFTXQLEN  = 0x8942,
                    SIOCSIFTXQLEN  = 0x8943,
                };
                /* struct ifreq layout (Linux x86_64):
                   char ifr_name[16];
                   union { sockaddr, int, ... } ifr_ifru; (16 bytes typically)
                   Total: 32-40 bytes depending on union member */
                struct ifreq_k {
                    char ifr_name[16];
                    union {
                        struct { uint16_t sa_family; char sa_data[14]; } ifr_addr;
                        struct { uint16_t sa_family; uint8_t sa_data[14]; } ifr_hwaddr;
                        int16_t ifr_flags;
                        int32_t ifr_ifindex;
                        int32_t ifr_metric;
                        int32_t ifr_mtu;
                        int32_t ifr_qlen;
                    };
                };
                /* Check if this is a network interface ioctl */
                if (req == SIOCGIFNAME || req == SIOCGIFINDEX || req == SIOCGIFFLAGS ||
                    req == SIOCGIFADDR || req == SIOCGIFNETMASK || req == SIOCGIFBRDADDR ||
                    req == SIOCGIFHWADDR || req == SIOCGIFMTU || req == SIOCGIFTXQLEN ||
                    req == SIOCGIFMETRIC || req == SIOCGIFDSTADDR ||
                    req == SIOCSIFFLAGS || req == SIOCSIFADDR || req == SIOCSIFNETMASK ||
                    req == SIOCSIFMTU || req == SIOCSIFTXQLEN) {
                    if (!argp || !user_range_ok(argp, sizeof(struct ifreq_k))) return ret_err(EFAULT);
                    struct ifreq_k ifr;
                    memset(&ifr, 0, sizeof(ifr));
                    if (copy_from_user_raw(&ifr, argp, sizeof(ifr)) != 0) return ret_err(EFAULT);
                    /* Determine which interface: lo (index 1) or eth0 (index 2) */
                    int is_lo = 0, is_eth0 = 0;
                    if (strcmp(ifr.ifr_name, "lo") == 0) is_lo = 1;
                    else if (strcmp(ifr.ifr_name, "eth0") == 0 || ifr.ifr_name[0] == '\0') is_eth0 = 1;
                    else if (req == SIOCGIFNAME && ifr.ifr_ifindex == 1) is_lo = 1;
                    else if (req == SIOCGIFNAME && ifr.ifr_ifindex == 2) is_eth0 = 1;
                    if (!is_lo && !is_eth0) return ret_err(ENODEV);
                    /* Set interface name */
                    if (is_lo) strncpy(ifr.ifr_name, "lo", sizeof(ifr.ifr_name));
                    else strncpy(ifr.ifr_name, "eth0", sizeof(ifr.ifr_name));
                    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
                    /* Handle specific requests */
                    if (req == SIOCGIFINDEX) {
                        ifr.ifr_ifindex = is_lo ? 1 : 2;
                    } else if (req == SIOCGIFNAME) {
                        /* ifr_name already set above */
                    } else if (req == SIOCGIFFLAGS) {
                        if (is_lo) {
                            /* IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP */
                            ifr.ifr_flags = (int16_t)(0x1 | 0x8 | 0x40);
                        } else {
                            /* IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST */
                            ifr.ifr_flags = (int16_t)(0x1 | 0x2 | 0x40 | 0x1000);
                        }
                    } else if (req == SIOCSIFFLAGS) {
                        /* Accept but ignore - we're always up */
                    } else if (req == SIOCGIFADDR) {
                        ifr.ifr_addr.sa_family = AF_INET_LOCAL;
                        uint32_t ip = is_lo ? 0x0100007Fu : g_net.ip_be; /* 127.0.0.1 for lo */
                        memcpy(ifr.ifr_addr.sa_data + 2, &ip, 4);
                    } else if (req == SIOCGIFNETMASK) {
                        ifr.ifr_addr.sa_family = AF_INET_LOCAL;
                        uint32_t mask = is_lo ? 0x000000FFu : g_net.mask_be; /* 255.0.0.0 for lo */
                        memcpy(ifr.ifr_addr.sa_data + 2, &mask, 4);
                    } else if (req == SIOCGIFBRDADDR) {
                        ifr.ifr_addr.sa_family = AF_INET_LOCAL;
                        if (is_lo) {
                            /* lo has no broadcast */
                            return ret_err(ENODEV);
                        }
                        uint32_t brd = (g_net.ip_be & g_net.mask_be) | ~g_net.mask_be;
                        memcpy(ifr.ifr_addr.sa_data + 2, &brd, 4);
                    } else if (req == SIOCGIFDSTADDR) {
                        ifr.ifr_addr.sa_family = AF_INET_LOCAL;
                        uint32_t dst = is_lo ? 0x0100007Fu : g_net.gw_be;
                        memcpy(ifr.ifr_addr.sa_data + 2, &dst, 4);
                    } else if (req == SIOCGIFHWADDR) {
                        if (is_lo) {
                            ifr.ifr_hwaddr.sa_family = 772; /* ARPHRD_LOOPBACK */
                            memset(ifr.ifr_hwaddr.sa_data, 0, 6);
                        } else {
                            ifr.ifr_hwaddr.sa_family = 1; /* ARPHRD_ETHER */
                            memcpy(ifr.ifr_hwaddr.sa_data, g_net.mac, 6);
                        }
                    } else if (req == SIOCGIFMTU) {
                        ifr.ifr_mtu = is_lo ? 65536 : 1500;
                    } else if (req == SIOCSIFMTU) {
                        /* Accept but ignore */
                    } else if (req == SIOCGIFTXQLEN) {
                        ifr.ifr_qlen = is_lo ? 1000 : 1000; /* typical default */
                    } else if (req == SIOCSIFTXQLEN) {
                        /* Accept but ignore */
                    } else if (req == SIOCGIFMETRIC) {
                        ifr.ifr_metric = 0;
                    } else if (req == SIOCSIFADDR || req == SIOCSIFNETMASK) {
                        /* Accept but ignore - static config */
                    }
                    if (copy_to_user_safe(argp, &ifr, sizeof(ifr)) != 0) return ret_err(EFAULT);
                    return 0;
                }
                /* SIOCGIFCONF - list all interfaces */
                if (req == SIOCGIFCONF) {
                    if (!argp) return ret_err(EFAULT);
                    struct ifconf_k {
                        int32_t ifc_len;
                        int32_t __pad;
                        void *ifc_buf;
                    } ifc;
                    if (copy_from_user_raw(&ifc, argp, sizeof(ifc)) != 0) return ret_err(EFAULT);
                    /* We have 2 interfaces: lo and eth0 */
                    struct ifreq_k entries[2];
                    memset(entries, 0, sizeof(entries));
                    /* lo */
                    strncpy(entries[0].ifr_name, "lo", sizeof(entries[0].ifr_name));
                    entries[0].ifr_addr.sa_family = AF_INET_LOCAL;
                    uint32_t lo_ip = 0x0100007Fu; /* 127.0.0.1 in big-endian */
                    memcpy(entries[0].ifr_addr.sa_data + 2, &lo_ip, 4);
                    /* eth0 */
                    strncpy(entries[1].ifr_name, "eth0", sizeof(entries[1].ifr_name));
                    entries[1].ifr_addr.sa_family = AF_INET_LOCAL;
                    memcpy(entries[1].ifr_addr.sa_data + 2, &g_net.ip_be, 4);
                    int32_t needed = (int32_t)(2 * sizeof(struct ifreq_k));
                    if (ifc.ifc_buf && ifc.ifc_len > 0) {
                        int32_t copy_len = (ifc.ifc_len < needed) ? ifc.ifc_len : needed;
                        if (user_range_ok(ifc.ifc_buf, (size_t)copy_len)) {
                            copy_to_user_safe(ifc.ifc_buf, entries, (size_t)copy_len);
                        }
                        ifc.ifc_len = copy_len;
                    } else {
                        ifc.ifc_len = needed;
                    }
                    if (copy_to_user_safe(argp, &ifc, sizeof(ifc)) != 0) return ret_err(EFAULT);
                    return 0;
                }
            }

            /* KDGKBTYPE (0x4B33): get keyboard type. BusyBox chvt uses this to validate console fd. */
            if (req == 0x4B33) {
                if (argp && user_range_ok(argp, 1)) {
                    char kbd_type = 0; /* 0 = PC/XT style */
                    if (copy_to_user_safe(argp, &kbd_type, 1) == 0 && devfs_is_tty_file(f))
                        return 0;
                }
                return ret_err(ENOTTY);
            }

            /* For the remaining tty-specific ioctls, require a real tty file. */
            if (!devfs_is_tty_file(f)) {
                return ret_err(ENOTTY);
            }
            if (req == 0x5606) { /* VT_ACTIVATE: arg is VT number (1-based) passed as value, not pointer */
                int vt = (int)(uintptr_t)argp;
                if (vt >= 1 && vt <= 6) { /* DEVFS_TTY_COUNT=6; Linux VTs are 1-based */
                    devfs_switch_tty(vt - 1);
                    return 0;
                }
                return ret_err(ENOTTY);
            }
            if (req == 0x5607) { /* VT_WAITACTIVE: arg is VT number; we switch synchronously, no-op */
                (void)argp;
                return 0;
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
            if (req == TIOCSTI) {
                /* Push one byte as if typed on the tty (used by some tools; input path is unchanged). */
                if (!argp) return ret_err(EFAULT);
                unsigned char cbyte;
                if (copy_from_user_raw(&cbyte, argp, 1) != 0) return ret_err(EFAULT);
                int tty_idx = devfs_get_tty_index_from_file(f);
                if (tty_idx < 0) return ret_err(ENOTTY);
                devfs_tty_push_input(tty_idx, (char)cbyte);
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
            if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                ssize_t wr = net_sock_write_userspace(cur, fd, s, bufp, cnt);
                if (wr < 0) return ret_err((int)-wr);
                return (uint64_t)wr;
            }
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
            size_t total = 0;
            while (total < cnt) {
                size_t chunk = cnt - total;
                if (chunk > 4096) chunk = 4096;
                size_t copied = 0;
                void *tmp = copy_from_user_safe((const uint8_t*)bufp + total, chunk, 4096, &copied);
                if (!tmp && chunk > 512) {
                    chunk = 512;
                    tmp = copy_from_user_safe((const uint8_t*)bufp + total, chunk, 512, &copied);
                }
                if (!tmp) return (total > 0) ? (uint64_t)total : ret_err(EFAULT);
                ssize_t wr = fs_write(f, tmp, copied, f->pos);
                kfree(tmp);
                if (wr <= 0) return (total > 0) ? (uint64_t)total : ret_err(EINVAL);
                f->pos += (size_t)wr;
                total += (size_t)wr;
                if ((size_t)wr < copied) break;
            }
            return (uint64_t)total;
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

            if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                uint64_t total = 0;
                for (int i = 0; i < iovcnt; i++) {
                    void *base = (void *)(uintptr_t)iov[i].base;
                    size_t len = (size_t)iov[i].len;
                    if (len == 0) continue;
                    if (!user_range_ok(base, len)) return (total > 0) ? total : ret_err(EFAULT);
                    size_t pos = 0;
                    while (pos < len) {
                        size_t chunk = len - pos;
                        if (chunk > 4096) chunk = 4096;
                        ssize_t rr = net_sock_read_userspace(cur, s, (uint8_t *)base + pos, chunk);
                        if (rr < 0) return (total > 0) ? total : ret_err((int)-rr);
                        if (rr == 0) return total;
                        total += (uint64_t)rr;
                        pos += (size_t)rr;
                    }
                }
                return total;
            }

            uint64_t total = 0;
            for (int i = 0; i < iovcnt; i++) {
                void *base = (void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                if (!user_range_ok(base, len)) return (total > 0) ? total : ret_err(EFAULT);
                size_t off = 0;
                while (off < len) {
                    size_t chunk = len - off;
                    if (chunk > 4096) chunk = 4096;
                    void *tmp = kmalloc(chunk);
                    if (!tmp) return (total > 0) ? total : ret_err(ENOMEM);
                    ssize_t rr;
                    if (f->type == FS_TYPE_PIPE && !f->fs_private && f->driver_private) {
                        rr = pipe_read_bytes((pipe_t *)f->driver_private, tmp, chunk, cur);
                    } else {
                        rr = fs_read(f, tmp, chunk, f->pos);
                    }
                    if (rr < 0) {
                        kfree(tmp);
                        return (total > 0) ? total : ret_err((int)-rr);
                    }
                    if (rr == 0) {
                        kfree(tmp);
                        return total;
                    }
                    if (copy_to_user_safe((uint8_t*)base + off, tmp, (size_t)rr) != 0) { kfree(tmp); return (total > 0) ? total : ret_err(EFAULT); }
                    kfree(tmp);
                    if (f->type != FS_TYPE_PIPE) f->pos += (size_t)rr;
                    total += (uint64_t)rr;
                    off += (size_t)rr;
                    if ((size_t)rr < chunk) return total;
                }
            }
            return total;
        }
        case SYS_preadv: {
            /* preadv(fd, const struct iovec *iov, int iovcnt, off_t offset) — Linux x86_64 295 */
            int fd = (int)a1;
            const void *iov_u = (const void*)(uintptr_t)a2;
            int iovcnt = (int)a3;
            int64_t off_in = (int64_t)a4;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            if (!iov_u) return ret_err(EFAULT);
            if (iovcnt <= 0 || iovcnt > 64) return ret_err(EINVAL);
            if (off_in < 0) return ret_err(EINVAL);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);

            struct iovec_k { uint64_t base; uint64_t len; };
            struct iovec_k iov[64];
            size_t bytes = (size_t)iovcnt * sizeof(iov[0]);
            if (copy_from_user_raw(iov, iov_u, bytes) != 0) return ret_err(EFAULT);

            uint64_t total = 0;
            size_t cur_off = (size_t)off_in;
            for (int i = 0; i < iovcnt; i++) {
                void *base = (void*)(uintptr_t)iov[i].base;
                size_t len = (size_t)iov[i].len;
                if (len == 0) continue;
                if (!user_range_ok(base, len)) return (total > 0) ? total : ret_err(EFAULT);
                size_t pos = 0;
                while (pos < len) {
                    size_t chunk = len - pos;
                    if (chunk > 4096) chunk = 4096;
                    void *tmp = kmalloc(chunk);
                    if (!tmp) return (total > 0) ? total : ret_err(ENOMEM);
                    ssize_t rr = fs_read(f, tmp, chunk, cur_off);
                    if (rr < 0) {
                        kfree(tmp);
                        return (total > 0) ? total : ret_err((int)-rr);
                    }
                    if (rr == 0) {
                        kfree(tmp);
                        return total;
                    }
                    if (copy_to_user_safe((uint8_t*)base + pos, tmp, (size_t)rr) != 0) { kfree(tmp); return (total > 0) ? total : ret_err(EFAULT); }
                    kfree(tmp);
                    cur_off += (size_t)rr;
                    total += (uint64_t)rr;
                    pos += (size_t)rr;
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
            if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                ssize_t r = net_sock_read_userspace(cur, (ksock_net_t *)f->driver_private, bufp, cnt);
                if (r < 0) return ret_err((int)-r);
                return (uint64_t)r;
            }
            if (f->type == FS_TYPE_PIPE && !f->fs_private) {
                pipe_t *p = (pipe_t *)f->driver_private;
                if (!p) return ret_err(EBADF);
                if (!bufp || !user_range_ok(bufp, cnt)) return ret_err(EFAULT);
                size_t to_read = cnt < (size_t)PIPE_BUF_SIZE ? cnt : (size_t)PIPE_BUF_SIZE;
                void *tmp = kmalloc(to_read);
                if (!tmp) return ret_err(ENOMEM);
                ssize_t rr = pipe_read_bytes(p, tmp, to_read, cur);
                if (rr > 0) {
                    if (copy_to_user_safe(bufp, tmp, (size_t)rr) != 0) { kfree(tmp); return ret_err(EFAULT); }
                }
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
            return (rr >= 0) ? (uint64_t)rr : ret_err((int)-rr);
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
            /* Keep sendfile conservative: tty output is handled better via read/write fallback. */
            if (devfs_is_tty_file(fout)) {
                return ret_err(ENOSYS);
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
            if (offp) {
                if (copy_from_user_raw(&use_pos, offp, sizeof(use_pos)) != 0) {
                    kfree(tmp);
                    return ret_err(EFAULT);
                }
            }
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
            if (offp) {
                if (copy_to_user_safe(offp, &use_pos, sizeof(use_pos)) != 0) return ret_err(EFAULT);
            }
            return (uint64_t)total;
        }
        case 271: /* ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask, size_t sigsetsize) */
        case SYS_poll: {
            /* int poll(struct pollfd *fds, nfds_t nfds, int timeout_ms) */
            const void *ufds = (const void*)(uintptr_t)a1;
            int nfds = (int)a2;
            int timeout;
            thread_t *tcur_poll_cfg = thread_get_current_user();
            if (!tcur_poll_cfg) tcur_poll_cfg = thread_current();
            int is_wget_proc = (tcur_poll_cfg && tcur_poll_cfg->name[0] && strstr(tcur_poll_cfg->name, "wget")) ? 1 : 0;
            int is_apm_proc = (tcur_poll_cfg && tcur_poll_cfg->name[0] && strstr(tcur_poll_cfg->name, "apm")) ? 1 : 0;
            int is_git_proc = (tcur_poll_cfg && tcur_poll_cfg->name[0] && strstr(tcur_poll_cfg->name, "git")) ? 1 : 0;
            if (num == 271) {
                /* Minimal ppoll: ignore sigmask/sigsetsize, translate timespec->ms for poll(). */
                const void *tmo_u = (const void*)(uintptr_t)a3;
                timeout = -1; /* NULL timeout => infinite */
                if (tmo_u) {
                    struct timespec_k { int64_t tv_sec; int64_t tv_nsec; } ts;
                    if (copy_from_user_raw(&ts, tmo_u, sizeof(ts)) != 0) return ret_err(EFAULT);
                    if (ts.tv_sec < 0 || ts.tv_nsec < 0) return ret_err(EINVAL);
                    uint64_t ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
                    if (ms == 0 && ts.tv_nsec > 0) ms = 1;
                    if (ms > 0x7FFFFFFFULL) ms = 0x7FFFFFFFULL;
                    timeout = (int)ms;
                } else {
                    /* Cap NULL-timeout ppoll so userland can't block forever on network. */
                    if (is_wget_proc || is_apm_proc || is_git_proc) timeout = 1000;
                }
                } else {
                    timeout = (int)a3; /* milliseconds, -1 means infinite */
                    /* Some tools can block forever on network poll(-1); cap so process can progress. */
                    if (timeout < 0 && (is_wget_proc || is_apm_proc || is_git_proc)) timeout = 1000;
                }
            if (nfds < 0 || nfds > 1024) return ret_err(EINVAL);
            volatile int elapsed = 0;
            uint64_t poll_t_start = 0;
            int poll_first_entry = 1;
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

            enum { POLLIN = 0x001, POLLOUT = 0x004, POLLERR = 0x008, POLLHUP = 0x010, POLLNVAL = 0x020 };

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
                            } else if (f->type == SYSCALL_FTYPE_SOCKET && f->driver_private) {
                                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                                if (events & POLLOUT) {
                                    if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge) {
                                        revents |= POLLOUT;
                                    } else if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                                        net_tcp_ops_t ops;
                                        net_make_tcp_ops(&ops);
                                        (void)net_tcp_service(&s->tcp, &ops, 4);
                                        if (s->tcp.established) revents |= POLLOUT;
                                    } else {
                                        revents |= POLLOUT;
                                    }
                                }
                                if ((events & POLLIN) && s->sock_domain == AF_NETLINK_LOCAL) {
                                    if (s->nl_rx_off < s->nl_rx_len) revents |= POLLIN;
                                } else if ((events & POLLIN) && s->unix_domain_stub && s->connected) {
                                    revents |= POLLIN;
                                } else if ((events & POLLIN) &&
                                           ((s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL) ||
                                            (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && s->dns_tcp_udp_bridge))) {
                                    if (s->rx_has_pending) revents |= POLLIN;
                                    else {
                                        uint32_t sip = 0;
                                        uint16_t sport = 0;
                                        int rn = net_recv_udp_datagram(s, s->rx_pending, sizeof(s->rx_pending), 0, &sip, &sport);
                                        if (rn > 0) {
                                            ksock_rx_pending_install(s, rn);
                                            s->rx_pending_src_ip_be = sip;
                                            s->rx_pending_src_port = sport;
                                            revents |= POLLIN;
                                        }
                                    }
                                } else if ((events & POLLIN) && s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) {
                                    net_tcp_ops_t ops;
                                    net_make_tcp_ops(&ops);
                                    (void)net_tcp_service(&s->tcp, &ops, 4);
                                    if (s->tcp.rx_len > 0 || s->tcp.peer_fin) revents |= POLLIN;
                                }
                            } else if (usb_is_devfs_file(f)) {
                                if (events & POLLOUT) revents |= POLLOUT;
                                /* MVP: no async IN queue yet, keep POLLIN clear unless future IRQ path adds data. */
                            } else if (f->type == FS_TYPE_PIPE && f->driver_private) {
                                pipe_t *p = (pipe_t *)f->driver_private;
                                unsigned long fl = 0;
                                acquire_irqsave(&p->lock, &fl);
                                size_t used = (p->head >= p->tail) ? (p->head - p->tail) : (p->size - p->tail + p->head);
                                size_t free = (p->size > 1) ? ((p->size - 1) - used) : 0;
                                int is_write_end = (f->fs_private == (void *)1);
                                release_irqrestore(&p->lock, fl);
                                if (is_write_end) {
                                    if ((events & POLLOUT) && free > 0) revents |= POLLOUT;
                                    if (p->refcount < 2) revents |= POLLHUP;
                                } else {
                                    if ((events & POLLIN) && used > 0) revents |= POLLIN;
                                    if (p->refcount < 2) revents |= POLLHUP;
                                }
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
                    *(short*)((uint8_t*)kbuf + i * entry_size + 6) = revents; /* revents slot at offset 6 */
                    if (revents) ready++;
                }
                if (ready > 0) {
                    if (copy_to_user_safe((void*)ufds, kbuf, bytes) != 0) { kfree(kbuf); return ret_err(EFAULT); }
                    kfree(kbuf);
                    return (uint64_t)ready;
                }
            }

            thread_t *curth_poll = thread_get_current_user();
            if (!curth_poll) curth_poll = thread_current();
            /* Detect if poll set includes network sockets (TCP/UDP) - need e1000_poll */
            int has_net_socket = 0;
            for (int i = 0; i < nfds && !has_net_socket; i++) {
                int fd = *(int*)((uint8_t*)kbuf + i * entry_size + 0);
                if (fd < 0 || fd >= THREAD_MAX_FD) continue;
                struct fs_file *f = curth_poll ? curth_poll->fds[fd] : NULL;
                if (!f || f->type != SYSCALL_FTYPE_SOCKET || !f->driver_private) continue;
                ksock_net_t *s = (ksock_net_t *)f->driver_private;
                if ((s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL) ||
                    (s->type_base == SOCK_DGRAM_LOCAL && s->protocol == IPPROTO_UDP_LOCAL))
                    has_net_socket = 1;
            }
            if (timeout == 0) {
                /* Non-blocking poll: service network once so packets get processed. */
                if (has_net_socket) e1000_poll();
                else thread_sleep(10); /* avoid busy-loop when no network fds */
                kfree(kbuf);
                return 0;
            }
            int step = 10; /* ms */
            int cur_tid = curth_poll ? (int)curth_poll->tid : -1;
            int tty_waiting[16];
            int n_tty_waiting;
            if (timeout < 0) {
                /* block indefinitely: add self as TTY waiter so we wake on keypress.
                   When has_net_socket: must use bounded sleep so we periodically poll e1000 and re-check. */
                for (;;) {
                    if (has_net_socket) e1000_poll();
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
                    if (n_tty_waiting > 0 && !has_net_socket) {
                        thread_block(cur_tid);
                        thread_yield(); /* must yield so keyboard ISR can run and unblock */
                        for (int w = 0; w < n_tty_waiting; w++) devfs_tty_remove_waiter(tty_waiting[w], cur_tid);
                        goto auto_check;
                    }
                    if (n_tty_waiting > 0 && has_net_socket) {
                        thread_block_with_timeout(cur_tid, (uint32_t)step);
                        thread_yield();
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
                int step_ms = has_net_socket ? 10 : 2;
                if (poll_first_entry) { poll_t_start = pit_get_time_ms(); poll_first_entry = 0; }
                while (elapsed < timeout) {
                    if (has_net_socket) e1000_poll();
                    uint32_t sleep_ms = (uint32_t)(timeout - elapsed);
                    if (sleep_ms > (uint32_t)step_ms) sleep_ms = (uint32_t)step_ms;
                    thread_sleep(sleep_ms);
                    elapsed = (int)(pit_get_time_ms() - poll_t_start);
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
            int flags = (int)a2;
            (void)a3;
            if (!path_u || (uintptr_t)path_u >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            char *path = kmalloc(256);
            if (!path) return ret_err(ENOMEM);
            /* path is a heap buffer; sizeof(path) would be sizeof(char*) (8) and truncate paths */
            resolve_user_path(cur, path_u, path, 256);
            if (strcmp(path, "/etc/inittab") == 0) {
                struct stat st;
                if (vfs_stat(path, &st) == 0 && st.st_size == 0) {
                    kfree(path);
                    return ret_err(ENOENT);
                }
            }
            const int O_CREAT_MASK = 0x40;
            const int O_EXCL_MASK  = 0x80;

            /* POSIX: O_CREAT|O_EXCL must fail if file already exists. */
            struct fs_file *f = fs_open(path);
            if (!f) {
                if (strcmp(path, "/console") == 0) f = fs_open("/dev/console");
                else if (strcmp(path, "/tty") == 0) f = fs_open("/dev/tty");
                else if (strcmp(path, "/tty0") == 0) f = fs_open("/dev/tty0");
            }
            if (!f) {
                if (flags & O_CREAT_MASK) {
                    f = fs_create_file(path);
                    if (!f) { kfree(path); return ret_err(ENOENT); }
                } else {
                    kfree(path);
                    return ret_err(ENOENT);
                }
            } else {
                if ((flags & O_CREAT_MASK) && (flags & O_EXCL_MASK)) {
                    fs_file_free(f);
                    kfree(path);
                    return ret_err(EEXIST);
                }
            }
            const int O_TRUNC_MASK = 0x200;
            const int O_APPEND_MASK = 0x400;
            if (f && (flags & O_TRUNC_MASK)) {
                f->pos = 0;
                if (f->type == FS_TYPE_REG) {
                    if (vfs_ftruncate(f, 0) != 0) f->size = 0;
                } else {
                    f->size = 0;
                }
            }
            if (f && (flags & O_APPEND_MASK)) { f->pos = (off_t)(size_t)f->size; }
            int fd = thread_fd_alloc(f);
            kfree(path);
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
                    //klogprintf("openat() returned ENOENT for %s\n", path);
                    return ret_err(ENOENT);
                }
            }
            const int O_CREAT_MASK = 0x40;
            const int O_EXCL_MASK  = 0x80;

            /* POSIX: O_CREAT|O_EXCL must fail if file already exists. */
            struct fs_file *f = fs_open(path);
            if (!f) {
                /* chvt: "console"->/console, "tty"->/tty, "tty0"->/tty0, "vc/0"->/dev/vc/0 (handled by devfs) */
                if (strcmp(path, "/console") == 0) f = fs_open("/dev/console");
                else if (strcmp(path, "/tty") == 0) f = fs_open("/dev/tty");
                else if (strcmp(path, "/tty0") == 0) f = fs_open("/dev/tty0");
            }
            if (!f) {
                if (flags & O_CREAT_MASK) {
                    f = fs_create_file(path);
                    if (!f) return ret_err(ENOENT);
                } else {
                    //klogprintf("openat() returned ENOENT for %s\n", path);
                    return ret_err(ENOENT);
                }
            } else {
                if ((flags & O_CREAT_MASK) && (flags & O_EXCL_MASK)) {
                    fs_file_free(f);
                    return ret_err(EEXIST);
                }
            }
            const int O_TRUNC_MASK = 0x200;
            const int O_APPEND_MASK = 0x400;
            if (f && (flags & O_TRUNC_MASK)) {
                f->pos = 0;
                if (f->type == FS_TYPE_REG) {
                    if (vfs_ftruncate(f, 0) != 0) f->size = 0;
                } else {
                    f->size = 0;
                }
            }
            if (f && (flags & O_APPEND_MASK)) { f->pos = (off_t)(size_t)f->size; }
            int fd = thread_fd_alloc(f);
            if (fd < 0) { fs_file_free(f); return ret_err(EBADF); }
            return (uint64_t)(unsigned)fd;
        }
        case 53: { /* socketpair(domain, type, protocol, sv[2]) - stub AF_UNIX as pipe for wget/openssl */
            int domain = (int)a1;
            void *sv_u = (void*)(uintptr_t)a4;
            if (domain != 1 || !sv_u || (uintptr_t)sv_u + 8 > (uintptr_t)MMIO_IDENTITY_LIMIT)
                return ret_err(EAFNOSUPPORT);
            return syscall_do_inner(SYS_pipe2, (uint64_t)(uintptr_t)sv_u, 0, 0, 0, 0, 0);
        }
        case SYS_pipe:
        case SYS_pipe2: {
            /* pipe(int pipefd[2]); pipe2(int pipefd[2], int flags). flags (e.g. O_CLOEXEC) ignored for now. */
            void *pipefd_u = (void*)(uintptr_t)a1;
            (void)a2; /* flags for pipe2 */
            if (!pipefd_u || (uintptr_t)pipefd_u + 8 > (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
            pipe_t *p = (pipe_t *)kmalloc(sizeof(pipe_t));
            if (!p) { qemu_debug_printf("OOM: pipe pipe_t alloc\n"); return ret_err(ENOMEM); }
            p->buf = (uint8_t *)kmalloc(PIPE_BUF_SIZE);
            if (!p->buf) { qemu_debug_printf("OOM: pipe buf alloc %u\n", (unsigned)PIPE_BUF_SIZE); kfree(p); return ret_err(ENOMEM); }
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
            thread_t *t = thread_get_current_user();
            if (!t) t = thread_current();
            if (t) {
                struct fs_file *f = t->fds[fd];
                /* Free socket private state only on final close of shared fs_file. */
                if (f && f->type == SYSCALL_FTYPE_SOCKET && f->driver_private && f->refcount <= 1) {
                    ksock_net_t *s = (ksock_net_t *)f->driver_private;
                    if (s->type_base == SOCK_STREAM_LOCAL && s->protocol == IPPROTO_TCP_LOCAL && !s->dns_tcp_udp_bridge) {
                        net_tcp_ops_t ops;
                        net_make_tcp_ops(&ops);
                        (void)net_tcp_close(&s->tcp, &ops, 1000);
                    }
                    kfree(f->driver_private);
                    f->driver_private = NULL;
                }
            }
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
            enum { AT_FDCWD = -100 };
            /* Linux AT_* flags */
            enum { AT_SYMLINK_NOFOLLOW = 0x100 };
            int st_ready = 0;
            /* AT_EMPTY_PATH (0x1000): stat the file given by dirfd when path is empty (or NULL). */
            char first = '\0';
            int empty_path = 0;
            if ((flags & 0x1000) != 0) {
                if (!path_u) {
                    empty_path = 1;
                } else {
                    if (copy_from_user_raw(&first, path_u, 1) != 0) return ret_err(EFAULT);
                    if (first == '\0') empty_path = 1;
                }
            }
            if (empty_path) {
                if (dirfd < 0 || dirfd >= THREAD_MAX_FD) return ret_err(EBADF);
                struct fs_file *f = cur->fds[dirfd];
                if (!f) return ret_err(EBADF);
                if (vfs_fstat(f, &st) != 0) return ret_err(EINVAL);
                st_ready = 1;
            } else {
                if (!path_u) {
                    /* Be permissive for userland quirks: NULL path -> stat dirfd/cwd instead of hard fault. */
                    if (dirfd == AT_FDCWD) {
                        if (vfs_stat(cur->cwd[0] ? cur->cwd : "/", &st) != 0) return ret_err(ENOENT);
                        st_ready = 1;
                    } else if (dirfd >= 0 && dirfd < THREAD_MAX_FD && cur->fds[dirfd]) {
                        if (vfs_fstat(cur->fds[dirfd], &st) != 0) return ret_err(EINVAL);
                        st_ready = 1;
                    } else {
                        return ret_err(EFAULT);
                    }
                } else {
                    char *kpath = copy_user_cstr(path_u, 256);
                    if (!kpath) {
                        /* Avoid tight retry loops in userspace on EFAULT; fallback to dirfd/cwd stat. */
                        if (dirfd == AT_FDCWD) {
                            if (vfs_stat(cur->cwd[0] ? cur->cwd : "/", &st) != 0) return ret_err(ENOENT);
                            st_ready = 1;
                        } else if (dirfd >= 0 && dirfd < THREAD_MAX_FD && cur->fds[dirfd]) {
                            if (vfs_fstat(cur->fds[dirfd], &st) != 0) return ret_err(EINVAL);
                            st_ready = 1;
                        } else {
                            return ret_err(EFAULT);
                        }
                    } else {
                        char path[256];
                        int rc_resolve = 0;
                        if (kpath[0] == '/') {
                            resolve_user_path(cur, kpath, path, sizeof(path));
                        } else if (dirfd == AT_FDCWD) {
                            resolve_user_path(cur, kpath, path, sizeof(path));
                        } else {
                            if (dirfd < 0 || dirfd >= THREAD_MAX_FD) rc_resolve = -EBADF;
                            else {
                                struct fs_file *df = cur->fds[dirfd];
                                if (!df) rc_resolve = -EBADF;
                                else if (df->type != FS_TYPE_DIR) rc_resolve = -ENOTDIR;
                                else {
                                    const char *base = df->path ? df->path : "/";
                                    if (strcmp(base, "/") == 0) snprintf(path, sizeof(path), "/%s", kpath);
                                    else snprintf(path, sizeof(path), "%s/%s", base, kpath);
                                    path[sizeof(path) - 1] = '\0';
                                    if (path_needs_normalize(path)) normalize_path(path, sizeof(path));
                                }
                            }
                        }
                        kfree(kpath);
                        if (rc_resolve != 0) {
                            if (rc_resolve == -EBADF) return ret_err(EBADF);
                            if (rc_resolve == -ENOTDIR) return ret_err(ENOTDIR);
                            if (rc_resolve == -ENOENT) return ret_err(ENOENT);
                            return ret_err(EFAULT);
                        }
                        /* Respect AT_SYMLINK_NOFOLLOW: behave like lstat() when requested. */
                        int sr = (flags & AT_SYMLINK_NOFOLLOW) ? vfs_lstat(path, &st) : vfs_stat(path, &st);
                        if (sr != 0) return ret_err(ENOENT);
                        st_ready = 1;
                    }
                }
            }
            if (!st_ready) return ret_err(EFAULT);

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
            /* 0=SET 1=CUR 2=END; 3=SEEK_DATA 4=SEEK_HOLE (Linux) — glibc/wget use 3/4 on regular files */
            if (whence == 0)
                newpos = (off_t)off;
            else if (whence == 1)
                newpos = (off_t)((int64_t)f->pos + off);
            else if (whence == 2)
                newpos = (off_t)((int64_t)f->size + off);
            else if (whence == 3)
                newpos = (off_t)off;
            else if (whence == 4) { /* SEEK_HOLE: no sparse files; hole begins at EOF */
                if ((off_t)off >= (off_t)f->size)
                    newpos = (off_t)off;
                else
                    newpos = (off_t)f->size;
            } else
                return ret_err(EINVAL);
            if (newpos < 0) return ret_err(EINVAL);
            f->pos = newpos;
            return (uint64_t)(uint64_t)f->pos;
        }
        case SYS_ftruncate: {
            int fd = (int)a1;
            int64_t len64 = (int64_t)a2;
            if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
            struct fs_file *f = cur->fds[fd];
            if (!f) return ret_err(EBADF);
            if (f->type == SYSCALL_FTYPE_SOCKET) return ret_err(EINVAL);
            if (len64 < 0) return ret_err(EINVAL);
            int r = vfs_ftruncate(f, (off_t)len64);
            if (r == 0) return 0;
            if (r < 0) return ret_err(-r);
            return ret_err(EINVAL);
        }
        case SYS_getdents: /* historic getdents syscall (78) */
        case SYS_getdents64: {
            int fd = (int)a1;
            void *dirp_u = (void*)(uintptr_t)a2;
            size_t count = (size_t)a3;
            int want64 = (num == SYS_getdents64);
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
                /* Never read past this record — avoids "+" or garbage from next entry. */
                if (name_len_use > 255) name_len_use = 255;

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

                uint8_t dtype = 0; /* DT_UNKNOWN */
                if (out_type == EXT2_FT_DIR) dtype = 4;       /* DT_DIR */
                else if (out_type == EXT2_FT_REG_FILE) dtype = 8; /* DT_REG */
                else if (out_type == EXT2_FT_SYMLINK) dtype = 10; /* DT_LNK */

                size_t reclen;
                if (want64) {
                    /* linux_dirent64: ino(8), off(8), reclen(2), type(1), name[] */
                    reclen = 19 + nlen + 1;
                } else {
                    /* linux_dirent: ino(8), off(8), reclen(2), name[], ..., type at last byte */
                    reclen = 18 + nlen + 1 + 1;
                }
                reclen = (reclen + 7) & ~7u;
                if (out_off + reclen > out_cap) break;

                uint8_t *outp = outbuf + out_off;
                *(uint64_t*)(outp + 0) = (uint64_t)out_ino;
                *(int64_t*)(outp + 8) = (int64_t)f->pos;
                *(uint16_t*)(outp + 16) = (uint16_t)reclen;
                if (want64) {
                    outp[18] = dtype;
                    memcpy(outp + 19, nm, nlen);
                    outp[19 + nlen] = '\0';
                    for (size_t z = 19 + nlen + 1; z < reclen; z++) outp[z] = 0;
                } else {
                    memcpy(outp + 18, nm, nlen);
                    outp[18 + nlen] = '\0';
                    for (size_t z = 19 + nlen; z + 1 < reclen; z++) outp[z] = 0;
                    outp[reclen - 1] = dtype;
                }

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
                    (void)copy_from_user_raw(&old_guard, (const void *)(uintptr_t)(old_fs + 0x28), sizeof(old_guard));
                } else if (0x30 < (uint64_t)MMIO_IDENTITY_LIMIT) {
                    /* common boot case: old_fs==0 */
                    (void)copy_from_user_raw(&old_guard, (const void *)(uintptr_t)0x28, sizeof(old_guard));
                }

                cur->user_fs_base = addr;
                msr_write_u64(MSR_FS_BASE, addr);

                if (addr + 0x30 < (uint64_t)MMIO_IDENTITY_LIMIT) {
                    (void)copy_to_user_safe((void *)(uintptr_t)(addr + 0x28), &old_guard, sizeof(old_guard));
                }
                return 0;
            } else if (code == ARCH_GET_FS) {
                if (addr >= (uint64_t)MMIO_IDENTITY_LIMIT) return ret_err(EFAULT);
                if (copy_to_user_safe((void *)(uintptr_t)addr, &cur->user_fs_base, sizeof(cur->user_fs_base)) != 0)
                    return ret_err(EFAULT);
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
            (void)a4; (void)a5;
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
            } else if (strcmp(k_type, "fat32") == 0 || strcmp(k_type, "vfat") == 0 || strcmp(k_type, "msdos") == 0 || strcmp(k_type, "auto") == 0) {
                if (!src_u) { kfree(k_type); return ret_err(EINVAL); }
                char *k_src_raw = copy_user_cstr(src_u, 256);
                if (!k_src_raw) { kfree(k_type); return ret_err(EFAULT); }
                char source[256];
                resolve_user_path(cur, k_src_raw, source, sizeof(source));
                kfree(k_src_raw);
                if (source[0] == '\0') { kfree(k_type); return ret_err(EINVAL); }

                int dev_id = devfs_get_device_id(source);
                if (dev_id < 0) { kfree(k_type); return ret_err(ENOENT); }

                /* Ensure FAT32 state is initialized for this device. */
                if (fat32_probe_and_mount(dev_id) != 0) { kfree(k_type); return ret_err(EINVAL); }
                struct fs_driver *drv = fat32_get_driver();
                if (!drv) { kfree(k_type); return ret_err(ENOSYS); }

                ramfs_mkdir(target);
                rc = fs_mount(target, drv);
            } else {
                rc = -1;
            }

            kfree(k_type);
            return (rc == 0) ? 0 : ret_err(ENOSYS);
        }
        case SYS_umount2: {
            /* umount2(target, flags) */
            const char *tgt_u = (const char*)(uintptr_t)a1;
            int flags = (int)a2;
            /* Support only the common case flags==0; ignore MNT_DETACH etc for now. */
            if (flags != 0) return ret_err(ENOSYS);
            if (!tgt_u) return ret_err(EINVAL);
            char *k_tgt_raw = copy_user_cstr(tgt_u, 256);
            if (!k_tgt_raw) return ret_err(EFAULT);
            char target[256];
            resolve_user_path(cur, k_tgt_raw, target, sizeof(target));
            kfree(k_tgt_raw);
            if (target[0] == '\0') return ret_err(EINVAL);
            /* normalize: strip trailing slashes except root */
            size_t n = strlen(target);
            while (n > 1 && target[n - 1] == '/') target[--n] = '\0';

            struct fs_driver *drv = fs_get_mount_driver(target);
            int rc = fs_unmount(target);
            if (rc != 0) return ret_err(EINVAL);

            /* driver-specific cleanup */
            if (drv && drv->ops && drv->ops->name) {
                if (strcmp(drv->ops->name, "fat32") == 0) {
                    fat32_unmount_cleanup();
                }
            }
            return 0;
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
            if (req >= (uintptr_t)MMIO_IDENTITY_LIMIT || *p_cur >= (uintptr_t)MMIO_IDENTITY_LIMIT ||
                *p_base >= (uintptr_t)MMIO_IDENTITY_LIMIT) {
                *p_base = 8u * 1024u * 1024u;
                *p_cur = *p_base;
                return (uint64_t)(*p_cur);
            }
            /* Don't allow brk to collide with reserved TLS/stack area. */
            uintptr_t top_limit = (uintptr_t)USER_TLS_BASE;
            if (tcur) {
                uintptr_t tls_base = user_tls_base_for_tid_local(tcur->tid);
                if (tls_base > 0x200000 && tls_base < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    top_limit = tls_base;
                }
            }
            /* Userspace shares identity map with kernel heap: never let brk reach heap region.
               Only restrict when kernel heap could overlap user brk range [*p_base, top_limit). */
            {
                uintptr_t heap_lo = (uintptr_t)heap_base_addr();
                if (heap_lo > *p_base && heap_lo < top_limit) {
                    uintptr_t guard = 0x10000u;
                    top_limit = (heap_lo > guard) ? (heap_lo - guard) : heap_lo;
                }
            }
            /* Linux brk(2) semantics: on failure, return current brk (no -errno). */
            if (req < *p_base || req >= top_limit) return (uint64_t)(*p_cur);
            /* mark and zero new range */
            if (req > *p_cur) {
                if (mark_user_identity_range_2m_sys((uint64_t)(*p_cur), (uint64_t)req) != 0)
                    return (uint64_t)(*p_cur);
                memset((void*)(*p_cur), 0, req - (*p_cur));
            }
            *p_cur = req;
            return (uint64_t)(*p_cur);
        }
        case SYS_mmap: {
            /* mmap(addr,len,prot,flags,fd,off) - anonymous and file-backed MAP_PRIVATE */
            qemu_debug_printf("mmap: entry len=0x%llx prot=%d flags=0x%x\n",
                (unsigned long long)a2, (int)a3, (int)a4);
            (void)a1;
            size_t len = (size_t)a2;
            int prot = (int)a3;
            int flags = (int)a4;
            (void)prot;
            if (len == 0) { qemu_debug_printf("mmap: EINVAL len=0\n"); return ret_err(EINVAL); }
            len = (size_t)align_up_u((uintptr_t)len, 4096);
            enum { MAP_FIXED = 0x10, MAP_ANONYMOUS = 0x20, MAP_PRIVATE = 0x02,
                   MAP_SHARED = 0x01,
                   MAP_STACK = 0x20000, MAP_GROWSDOWN = 0x0100, MAP_NORESERVE = 0x4000 };
            if (flags & MAP_FIXED) { qemu_debug_printf("mmap: EINVAL MAP_FIXED\n"); return ret_err(EINVAL); }
            /* Many userspace tools (including xxd) use MAP_SHARED for read-only mmaps.
               We don't implement true shared mappings; treat MAP_SHARED like MAP_PRIVATE. */
            if (!(flags & (MAP_PRIVATE | MAP_SHARED))) { qemu_debug_printf("mmap: ENOSYS no priv/shared\n"); return ret_err(ENOSYS); }
            thread_t *tcur = thread_get_current_user();
            if (!tcur) tcur = thread_current();
            qemu_debug_printf("mmap: tcur tid=%d stack_base=0x%llx stack_limit=0x%llx\n",
                tcur ? (int)tcur->tid : -1,
                tcur ? (unsigned long long)tcur->user_stack_base : 0,
                tcur ? (unsigned long long)tcur->user_stack_limit : 0);
            /* Cap huge mmaps for clone3: 128MB zeroing causes reboot (bad phys range / overwrite) */
            if (tcur && tcur->user_stack_base != 0 && len > 16u * 1024u * 1024u) {
                len = 16u * 1024u * 1024u;
                len = (size_t)align_up_u((uintptr_t)len, 4096);
                qemu_debug_printf("mmap: clone3 len capped to 0x%llx\n", (unsigned long long)len);
            }
            uintptr_t *p_mmap_next = tcur ? &tcur->user_mmap_next : &user_mmap_next;
            uintptr_t top_limit = (uintptr_t)USER_TLS_BASE;
            if (tcur) {
                uintptr_t tls_base = user_tls_base_for_tid_local(tcur->tid);
                if (tls_base > 0x200000 && tls_base < (uintptr_t)MMIO_IDENTITY_LIMIT)
                    top_limit = tls_base;
            }
            /* Keep all user mmaps below kernel heap. Only restrict when kernel heap overlaps. */
            {
                uintptr_t brk_base = tcur ? tcur->user_brk_base : user_brk_base;
                if (brk_base == 0) brk_base = 8u * 1024u * 1024u;
                uintptr_t heap_lo = (uintptr_t)heap_base_addr();
                if (heap_lo > brk_base && heap_lo < top_limit) {
                    uintptr_t guard = 0x10000u;
                    top_limit = (heap_lo > guard) ? (heap_lo - guard) : heap_lo;
                }
            }
            qemu_debug_printf("mmap: top_limit=0x%llx heap_lo=0x%llx mmap_next=0x%llx\n",
                (unsigned long long)top_limit, (unsigned long long)(uintptr_t)heap_base_addr(), (unsigned long long)*p_mmap_next);
            if (*p_mmap_next == 0) {
                uintptr_t def = 32u * 1024u * 1024u;
                if (def >= top_limit && top_limit > (8u * 1024u * 1024u)) {
                    def = align_up_u(top_limit / 2u, 4096);
                    if (def < (8u * 1024u * 1024u)) def = 8u * 1024u * 1024u;
                }
                *p_mmap_next = def;
                qemu_debug_printf("mmap: init mmap_next=0x%llx\n", (unsigned long long)*p_mmap_next);
            }
            /* Clone3: keep mmap above stack when safe; but never above top_limit (heap_lo ~64 MiB).
               Otherwise mmap would ENOMEM and programs like wget fail with "out of memory". */
            if (tcur && tcur->user_stack_base != 0 && tcur->user_stack_limit > tcur->user_stack_base) {
                uintptr_t se = (uintptr_t)tcur->user_stack_limit;
                uintptr_t min_alloc = align_up_u(se, PAGE_SIZE_2M);
                if (tcur->user_fs_base > se && tcur->user_fs_base < (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    uintptr_t tls_min = align_up_u((uintptr_t)tcur->user_fs_base + 0x3000u, PAGE_SIZE_2M);
                    if (tls_min > min_alloc) min_alloc = tls_min;
                }
                if (min_alloc < top_limit && *p_mmap_next < min_alloc)
                    *p_mmap_next = min_alloc;
                else if (*p_mmap_next >= top_limit)
                    *p_mmap_next = align_up_u(top_limit / 2u, 4096); /* clamp to valid range */
                qemu_debug_printf("mmap: clone3 adj mmap_next=0x%llx (min_alloc 2MB-aligned)\n",
                    (unsigned long long)*p_mmap_next);
            }
            uintptr_t addr = align_up_u(*p_mmap_next, 4096);
            /* Clone3: place mmap on 2MB boundary above stack so munmap won't unmap the stack
               (unmap clears whole 2MB L2 entries; stack shares 0x2800000-0x2a00000 with 0x2804000).
               Only use above-stack placement if it fits within top_limit (VMware: heap/stack layout
               can leave top_limit below stack, causing ENOMEM and "out of memory" in wget). */
            if (tcur && tcur->user_stack_base != 0 && tcur->user_stack_limit > tcur->user_stack_base) {
                uintptr_t sb = (uintptr_t)tcur->user_stack_base;
                uintptr_t se = (uintptr_t)tcur->user_stack_limit;
                if (!(addr + len <= sb || addr >= se)) {
                    uintptr_t above_stack = align_up_u(se, PAGE_SIZE_2M);
                    if (above_stack + len < top_limit) {
                        addr = above_stack;
                        *p_mmap_next = addr;
                        qemu_debug_printf("mmap: clone3 addr=0x%llx above stack (2MB aligned)\n", (unsigned long long)addr);
                    }
                    /* else: keep addr below stack; above-stack would exceed top_limit */
                }
            }
            qemu_debug_printf("mmap: addr=0x%llx len=0x%llx addr+len=0x%llx\n",
                (unsigned long long)addr, (unsigned long long)len, (unsigned long long)(addr + len));
            if (addr + len >= top_limit) { qemu_debug_printf("mmap: ENOMEM top_limit\n"); return ret_err(ENOMEM); }
            /* Paranoid: never let mmap overlap kernel heap (identity map = zeroing would destroy heap) */
            {
                uintptr_t heap_lo = (uintptr_t)heap_base_addr();
                if (heap_lo > 0x200000 && addr + len > heap_lo - 0x10000u) {
                    qemu_debug_printf("mmap: ENOMEM would overwrite heap (addr+len=0x%llx heap_lo=0x%llx)\n",
                        (unsigned long long)(addr + len), (unsigned long long)heap_lo);
                    return ret_err(ENOMEM);
                }
            }
            if (addr < 0x200000 || addr + len > (uintptr_t)USER_STACK_TOP) {
                qemu_debug_printf("mmap: mark range 0x%llx..0x%llx\n", (unsigned long long)addr, (unsigned long long)(addr + len));
                if (mark_user_identity_range_2m_sys((uint64_t)addr, (uint64_t)(addr + len)) != 0) {
                    qemu_debug_printf("mmap: mark FAILED\n");
                    return ret_err(EFAULT);
                }
            } else if (tcur && tcur->user_stack_base != 0) {
                /* Clone3 child: mark can #PF when writing to read-only page tables.
                   Use map_page_2m to ensure region is mapped (creates/updates L2 with PG_US). */
                uintptr_t map_begin = addr & ~((uintptr_t)PAGE_SIZE_2M - 1);
                uintptr_t map_end = (addr + len + PAGE_SIZE_2M - 1) & ~((uintptr_t)PAGE_SIZE_2M - 1);
                if (map_end > (uintptr_t)USER_STACK_TOP) map_end = (uintptr_t)USER_STACK_TOP;
                qemu_debug_printf("mmap: clone3 map_page_2m 0x%llx..0x%llx\n",
                    (unsigned long long)map_begin, (unsigned long long)map_end);
                for (uintptr_t va = map_begin; va < map_end; va += PAGE_SIZE_2M) {
                    if (map_page_2m(va, va, PG_PRESENT | PG_RW | PG_US) != 0) {
                        qemu_debug_printf("mmap: map_page_2m FAILED va=0x%llx\n", (unsigned long long)va);
                        return ret_err(EFAULT);
                    }
                }
                qemu_debug_printf("mmap: clone3 map_page_2m ok\n");
            } else if (addr >= 0x200000 && addr + len <= (uintptr_t)USER_STACK_TOP) {
                /* Parent or non-clone3: region may have been munmap'd by sibling (e.g. clone3 child).
                   Always ensure mapped before memset to avoid kernel #PF. */
                uintptr_t map_begin = addr & ~((uintptr_t)PAGE_SIZE_2M - 1);
                uintptr_t map_end = (addr + len + PAGE_SIZE_2M - 1) & ~((uintptr_t)PAGE_SIZE_2M - 1);
                if (map_end > (uintptr_t)USER_STACK_TOP) map_end = (uintptr_t)USER_STACK_TOP;
                for (uintptr_t va = map_begin; va < map_end; va += PAGE_SIZE_2M) {
                    if (map_page_2m(va, va, PG_PRESENT | PG_RW | PG_US) != 0)
                        return ret_err(EFAULT);
                }
            }

            if (flags & MAP_ANONYMOUS) {
                flags &= ~(MAP_ANONYMOUS | MAP_PRIVATE | MAP_SHARED | MAP_STACK | MAP_GROWSDOWN | MAP_NORESERVE);
                if (flags != 0) return ret_err(ENOSYS);
                qemu_debug_printf("mmap: memset 0x%llx len=0x%llx\n", (unsigned long long)addr, (unsigned long long)len);
                if (len > 4u * 1024u * 1024u) {
                    /* Large mmap: zero in 4MB chunks with progress so we see if we fault or just slow */
                    size_t chunk = 4u * 1024u * 1024u;
                    for (size_t off = 0; off < len; off += chunk) {
                        size_t now = (len - off < chunk) ? (len - off) : chunk;
                        memset((void*)(addr + off), 0, now);
                        if (off + now < len)
                            qemu_debug_printf("mmap: memset progress 0x%llx/%llx\n",
                                (unsigned long long)(off + now), (unsigned long long)len);
                    }
                } else {
                    memset((void*)addr, 0, len);
                }
                qemu_debug_printf("mmap: memset done\n");
            } else {
                /* File-backed MAP_PRIVATE (e.g. BusyBox rpm mmaps .rpm file) */
                int fd = (int)(int64_t)a5;
                off_t file_off = (off_t)(int64_t)a6;
                if (fd < 0 || fd >= THREAD_MAX_FD) return ret_err(EBADF);
                struct fs_file *f = cur->fds[fd];
                if (!f) return ret_err(EBADF);
                if (f->type != FS_TYPE_REG) return ret_err(EBADF);
                if (fbdev_is_fb0_file(f)) {
                    if (!fbdev_is_active()) {
                        qemu_debug_printf("mmap: /dev/fb0 inactive\n");
                        return ret_err(ENODEV);
                    }
                    if (file_off < 0) return ret_err(EINVAL);
                    size_t fo = (size_t)file_off;
                    size_t cap = f->size;
                    if (fo > cap) return ret_err(EINVAL);
                    size_t maxl = cap - fo;
                    size_t maplen = len;
                    if (maplen > maxl) maplen = maxl;
                    if (maplen > 0) {
                        qemu_debug_printf("mmap: fb0 0x%llx len=0x%llx off=0x%llx\n",
                            (unsigned long long)addr, (unsigned long long)maplen, (unsigned long long)fo);
                        if (fbdev_mmap_user(addr, maplen, fo) != 0) {
                            qemu_debug_printf("mmap: fb0 map failed\n");
                            return ret_err(EFAULT);
                        }
                    }
                } else {
                    qemu_debug_printf("mmap: file memset 0x%llx len=0x%llx\n", (unsigned long long)addr, (unsigned long long)len);
                    memset((void*)addr, 0, len);
                    size_t file_avail = 0;
                    if ((size_t)file_off < f->size) file_avail = f->size - (size_t)file_off;
                    size_t to_read = len < file_avail ? len : file_avail;
                    if (to_read > 0) {
                        ssize_t nr = fs_read(f, (void*)addr, to_read, (size_t)file_off);
                        (void)nr; /* partial read leaves rest zeroed */
                    }
                }
            }
            qemu_debug_printf("mmap: ok return 0x%llx\n", (unsigned long long)addr);
            *p_mmap_next = addr + len;
            {
                uintptr_t he = (uintptr_t)(addr + len);
                if (tcur) {
                    if (he > tcur->user_mmap_hi) tcur->user_mmap_hi = he;
                } else {
                    if (he > user_mmap_hi) user_mmap_hi = he;
                }
            }
            return (uint64_t)addr;
        }
        case SYS_munmap: {
            uintptr_t addr = (uintptr_t)a1;
            size_t len = (size_t)a2;
            if (len == 0) return 0;
            len = (size_t)align_up_u((uintptr_t)len, 4096);
            if (addr < 0x200000) return ret_err(EINVAL);
            if (addr + len >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EINVAL);
            if ((addr & 0xFFF) != 0) return ret_err(EINVAL);
            /* Never unmap clone3 stack (unmap clears whole 2MB L2 entries; would kill stack) */
            thread_t *tcur_m = thread_get_current_user();
            if (!tcur_m) tcur_m = thread_current();
            if (tcur_m && tcur_m->user_stack_base != 0 && tcur_m->user_stack_limit > tcur_m->user_stack_base) {
                uintptr_t sb = (uintptr_t)tcur_m->user_stack_base;
                uintptr_t se = (uintptr_t)tcur_m->user_stack_limit;
                /* Reject if [addr, addr+len) overlaps [sb, se) */
                if (!(addr + len <= sb || addr >= se))
                    return ret_err(EINVAL);
            }
            if (unmap_user_range_sys((uint64_t)addr, (uint64_t)(addr + len)) != 0)
                return ret_err(EINVAL);
            return 0;
        }
        case SYS_madvise: {
            /* madvise(addr, length, advice) - syscall 28; glibc/apm uses MADV_DONTNEED etc.; stub success */
            (void)a1; (void)a2; (void)a3;
            return 0;
        }
        case SYS_mprotect: {
            uintptr_t addr = (uintptr_t)a1;
            size_t len = (size_t)a2;
            int prot = (int)a3;
            if (len == 0) return 0;
            len = (size_t)align_up_u((uintptr_t)len, 4096);
            if (addr < 0x200000) return ret_err(EINVAL);
            if (addr + len >= (uintptr_t)MMIO_IDENTITY_LIMIT) return ret_err(EINVAL);
            if ((addr & 0xFFF) != 0) return ret_err(EINVAL);
            if ((prot & ~7) != 0) return ret_err(EINVAL);  /* PROT_READ|WRITE|EXEC only */
            if (mprotect_user_range_sys((uint64_t)addr, (uint64_t)(addr + len), prot) != 0)
                return ret_err(EINVAL);
            return 0;
        }
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
                /* close all FDs so pipes/sockets release (reader gets EOF, wait4 can proceed) */
                for (int i = 0; i < THREAD_MAX_FD; i++) {
                    if (cur->fds[i]) {
                        struct fs_file *f = cur->fds[i];
                        cur->fds[i] = NULL;
                        fs_file_free(f);
                    }
                }
                thread_yield(); /* let pipe reader run and see EOF before we wake vfork parent */
                if (cur->parent_tid >= 0) {
                    thread_t *pt = thread_get(cur->parent_tid);
                    if (pt) {
                        thread_set_pending_signal(pt, SIGCHLD);
                        if (cur->attached_tty >= 0 && pt->attached_tty == cur->attached_tty) {
                            devfs_set_tty_fg_pgrp(cur->attached_tty, pt->pgid);
                        }
                    }
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
                    if (is_watch_proc(cur)) {
                        kprintf("exit: pid=%llu (%s) waking waiter=%d\n",
                            (unsigned long long)(cur->tid ? cur->tid : 1),
                            cur->name,
                            cur->waiter_tid);
                    }
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
                /* Clone3 child (CLONE_VM): propagate brk/mmap to parent so parent won't
                   reuse child's allocations and overwrite shared memory -> stack smashing. */
                if (cur->user_stack_base != 0 && cur->parent_tid >= 0) {
                    thread_t *pt = thread_get(cur->parent_tid);
                    if (pt) {
                        if (pt->user_brk_cur < cur->user_brk_cur)
                            pt->user_brk_cur = cur->user_brk_cur;
                        if (pt->user_mmap_next < cur->user_mmap_next)
                            pt->user_mmap_next = cur->user_mmap_next;
                    }
                }
            }
            /* mark terminated */
            if (cur) {
                cur->state = THREAD_TERMINATED;
                if (is_watch_proc(cur)) {
                    kprintf("exit: tid=%llu name=%s exit_status=0x%x waiter_tid=%d parent_tid=%d\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        (cur->name[0] ? cur->name : "(noname)"),
                        (unsigned)cur->exit_status,
                        cur->waiter_tid,
                        cur->parent_tid);
                }
                /* Release private address space on task exit. */
                if (cur->mm && cur->mm != mm_kernel()) {
                    mm_release(cur->mm);
                    cur->mm = mm_kernel();
                }
            }
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
                devfs_tty_remove_waiter_from_all_ttys((int)(cur->tid ? cur->tid : 1));
                exit_group_reap_peer_threads(cur);
                int code = (int)a1;
                cur->exit_status = (code & 0xFF) << 8;
                /* close all FDs so pipes/sockets release (reader gets EOF, wait4 can proceed) */
                for (int i = 0; i < THREAD_MAX_FD; i++) {
                    if (cur->fds[i]) {
                        struct fs_file *f = cur->fds[i];
                        cur->fds[i] = NULL;
                        fs_file_free(f);
                    }
                }
                thread_yield(); /* let pipe reader run and see EOF before we wake vfork parent */
                if (cur->parent_tid >= 0) {
                    thread_t *pt = thread_get(cur->parent_tid);
                    if (pt) {
                        thread_set_pending_signal(pt, SIGCHLD);
                        if (cur->attached_tty >= 0 && pt->attached_tty == cur->attached_tty) {
                            devfs_set_tty_fg_pgrp(cur->attached_tty, pt->pgid);
                        }
                    }
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
                /* Clone3 child (CLONE_VM): propagate brk/mmap to parent so parent won't
                   reuse child's allocations and overwrite shared memory -> stack smashing. */
                if (cur->user_stack_base != 0 && cur->parent_tid >= 0) {
                    thread_t *pt = thread_get(cur->parent_tid);
                    if (pt) {
                        if (pt->user_brk_cur < cur->user_brk_cur)
                            pt->user_brk_cur = cur->user_brk_cur;
                        if (pt->user_mmap_next < cur->user_mmap_next)
                            pt->user_mmap_next = cur->user_mmap_next;
                    }
                }
                cur->state = THREAD_TERMINATED;
                if (is_watch_proc(cur)) {
                    kprintf("exit_group: tid=%llu name=%s exit_status=0x%x waiter_tid=%d parent_tid=%d\n",
                        (unsigned long long)(cur->tid ? cur->tid : 1),
                        (cur->name[0] ? cur->name : "(noname)"),
                        (unsigned)cur->exit_status,
                        cur->waiter_tid,
                        cur->parent_tid);
                }
                if (cur->mm_ptemplate) {
                    mm_release(cur->mm_ptemplate);
                    cur->mm_ptemplate = NULL;
                }
                if (cur->mm && cur->mm != mm_kernel()) {
                    mm_release(cur->mm);
                    cur->mm = mm_kernel();
                }
            }
            thread_t *kcur = thread_current();
            if (kcur && kcur->tid != 0) {
                thread_yield();
                for (;;) asm volatile("sti; hlt" ::: "memory");
            }
            syscall_exit_to_shell_flag = 1;
            return 0;
        }
        case SYS_rt_sigreturn: {
            /* rt_sigreturn: restore from ucontext on user stack. RSP at entry = ucontext. */
            uintptr_t uc_ptr = (uintptr_t)syscall_user_rsp_saved;
            if (uc_ptr < 0x200000 || uc_ptr + sizeof(k_ucontext_t) > (uintptr_t)MMIO_IDENTITY_LIMIT)
                return ret_err(EFAULT);
            k_ucontext_t uc;
            if (copy_from_user_raw(&uc, (const void *)uc_ptr, sizeof(uc)) != 0)
                return ret_err(EFAULT);
            k_sigcontext_t *sc = &uc.uc_mcontext;
            cur->saved_user_r8  = sc->r8;
            cur->saved_user_r9  = sc->r9;
            cur->saved_user_r10 = sc->r10;
            cur->saved_user_r11 = sc->r11;
            cur->saved_user_r12 = sc->r12;
            cur->saved_user_r13 = sc->r13;
            cur->saved_user_r14 = sc->r14;
            cur->saved_user_r15 = sc->r15;
            cur->saved_user_rdi = sc->rdi;
            cur->saved_user_rsi = sc->rsi;
            cur->saved_user_rbp = sc->rbp;
            cur->saved_user_rbx = sc->rbx;
            cur->saved_user_rdx = sc->rdx;
            cur->saved_user_rcx = sc->rcx;
            cur->saved_user_rip = sc->rip;
            cur->saved_user_rsp = sc->rsp;
            cur->saved_sig_mask = uc.uc_sigmask[0];
            rebuild_syscall_frame(cur);
            syscall_user_rsp_saved = sc->rsp;
            return sc->rax;
        }
        case 91: /* set_robust_list(head, len) - glibc/pthread; no-op */
            (void)a1; (void)a2;
            return 0;
        case 93: /* set_tid_address(tidptr) - glibc for exit notification; no-op */
            (void)a1;
            return 0;
        case SYS_resolve: { /* resolve(hostname, out_ip_be) - full resolver: hosts then DNS; hostname user ptr, out_ip_be user ptr to uint32_t */
            const char *host_u = (const char *)(uintptr_t)a1;
            uint32_t *out_u = (uint32_t *)(uintptr_t)a2;
            if (!host_u || !out_u || !user_range_ok(host_u, 1) || !user_range_ok(out_u, 4))
                return ret_err(EFAULT);
            static int resolve_dbg_left = 8;
            char host[256];
            size_t i = 0;
            for (; i < sizeof(host) - 1; i++) {
                char c;
                if (copy_from_user_raw(&c, host_u + i, 1) != 0) return ret_err(EFAULT);
                host[i] = c;
                if (c == '\0') break;
            }
            host[sizeof(host) - 1] = '\0';
            if (i >= sizeof(host) - 1) return ret_err(ENAMETOOLONG);

            /* Ensure net stack is initialized before reading dns/gw fields.
               Otherwise g_net.{dns_be,gw_be} can be 0 and resolver returns EIO. */
            if (net_stack_init() != 0) return ret_err(ENETDOWN);
            uint32_t dns_be = g_net.dns_be ? g_net.dns_be : g_net.gw_be;
            if (!dns_be) return ret_err(ENETDOWN);
            if (resolve_dbg_left-- > 0) {
                klogprintf("resolve: host=%s ip=%u.%u.%u.%u gw=%u.%u.%u.%u dns=%u.%u.%u.%u use_dns=%u.%u.%u.%u\n",
                    host,
                    (unsigned)((g_net.ip_be >> 24) & 0xFF), (unsigned)((g_net.ip_be >> 16) & 0xFF),
                    (unsigned)((g_net.ip_be >> 8) & 0xFF), (unsigned)(g_net.ip_be & 0xFF),
                    (unsigned)((g_net.gw_be >> 24) & 0xFF), (unsigned)((g_net.gw_be >> 16) & 0xFF),
                    (unsigned)((g_net.gw_be >> 8) & 0xFF), (unsigned)(g_net.gw_be & 0xFF),
                    (unsigned)((g_net.dns_be >> 24) & 0xFF), (unsigned)((g_net.dns_be >> 16) & 0xFF),
                    (unsigned)((g_net.dns_be >> 8) & 0xFF), (unsigned)(g_net.dns_be & 0xFF),
                    (unsigned)((dns_be >> 24) & 0xFF), (unsigned)((dns_be >> 16) & 0xFF),
                    (unsigned)((dns_be >> 8) & 0xFF), (unsigned)(dns_be & 0xFF));
            }
            /* No 10.0.2.3 fallback: bridged/NAT would use wrong DNS */
            uint32_t ip_be;
            if (kernel_resolve_full(host, dns_be, &ip_be) != 0) return ret_err(EIO);
            /* User ABI: same as sockaddr_in.sin_addr / in_addr_t on x86_64 (LE memory = wire order). */
            {
                uint32_t ip_user = be32(ip_be);
                if (copy_to_user_safe(out_u, &ip_user, 4) != 0) return ret_err(EFAULT);
            }
            return 0;
        }
        default:
            /* Keep unknown syscalls silent to avoid console stalls under heavy userland probing. */
            (void)a4; (void)a5; (void)a6;
            return ret_err(ENOSYS);
    }
}

uint64_t syscall_do(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    uint64_t r = syscall_do_inner(num, a1, a2, a3, a4, a5, a6);
    //axon_wget_sc_log(num, r, a1, a2, a3);
    return r;
}

void isr_syscall(cpu_registers_t* regs) {
    if (!regs) return;
    /* Record user rip/rsp for int0x80 path so fork/vfork can find return site. */
    syscall_user_return_rip = regs->rip;
    syscall_user_rsp_saved = regs->rsp;
    if (syscall_user_return_rip == 0) {
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

    klogprintf("syscall: int0x80 handler registered; SYSCALL enabled (build=2026-03-31-wget-sc)\n");
}


