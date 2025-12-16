#include <axonos.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <thread.h>
#include <fs.h>
#include <mmio.h>
#include <heap.h>
#include <syscall.h>

extern void kprintf(const char *fmt, ...);

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

void isr_syscall(cpu_registers_t* regs) {
    if (!regs) return;
    uint64_t num = regs->rax;
    uint64_t a1 = regs->rdi;
    uint64_t a2 = regs->rsi;
    uint64_t a3 = regs->rdx;
    uint64_t a4 = regs->r10; /* saved in regs struct */
    uint64_t a5 = regs->r9;
    uint64_t a6 = regs->r8;

    thread_t *cur = thread_current();
    if (!cur) { regs->rax = (uint64_t)-1; return; }

    kprintf("syscall: num=%d a1=0x%llx a2=0x%llx a3=0x%llx a4=0x%llx a5=0x%llx a6=0x%llx\n",
        num, (unsigned long long)a1, (unsigned long long)a2, (unsigned long long)a3, (unsigned long long)a4, (unsigned long long)a5, (unsigned long long)a6);

    switch (num) {
        case SYS_write: {
            int fd = (int)a1;
            const void *bufp = (const void*)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) { regs->rax = (uint64_t)-1; break; }
            struct fs_file *f = cur->fds[fd];
            if (!f) { regs->rax = (uint64_t)-1; break; }
            /* copy up to 4096 bytes at once */
            size_t copied = 0;
            void *tmp = copy_from_user_safe(bufp, cnt, 4096, &copied);
            if (!tmp) { regs->rax = (uint64_t)-1; break; }
            ssize_t wr = fs_write(f, tmp, copied, f->pos);
            if (wr > 0) f->pos += (size_t)wr;
            kfree(tmp);
            regs->rax = (uint64_t)(wr >= 0 ? wr : -1);
            break;
        }
        case SYS_read: {
            int fd = (int)a1;
            void *bufp = (void*)(uintptr_t)a2;
            size_t cnt = (size_t)a3;
            if (fd < 0 || fd >= THREAD_MAX_FD) { regs->rax = (uint64_t)-1; break; }
            struct fs_file *f = cur->fds[fd];
            if (!f) { regs->rax = (uint64_t)-1; break; }
            /* temporary kernel buffer */
            size_t to_read = cnt < 4096 ? cnt : 4096;
            void *tmp = kmalloc(to_read);
            if (!tmp) { regs->rax = (uint64_t)-1; break; }
            ssize_t rr = fs_read(f, tmp, to_read, f->pos);
            if (rr > 0) {
                /* copy back to user only if within identity region */
                if ((uintptr_t)bufp + (size_t)rr <= (uintptr_t)MMIO_IDENTITY_LIMIT) {
                    memcpy(bufp, tmp, (size_t)rr);
                    f->pos += (size_t)rr;
                    regs->rax = (uint64_t)rr;
                } else {
                    regs->rax = (uint64_t)-1;
                }
            } else {
                regs->rax = (uint64_t)(rr >= 0 ? rr : -1);
            }
            kfree(tmp);
            break;
        }
        case SYS_open: {
            const char *path = (const char*)(uintptr_t)a1;
            int flags = (int)a2;
            (void)flags;
            /* only support simple path strings within identity region */
            if (!path || (uintptr_t)path >= (uintptr_t)MMIO_IDENTITY_LIMIT) { regs->rax = (uint64_t)-1; break; }
            struct fs_file *f = fs_open(path);
            if (!f) { regs->rax = (uint64_t)-1; break; }
            int fd = thread_fd_alloc(f);
            if (fd < 0) fs_file_free(f);
            regs->rax = (uint64_t)fd;
            break;
        }
        case SYS_close: {
            int fd = (int)a1;
            if (fd < 0 || fd >= THREAD_MAX_FD) { regs->rax = (uint64_t)-1; break; }
            int r = thread_fd_close(fd);
            regs->rax = (uint64_t)(r == 0 ? 0 : -1);
            break;
        }
        case SYS_exit: {
            int status = (int)a1;
            (void)status;
            /* Mark thread terminated; actual scheduling away will happen on next tick.
               We avoid forcing a context switch inside ISR to keep stack integrity. */
            thread_stop((int)cur->tid);
            regs->rax = 0;
            break;
        }
        default:
            regs->rax = (uint64_t)-1;
            break;
    }
}

void syscall_init(void) {
    /* register handler on vector 0x80 */
    idt_set_handler(0x80, isr_syscall);
    kprintf("syscall: int0x80 handler registered\n");
}


