#include <thread.h>
#include <heap.h>
#include <debug.h>
#include <string.h>
#include <pit.h>
#include <mmio.h>
#include <vga.h>
#include <context.h>
#include <debug.h>
#include <devfs.h>
#include <gdt.h>

#define MAX_THREADS 32
thread_t* threads[MAX_THREADS];
int thread_count = 0;
static thread_t* current = NULL;
static thread_t* current_user = NULL; // регистрируемый юзер-процесс
static thread_t* idle_thread = NULL;  /* always-runnable idle task */
static int idle_tid = -1;
int init = 0;
static thread_t main_thread;

/* Kernel stack size per thread.
   8KiB was too small for our very large syscall handler (`syscall_do`) and led to
   kernel stack overflows, corrupting thread structs / saved user registers and
   manifesting as user-mode #GP with non-canonical RBP/RDI after heavy syscalls (e.g. busybox ls). */
#define KERNEL_STACK_SIZE (64 * 1024)

/* A real idle task: used when all other threads are BLOCKED/SLEEPING/TERMINATED.
   It must be a normal schedulable thread with its own saved context, otherwise
   the scheduler can end up "returning" into a terminated thread (e.g. after SYS_exit_group)
   when there are no READY threads. */
static void idle_task_entry(void) {
        for (;;) {
                /* Drive scheduling from a safe thread context.
                   IRQ handlers must not context_switch(), so when an interrupt
                   unblocks a thread (e.g. keyboard input waking a tty reader),
                   we rely on the idle task to notice READY threads and switch. */
                thread_schedule();
                asm volatile("sti; hlt" ::: "memory");
        }
}

void thread_init() {
        memset(&main_thread, 0, sizeof(main_thread));
        main_thread.state = THREAD_RUNNING;
        main_thread.tid = 0;
        main_thread.context.rflags = 0x202; // ensure IF set for idle/main thread
        main_thread.sleep_until = 0;
        //for (int i=0;i<THREAD_MAX_FD;i++) main_thread.fds[i]=NULL;
        current = &main_thread;
        threads[0] = &main_thread;
        thread_count = 1;
        strncpy(main_thread.name, "idle", sizeof(main_thread.name));
        /* default credentials: root */
        main_thread.euid = 0;
        main_thread.egid = 0;
        main_thread.attached_tty = devfs_get_active();
        strncpy(main_thread.cwd, "/", sizeof(main_thread.cwd));
        main_thread.cwd[sizeof(main_thread.cwd) - 1] = '\0';
        main_thread.vfork_parent_tid = -1;
        main_thread.rseq_ptr = NULL;
        main_thread.parent_tid = -1;
        main_thread.saved_user_rip = 0;
        main_thread.saved_user_rsp = 0;
        main_thread.waiter_tid = -1;
        main_thread.exit_status = 0;
        main_thread.exec_trampoline_flag = 0;
        main_thread.exec_trampoline_rip = 0;
        main_thread.exec_trampoline_rsp = 0;
        main_thread.exec_trampoline_rax = 0;
        init = 1;

        /* Create an always-READY idle task (tid != 0) so the scheduler always has
           a safe thread to switch to when all other threads are blocked. */
        idle_thread = thread_create(idle_task_entry, "idle_task");
        if (idle_thread) {
                idle_tid = idle_thread->tid;
        } else {
                idle_tid = -1;
        }
}

// для старта потока
static void thread_trampoline(void) {
        void (*entry)(void);
        __asm__ __volatile__("movq %%r12, %0" : "=r"(entry)); // entry = r12
        // Log RFLAGS at thread start to ensure IF bit is set in thread context
        unsigned long long _rflags = 0;
        asm volatile("pushfq; pop %%rax" : "=a"(_rflags));
        thread_t* _self = thread_current();
        int _tid = _self ? _self->tid : -1;
        //qemu_debug_printf("thread_trampoline: tid=%d start RFLAGS=0x%x\n", _tid, (unsigned int)_rflags);
        entry();
        
        // Поток завершился - помечаем как завершенный
        thread_t* self = thread_current();
        if (self) {
                self->state = THREAD_TERMINATED;
        }
        
        // Переключаемся на другой поток
        thread_yield();
        
        // На всякий случай - если что-то пошло не так
        for (;;) {
                asm volatile("hlt");
        }
}

static thread_t* thread_create_with_state(void (*entry)(void), const char* name, thread_state_t st) {
        if (thread_count >= MAX_THREADS) return NULL;
        thread_t* t = (thread_t*)kmalloc(sizeof(thread_t));
        if (!t) return NULL;
        memset(t, 0, sizeof(thread_t));
        t->kernel_stack = (uint64_t)kmalloc(KERNEL_STACK_SIZE + 16) + KERNEL_STACK_SIZE;
        uint64_t* stack = (uint64_t*)t->kernel_stack;
        // Ensure 16-byte alignment for the stack pointer before ret
        uint64_t sp = ((uint64_t)&stack[-1]) & ~0xFULL;
        *((uint64_t*)sp) = (uint64_t)thread_trampoline; // ret пойдёт на trampoline
        t->context.rsp = sp;
        t->context.r12 = (uint64_t)entry; // entry передаётся через r12
        t->context.rflags = 0x202;
        t->state = st;
        t->sleep_until = 0;
        t->tid = thread_count;
        strncpy(t->name, name, sizeof(t->name));
        /* default credentials (root) */
        t->euid = 0;
        t->egid = 0;
        t->attached_tty = -1;
        t->vfork_parent_tid = -1;
        t->rseq_ptr = NULL;
        t->parent_tid = -1;
        t->saved_user_rip = 0;
        t->saved_user_rsp = 0;
        t->waiter_tid = -1;
        t->exit_status = 0;
        t->exec_trampoline_flag = 0;
        t->exec_trampoline_rip = 0;
        t->exec_trampoline_rsp = 0;
        t->exec_trampoline_rax = 0;
        strncpy(t->cwd, "/", sizeof(t->cwd));
        t->cwd[sizeof(t->cwd) - 1] = '\0';
        threads[thread_count++] = t;
        return t;
}

thread_t* thread_create(void (*entry)(void), const char* name) {
        return thread_create_with_state(entry, name, THREAD_READY);
}

thread_t* thread_create_blocked(void (*entry)(void), const char* name) {
        return thread_create_with_state(entry, name, THREAD_BLOCKED);
}

thread_t* thread_register_user(uint64_t user_rip, uint64_t user_rsp, const char* name){
        if (thread_count >= MAX_THREADS) return NULL;
        // Sanity checks: reject clearly invalid user contexts (entry==0 or tiny stack)
        if (user_rip == 0 || user_rsp < 0x1000) {
                klogprintf("fatal: refusing to register user thread with invalid rip=0x%llx rsp=0x%llx\n",
                               (unsigned long long)user_rip, (unsigned long long)user_rsp);
                return NULL;
        }
        thread_t* t = (thread_t*)kmalloc(sizeof(thread_t));
        if (!t) return NULL;
        memset(t, 0, sizeof(thread_t));
        //for (int i=0;i<THREAD_MAX_FD;i++) t->fds[i]=NULL;
        t->ring = 3;
        t->user_rip = user_rip;
        t->user_stack = user_rsp;
        t->state = THREAD_RUNNING; // уже выполняется как текущее user‑задача
        t->sleep_until = 0;
        t->tid = thread_count;
        strncpy(t->name, name ? name : "user", sizeof(t->name));
        /* initialize POSIX-ish job control ids */
        t->pgid = (int)t->tid;
        t->sid = (int)t->tid;
        /* inherit credentials, file descriptors and attached tty from current thread if available */
        if (current) {
                t->euid = current->euid;
                t->egid = current->egid;
                /* copy fd table */
                for (int i = 0; i < THREAD_MAX_FD; i++) t->fds[i] = current->fds[i];
                t->attached_tty = current->attached_tty >= 0 ? current->attached_tty : devfs_get_active();
                strncpy(t->cwd, current->cwd[0] ? current->cwd : "/", sizeof(t->cwd));
                t->cwd[sizeof(t->cwd) - 1] = '\0';
        } else { t->euid = 0; t->egid = 0; t->attached_tty = devfs_get_active(); }
        if (!t->cwd[0]) { strncpy(t->cwd, "/", sizeof(t->cwd)); t->cwd[sizeof(t->cwd)-1] = '\0'; }
        t->vfork_parent_tid = -1;
        t->rseq_ptr = NULL;
        t->parent_tid = -1;
        t->waiter_tid = -1;
        t->exit_status = 0;
        t->exec_trampoline_flag = 0;
        t->exec_trampoline_rip = 0;
        t->exec_trampoline_rsp = 0;
        t->exec_trampoline_rax = 0;
        threads[thread_count++] = t;
        current_user = t;
        return t;
}

// Entry for kernel-created user threads: set up per-thread kernel stack as TSS, mark as current_user
// then enter user mode at saved rip/rsp. This function is used as the entry point passed to thread_create().
void user_thread_entry(void) {
	thread_t *self = thread_current();
	if (!self) {
		for (;;) asm volatile("hlt");
	}
	// mark as user thread
	self->ring = 3;
	thread_set_current_user(self);
	// set TSS RSP0 to this thread's kernel stack so syscalls use its stack
	tss_set_rsp0(self->kernel_stack);
	// restore user FS base (TLS) so user code can access fs-relative data like stack-protector
	{
		uint64_t fsbase = self->user_fs_base;
		uint32_t msr = 0xC0000100u; /* MSR_FS_BASE */
		/* Read current MSR_FS_BASE for debug */
		{
			uint32_t _lo = 0, _hi = 0;
			asm volatile("rdmsr" : "=a"(_lo), "=d"(_hi) : "c"(msr));
			uint64_t cur = ((uint64_t)_hi << 32) | _lo;
			qemu_debug_printf("user_thread_entry: rdmsr before set MSR_FS_BASE=0x%llx target=0x%llx tid=%d\n",
			                  (unsigned long long)cur, (unsigned long long)fsbase, (int)self->tid);
		}
		/* Write desired FS base then verify by reading back */
		{
			uint32_t lo = (uint32_t)(fsbase & 0xFFFFFFFFu);
			uint32_t hi = (uint32_t)(fsbase >> 32);
			asm volatile("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
			uint32_t _lo = 0, _hi = 0;
			asm volatile("rdmsr" : "=a"(_lo), "=d"(_hi) : "c"(msr));
			uint64_t after = ((uint64_t)_hi << 32) | _lo;
			qemu_debug_printf("user_thread_entry: rdmsr after set MSR_FS_BASE=0x%llx tid=%d\n",
			                  (unsigned long long)after, (int)self->tid);
		}
	}
	// ensure return value from fork is 0 in child: clear RAX
	asm volatile("xor %%rax, %%rax" ::: "rax");
	// Debug: report the user entry we're about to jump to
	qemu_debug_printf("user_thread_entry: entering user mode rip=0x%llx rsp=0x%llx tid=%d\n",
			  (unsigned long long)self->user_rip,
			  (unsigned long long)self->user_stack,
			  (int)self->tid);
	/* Diagnostic: dump first bytes at user RIP before entering user mode */
	if ((uintptr_t)self->user_rip + 32 < (uintptr_t)MMIO_IDENTITY_LIMIT) {
		qemu_debug_printf("user_thread_entry: bytes at user RIP 0x%llx:\n", (unsigned long long)self->user_rip);
		for (int i = 0; i < 32; i++) qemu_debug_printf("%02x", *((unsigned char*)(uintptr_t)(self->user_rip + i)));
		qemu_debug_printf("\n");
	} else {
		qemu_debug_printf("user_thread_entry: user RIP outside identity map, skipping bytes dump\n");
	}
	// Jump to user mode
	enter_user_mode(self->user_rip, self->user_stack);
	// Should not return
	for (;;) asm volatile("hlt");
}

int thread_fd_alloc(struct fs_file *file) {
    if (!file) return -1;
    /* Prefer the registered user thread for syscall context; fall back to current kernel thread. */
    thread_t *cur = thread_get_current_user();
    if (!cur) cur = thread_current();
    if (!cur) return -1;
    for (int i = 0; i < THREAD_MAX_FD; i++) {
        if (cur->fds[i] == NULL) {
            cur->fds[i] = file;
            /* take ownership - increase refcount */
            if (file->refcount <= 0) file->refcount = 1;
            else file->refcount++;
            return i;
        }
    }
    return -1;
}

int thread_fd_close(int fd) {
    thread_t *cur = thread_get_current_user();
    if (!cur) cur = thread_current();
    if (!cur || fd < 0 || fd >= THREAD_MAX_FD) return -1;
    struct fs_file *f = cur->fds[fd];
    if (!f) return -1;
    cur->fds[fd] = NULL;
    fs_file_free(f);
    return 0;
}

int thread_fd_dup(int oldfd) {
    thread_t *cur = thread_get_current_user();
    if (!cur) cur = thread_current();
    if (!cur || oldfd < 0 || oldfd >= THREAD_MAX_FD) return -1;
    struct fs_file *f = cur->fds[oldfd];
    if (!f) return -1;
    for (int i = 0; i < THREAD_MAX_FD; i++) {
        if (cur->fds[i] == NULL) {
            cur->fds[i] = f;
            if (f->refcount <= 0) f->refcount = 1;
            else f->refcount++;
            return i;
        }
    }
    return -1;
}

int thread_fd_dup2(int oldfd, int newfd) {
    thread_t *cur = thread_get_current_user();
    if (!cur) cur = thread_current();
    if (!cur || oldfd < 0 || oldfd >= THREAD_MAX_FD || newfd < 0 || newfd >= THREAD_MAX_FD) return -1;
    if (oldfd == newfd) return newfd;
    struct fs_file *f = cur->fds[oldfd];
    if (!f) return -1;
    /* close newfd if open */
    if (cur->fds[newfd]) {
        fs_file_free(cur->fds[newfd]);
        cur->fds[newfd] = NULL;
    }
    cur->fds[newfd] = f;
    if (f->refcount <= 0) f->refcount = 1;
    else f->refcount++;
    return newfd;
}

int thread_fd_isatty(int fd) {
    thread_t *cur = thread_get_current_user();
    if (!cur) cur = thread_current();
    if (!cur || fd < 0 || fd >= THREAD_MAX_FD) return 0;
    struct fs_file *f = cur->fds[fd];
    if (!f) return 0;
    return devfs_is_tty_file(f);
}

thread_t* thread_current() {
        return current;
}

void thread_yield() {
        thread_schedule();
}

void thread_stop(int pid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid && threads[i]->state != THREAD_TERMINATED) {
                        kprintf("thread_stop: stopping tid=%d name=%s\n", pid, threads[i]->name);
                        threads[i]->state = THREAD_TERMINATED;
                        return;
                }
        }
        klogprintf("thread_stop: thread %d not found or already terminated\n", pid);
}

void thread_block(int pid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid && threads[i]->state != THREAD_BLOCKED) {
                        threads[i]->state = THREAD_BLOCKED;
                        return;
                }
        }
        klogprintf("<(0c)>thread_block: thread %d not found or already blocked\n", pid);
}

void thread_sleep(uint32_t ms) {
        if (ms == 0) return;

        /* Use common timer ticks so sleep works even when PIT is disabled (APIC timer). */
        uint32_t now = (uint32_t)timer_ticks;
        current->sleep_until = (uint32_t)(now + ms);
        current->state = THREAD_SLEEPING;
        thread_yield();
}

void thread_schedule() {
        // Сначала проверяем спящие потоки
        uint32_t now = (uint32_t)timer_ticks;
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->state == THREAD_SLEEPING) {
                        if (now >= threads[i]->sleep_until) {
                                threads[i]->state = THREAD_READY;
                        }
                }
        }
        
        if (!current) {
                current = &main_thread;
                current->state = THREAD_RUNNING;
                return;
        }
        int next = (current->tid + 1) % thread_count;

        /* Two-pass selection:
           1) Prefer any READY non-idle thread
           2) If none, allow the idle thread */
        thread_t *pick = NULL;
        for (int pass = 0; pass < 2 && !pick; pass++) {
                for (int i = 0; i < thread_count; ++i) {
                        int idx = (next + i) % thread_count;
                        thread_t *t = threads[idx];
                        if (!t) continue;
                        if (t->state != THREAD_READY) continue;
                        if (t->state == THREAD_TERMINATED) continue;
                        if (pass == 0 && idle_tid >= 0 && t->tid == idle_tid) continue; /* skip idle on pass0 */
                        pick = t;
                        break;
                }
        }

        if (pick) {
                        thread_t* prev = current;
                        current = pick;
                        current->state = THREAD_RUNNING;
                        /* Keep TSS.RSP0 / syscall kernel stack in sync with the actually scheduled thread.
                           Without this, a user thread can take a SYSCALL/IRQ on the previous thread's
                           kernel stack, corrupting syscall frames and eventually userspace context
                           (observed as #GP with non-canonical RBP/RDI after busybox). */
                        if (current->kernel_stack) {
                                tss_set_rsp0(current->kernel_stack);
                        }
                        /* Keep "current user thread" in sync with the actually running thread.
                           Some code used current_user as a proxy for "current process" and
                           desync here causes syscalls to be dispatched on the wrong thread. */
                        if (current->ring == 3) thread_set_current_user(current);
                        else thread_set_current_user(NULL);
                        /* Restore per-thread userspace FS base (TLS) before switching.
                           Without this, vfork/exec will leave the parent running with the
                           child's FS base, which breaks libc stack protector and can lead
                           to the shell unexpectedly exiting after child termination. */
                        if (current->ring == 3) {
                                set_user_fs_base(current->user_fs_base);
                        } else {
                                set_user_fs_base(0);
                        }
                        /* Only a RUNNING thread becomes READY when we switch away.
                           If it was already BLOCKED/SLEEPING/TERMINATED, preserve that state. */
                        if (prev->state == THREAD_RUNNING) {
                                prev->state = THREAD_READY;
                        }
                        //qemu_debug_printf("thread_schedule: switching from tid=%d to tid=%d\n", prev->tid, current->tid);
                        //qemu_debug_printf("thread_schedule: prev.ctx.rflags=0x%x new.ctx.rflags=0x%x\n", (unsigned int)prev->context.rflags, (unsigned int)current->context.rflags);
                        context_switch(&prev->context, &current->context);
                        return;
        }
        /* No READY threads found.
           Previous behavior forced execution of main_thread even if it was BLOCKED,
           which breaks wait semantics (e.g., osh waiting for user program) and causes
           two shells to run concurrently.
           
           If the current thread is still RUNNING, keep running it. Otherwise fall back
           to main_thread as an idle loop. */
        if (current->state == THREAD_RUNNING) {
                return;
        }
        /* As a last resort, if idle thread exists and is not current, switch to it even
           if it isn't marked READY (shouldn't happen, but safer than returning into a dead thread). */
        if (idle_thread && current != idle_thread) {
                thread_t *prev = current;
                current = idle_thread;
                current->state = THREAD_RUNNING;
                if (prev->state == THREAD_RUNNING) prev->state = THREAD_READY;
                context_switch(&prev->context, &current->context);
                return;
        }
        /* Fallback to tid0 context (best-effort). */
        current = &main_thread;
        current->state = THREAD_RUNNING;
}

void thread_unblock(int pid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid && threads[i]->state == THREAD_BLOCKED) {
                        threads[i]->state = THREAD_READY;
                        return;
                }
        }
}

// get thread info by pid
thread_t* thread_get(int pid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid) {
                        return threads[i];
                }
        }
        return NULL;
}

thread_t* thread_find_child_of(int parent_tid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->parent_tid == parent_tid) return threads[i];
        }
        return NULL;
}

thread_t* thread_get_by_index(int idx) {
    if (idx < 0 || idx >= thread_count) return NULL;
    return threads[idx];
}

int thread_get_pid(const char* name) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && strcmp(threads[i]->name, name) == 0) {
                        return threads[i]->tid;
                }
        }
        return -1;
}

int thread_get_state(int pid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid) {
                        return threads[i]->state;
                }
        }
        return -1;
}

int thread_get_count() {
        return thread_count;
}

thread_t* thread_get_current_user(){ return current_user; }
void thread_set_current_user(thread_t* t){ current_user = t; }
thread_t* thread_find_by_tty(int tty) {
    for (int i = 0; i < thread_count; ++i) {
        if (threads[i] && threads[i]->attached_tty == tty) return threads[i];
    }
    return NULL;
}