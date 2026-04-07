#include <thread.h>
#include <heap.h>
#include <klog.h>
#include <debug.h>
#include <string.h>
#include <pit.h>
#include <mmio.h>
#include <vga.h>
#include <context.h>
#include <devfs.h>
#include <gdt.h>
#include <mm.h>
#include <paging.h>
#include <exec.h>
#include <spinlock.h>
#include <smp.h>

#define MAX_THREADS 128
thread_t* threads[MAX_THREADS];
int thread_count = 0;
static thread_t *volatile current_cpu[SMP_MAX_CPUS];
static spinlock_t sched_lock = { 0 };
static uint32_t sched_fifo_counter;
static thread_t* current_user = NULL; // регистрируемый юзер-процесс
static thread_t* idle_thread_by_cpu[SMP_MAX_CPUS];
int init = 0;
static int init_user_tid = -1;

/* forward declaration */
thread_t* thread_get(int pid);
thread_t* thread_current(void);

static int thread_is_any_idle(const thread_t *t) {
        if (!t)
                return 0;
        for (int i = 0; i < SMP_MAX_CPUS; i++) {
                if (idle_thread_by_cpu[i] == t)
                        return 1;
        }
        return 0;
}

int thread_runnable_nonidle_count(void) {
        int n = 0;
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);
        for (int i = 0; i < thread_count; ++i) {
                thread_t *t = threads[i];
                if (!t || thread_is_any_idle(t))
                        continue;
                if (t->state == THREAD_READY || t->state == THREAD_RUNNING)
                        n++;
        }
        release_irqrestore(&sched_lock, irqf);
        return n;
}

thread_t *thread_idle_for_cpu(int cpu) {
        if (cpu < 0 || cpu >= SMP_MAX_CPUS)
                return NULL;
        return idle_thread_by_cpu[cpu];
}

static int thread_static_prio(const thread_t *t) {
        int p = 20 - t->nice;
        if (p < 1)
                p = 1;
        if (p > 40)
                p = 40;
        return p;
}

static inline void sched_set_current(thread_t *t) {
        current_cpu[smp_sched_cpu_id()] = t;
}

static void thread_note_ready_nolock(thread_t *t) {
        if (!t)
                return;
        if (t->state == THREAD_READY)
                return;
        t->sched_fifo_seq = ++sched_fifo_counter;
        t->state = THREAD_READY;
}

/* Called from context_switch_with_prev after outgoing context is fully saved (SMP-safe).
 * Unlocks only — IF must stay 0 until asm restores next thread (avoid IRQ during switch tail). */
void thread_schedule_prev_saved(thread_t *t) {
        if (t && t->state == THREAD_RUNNING)
                thread_note_ready_nolock(t);
        release(&sched_lock);
}

void thread_note_ready(thread_t *t) {
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);
        thread_note_ready_nolock(t);
        release_irqrestore(&sched_lock, irqf);
}

int thread_nice_set(int tid, int nice) {
        if (nice < -20)
                nice = -20;
        if (nice > 19)
                nice = 19;
        thread_t *t = (tid == 0) ? thread_current() : thread_get(tid);
        if (!t)
                return -1;
        t->nice = nice;
        return 0;
}

int thread_nice_get(int tid) {
        thread_t *t = (tid == 0) ? thread_current() : thread_get(tid);
        if (!t)
                return -1;
        return t->nice;
}

void thread_mark_init_user(thread_t* t) {
        if (!t) return;
        if (init_user_tid < 0) {
                init_user_tid = (int)t->tid;
                return;
        }
        thread_t *it = thread_get(init_user_tid);
        if (!it || it->state == THREAD_TERMINATED) {
                init_user_tid = (int)t->tid;
        }
}
static thread_t main_thread;

static int thread_context_valid(thread_t *t) {
        if (!t) return 0;
        uintptr_t tp = (uintptr_t)t;
        if (tp < 0x1000 || tp + sizeof(thread_t) >= (uintptr_t)MMIO_IDENTITY_LIMIT) return 0;
        uintptr_t rsp = (uintptr_t)t->context.rsp;
        if (rsp < 0x1000 || rsp >= (uintptr_t)MMIO_IDENTITY_LIMIT - 16) return 0;
        return 1;
}

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
        mm_init();
        memset(&main_thread, 0, sizeof(main_thread));
        main_thread.sched_target_cpu = -1;
        main_thread.state = THREAD_RUNNING;
        main_thread.tid = 0;
        main_thread.nice = 0;
        main_thread.sched_fifo_seq = 0;
        main_thread.context.rflags = 0x202; // ensure IF set for idle/main thread
        main_thread.sleep_until = 0;
        //for (int i=0;i<THREAD_MAX_FD;i++) main_thread.fds[i]=NULL;
        sched_set_current(&main_thread);
        threads[0] = &main_thread;
        thread_count = 1;
        strncpy(main_thread.name, "idle", sizeof(main_thread.name));
        /* default credentials: root */
        main_thread.uid = main_thread.euid = main_thread.suid = 0;
        main_thread.gid = main_thread.egid = main_thread.sgid = 0;
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
        main_thread.mm = mm_retain(mm_kernel());
        main_thread.bound_cpu = 0;

        for (int i = 0; i < SMP_MAX_CPUS; i++)
                idle_thread_by_cpu[i] = NULL;

        int ncpu = smp_cpu_count();
        if (ncpu > SMP_MAX_CPUS)
                ncpu = SMP_MAX_CPUS;
        for (int i = 0; i < ncpu; i++) {
                char iname[16];
                if (i < 10) {
                        memcpy(iname, "idle", 4);
                        iname[4] = (char)('0' + i);
                        iname[5] = '\0';
                } else {
                        memcpy(iname, "idle", 4);
                        iname[4] = (char)('0' + i / 10);
                        iname[5] = (char)('0' + i % 10);
                        iname[6] = '\0';
                }
                thread_t *it = thread_create(idle_task_entry, iname);
                if (it) {
                        it->nice = 19;
                        it->bound_cpu = i;
                        idle_thread_by_cpu[i] = it;
                }
        }
        /* After idlers exist; before this, pit_handler must not thread_schedule()
         * while threads[] / thread_count are being set up. */
        init = 1;
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
        if (!t) { kprintf("OOM thread: kmalloc(thread_t) failed\n"); return NULL; }
        memset(t, 0, sizeof(thread_t));
        t->bound_cpu = -1;
        t->sched_target_cpu = -1;
        void *stack_mem = kmalloc(KERNEL_STACK_SIZE + 16);
        if (!stack_mem) { kprintf("OOM thread: kmalloc(stack %u) failed\n", (unsigned)(KERNEL_STACK_SIZE+16)); kfree(t); return NULL; }
        t->kernel_stack = (uint64_t)stack_mem + KERNEL_STACK_SIZE;
        uint64_t* stack = (uint64_t*)t->kernel_stack;
        // Ensure 16-byte alignment for the stack pointer before ret
        uint64_t sp = ((uint64_t)&stack[-1]) & ~0xFULL;
        *((uint64_t*)sp) = (uint64_t)thread_trampoline; // ret пойдёт на trampoline
        t->context.rsp = sp;
        t->context.r12 = (uint64_t)entry; // entry передаётся через r12
        t->context.rflags = 0x202;
        t->state = st;
        t->nice = 0;
        t->sched_fifo_seq = 0;
        t->sleep_until = 0;
        strncpy(t->name, name, sizeof(t->name));
        /* default credentials (root) */
        t->uid = t->euid = t->suid = 0;
        t->gid = t->egid = t->sgid = 0;
        t->attached_tty = -1;
        t->vfork_parent_tid = -1;
        t->vfork_parent_saved_rsp = 0;
        t->vfork_parent_stack_backup = NULL;
        t->vfork_parent_stack_backup_len = 0;
        t->vfork_parent_mem_backup = NULL;
        t->vfork_parent_mem_backup_len = 0;
        t->vfork_parent_mem_backup_base = 0;
        t->vfork_parent_brk_saved = 0;
        t->user_brk_base = 0;
        t->user_brk_cur = 0;
        t->user_mmap_next = 0;
        t->user_mmap_hi = 0;
        t->mm_ptemplate = NULL;
        t->rseq_ptr = NULL;
        t->parent_tid = -1;
        t->saved_user_rip = 0;
        t->saved_user_rsp = 0;
        t->saved_user_rbx = 0;
        t->saved_user_rbp = 0;
        t->saved_user_r12 = 0;
        t->saved_user_r13 = 0;
        t->saved_user_r14 = 0;
        t->saved_user_r15 = 0;
        t->saved_user_rdi = 0;
        t->saved_user_rsi = 0;
        t->saved_user_rdx = 0;
        t->saved_user_r8 = 0;
        t->saved_user_r9 = 0;
        t->saved_user_r10 = 0;
        t->saved_user_r11 = 0;
        t->saved_user_rcx = 0;
        t->saved_syscall_frame = NULL;
        t->uaccess_begin = 0;
        t->uaccess_end = 0;
        t->uaccess_resume_rip = 0;
        t->uaccess_active = 0;
        t->pending_signals = 0;
        t->saved_sig_mask = 0;
        t->waiter_tid = -1;
        t->exit_status = 0;
        t->exec_trampoline_flag = 0;
        t->exec_trampoline_rip = 0;
        t->exec_trampoline_rsp = 0;
        t->exec_trampoline_rax = 0;
        {
                thread_t *tc = thread_current();
                if (tc && tc->mm) t->mm = mm_retain(tc->mm);
                else t->mm = mm_retain(mm_kernel());
        }
        strncpy(t->cwd, "/", sizeof(t->cwd));
        t->cwd[sizeof(t->cwd) - 1] = '\0';
        /* Use next free slot and tid so we never overwrite an existing thread. */
        {
                unsigned long irqf;
                acquire_irqsave(&sched_lock, &irqf);
                threads[thread_count] = t;
                t->tid = thread_count;
                thread_count++;
                if (st == THREAD_READY)
                        t->sched_fifo_seq = ++sched_fifo_counter;
                release_irqrestore(&sched_lock, irqf);
        }
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
        if (!t) { kprintf("OOM thread_register_user: kmalloc(thread_t) failed\n"); return NULL; }
        memset(t, 0, sizeof(thread_t));
        t->bound_cpu = 0;
        t->sched_target_cpu = -1;
        //for (int i=0;i<THREAD_MAX_FD;i++) t->fds[i]=NULL;
        t->ring = 3;
        t->user_rip = user_rip;
        t->user_stack = user_rsp;
        t->state = THREAD_RUNNING; // уже выполняется как текущее user‑задача
        t->nice = 0;
        t->sched_fifo_seq = 0;
        t->sleep_until = 0;
        t->tid = thread_count;
        strncpy(t->name, name ? name : "user", sizeof(t->name));
        /* initialize POSIX-ish job control ids */
        t->pgid = (int)t->tid;
        t->sid = (int)t->tid;
        /* inherit credentials, file descriptors and attached tty from current thread if available */
        thread_t *tc = thread_current();
        if (tc) {
                t->uid = tc->uid;
                t->euid = tc->euid;
                t->suid = tc->suid;
                t->gid = tc->gid;
                t->egid = tc->egid;
                t->sgid = tc->sgid;
                t->umask = tc->umask;
                /* copy fd table and bump refcount so close in parent doesn't free shared files (e.g. pipe) */
                for (int i = 0; i < THREAD_MAX_FD; i++) {
                    t->fds[i] = tc->fds[i];
                    if (t->fds[i]) {
                        if (t->fds[i]->refcount <= 0) t->fds[i]->refcount = 1;
                        else t->fds[i]->refcount++;
                    }
                }
                t->attached_tty = tc->attached_tty >= 0 ? tc->attached_tty : devfs_get_active();
                strncpy(t->cwd, tc->cwd[0] ? tc->cwd : "/", sizeof(t->cwd));
                t->cwd[sizeof(t->cwd) - 1] = '\0';
        } else {
                t->uid = t->euid = t->suid = 0;
                t->gid = t->egid = t->sgid = 0;
                t->attached_tty = devfs_get_active();
        }
        if (!t->cwd[0]) { strncpy(t->cwd, "/", sizeof(t->cwd)); t->cwd[sizeof(t->cwd)-1] = '\0'; }
        t->vfork_parent_tid = -1;
        t->vfork_parent_saved_rsp = 0;
        t->vfork_parent_stack_backup = NULL;
        t->vfork_parent_stack_backup_len = 0;
        t->vfork_parent_mem_backup = NULL;
        t->vfork_parent_mem_backup_len = 0;
        t->vfork_parent_mem_backup_base = 0;
        t->vfork_parent_brk_saved = 0;
        t->user_brk_base = 0;
        t->user_brk_cur = 0;
        t->user_mmap_next = 0;
        t->user_mmap_hi = 0;
        t->mm_ptemplate = NULL;
        t->rseq_ptr = NULL;
        t->parent_tid = -1;
        t->saved_user_rip = 0;
        t->saved_user_rsp = 0;
        t->saved_user_rbx = 0;
        t->saved_user_rbp = 0;
        t->saved_user_r12 = 0;
        t->saved_user_r13 = 0;
        t->saved_user_r14 = 0;
        t->saved_user_r15 = 0;
        t->saved_user_rdi = 0;
        t->saved_user_rsi = 0;
        t->saved_user_rdx = 0;
        t->saved_user_r8 = 0;
        t->saved_user_r9 = 0;
        t->saved_user_r10 = 0;
        t->saved_user_r11 = 0;
        t->saved_user_rcx = 0;
        t->saved_syscall_frame = NULL;
        t->uaccess_begin = 0;
        t->uaccess_end = 0;
        t->uaccess_resume_rip = 0;
        t->uaccess_active = 0;
        t->pending_signals = 0;
        t->saved_sig_mask = 0;
        t->waiter_tid = -1;
        t->exit_status = 0;
        t->exec_trampoline_flag = 0;
        t->exec_trampoline_rip = 0;
        t->exec_trampoline_rsp = 0;
        t->exec_trampoline_rax = 0;
        {
                thread_t *tc = thread_current();
                if (tc && tc->mm) t->mm = mm_retain(tc->mm);
                else t->mm = mm_retain(mm_kernel());
        }
        threads[thread_count++] = t;
        current_user = t;
        return t;
}

int thread_get_init_user_tid(void) {
        return init_user_tid;
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
	/* Init path never calls mark_broad_user_ranges; ensure full user mappings before user mode.
	   Clone3 children (user_stack_base != 0) already have mappings; re-marking causes #PF/triple fault. */
	if (self->user_stack_base == 0)
		exec_ensure_user_mappings();
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

thread_t* thread_current(void) {
        return current_cpu[smp_sched_cpu_id()];
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
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid && threads[i]->state != THREAD_BLOCKED) {
                        threads[i]->state = THREAD_BLOCKED;
                        threads[i]->sleep_until = 0; /* no timeout */
                        release_irqrestore(&sched_lock, irqf);
                        return;
                }
        }
        release_irqrestore(&sched_lock, irqf);
        klogprintf("<(0c)>thread_block: thread %d not found or already blocked\n", pid);
}

int thread_block_current_atomic(void) {
        unsigned long irqf;
        int blocked = 0;
        acquire_irqsave(&sched_lock, &irqf);
        thread_t *cur = thread_current();
        if (cur && cur->state == THREAD_RUNNING) {
                cur->state = THREAD_BLOCKED;
                cur->sleep_until = 0;
                blocked = 1;
        }
        release_irqrestore(&sched_lock, irqf);
        return blocked;
}

void thread_block_with_timeout(int pid, uint32_t timeout_ms) {
        extern volatile uint64_t timer_ticks;
        uint32_t now = (uint32_t)timer_ticks;
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid && threads[i]->state != THREAD_BLOCKED) {
                        threads[i]->state = THREAD_BLOCKED;
                        threads[i]->sleep_until = now + (timeout_ms ? timeout_ms : 0xFFFFFFFFu);
                        release_irqrestore(&sched_lock, irqf);
                        return;
                }
        }
        release_irqrestore(&sched_lock, irqf);
}

void thread_sleep(uint32_t ms) {
        if (ms == 0) return;

        /* Use common timer ticks so sleep works even when PIT is disabled (APIC timer). */
        thread_t *c = thread_current();
        if (!c)
                return;
        uint32_t now = (uint32_t)timer_ticks;
        c->sleep_until = (uint32_t)(now + ms);
        c->state = THREAD_SLEEPING;
        thread_yield();
}

void thread_schedule() {
        unsigned long irqf;
        acquire_irqsave(&sched_lock, &irqf);

        uint32_t now = (uint32_t)timer_ticks;
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->state == THREAD_SLEEPING) {
                        if (now >= threads[i]->sleep_until) {
                                thread_note_ready_nolock(threads[i]);
                        }
                } else if (threads[i] && threads[i]->state == THREAD_BLOCKED && threads[i]->sleep_until != 0) {
                        if (now >= threads[i]->sleep_until) {
                                threads[i]->sleep_until = 0;
                                thread_note_ready_nolock(threads[i]);
                        }
                }
        }

        thread_t *cur = thread_current();
        if (!cur) {
                int cid = smp_sched_cpu_id();
                thread_t *d = (cid == 0) ? &main_thread : idle_thread_by_cpu[cid];
                if (!d && cid != 0) {
                        release_irqrestore(&sched_lock, irqf);
                        for (;;)
                                asm volatile("cli; hlt" ::: "memory");
                }
                if (!d)
                        d = &main_thread;
                sched_set_current(d);
                cur = d;
                cur->sched_target_cpu = -1;
                cur->state = THREAD_RUNNING;
                release_irqrestore(&sched_lock, irqf);
                return;
        }

        /* Unix-ish: highest static priority (from nice) first; FIFO within same priority.
           Two passes: prefer any non-idle READY thread, then this CPU's idle only. */
        thread_t *pick = NULL;
        int best_pri = -1;
        uint32_t best_seq = 0;
        int my_cpu = smp_sched_cpu_id();
        thread_t *my_idle = NULL;
        if (my_cpu >= 0 && my_cpu < SMP_MAX_CPUS)
                my_idle = idle_thread_by_cpu[my_cpu];

        for (int pass = 0; pass < 2 && !pick; pass++) {
                for (int i = 0; i < thread_count; ++i) {
                        thread_t *t = threads[i];
                        if (!t || t->state != THREAD_READY)
                                continue;
                        if (t->bound_cpu >= 0 && t->bound_cpu != my_cpu)
                                continue;
                        if (pass == 0 && thread_is_any_idle(t))
                                continue;
                        if (pass == 1 && thread_is_any_idle(t) && t != my_idle)
                                continue;
                        if (!thread_context_valid(t)) {
                                t->state = THREAD_TERMINATED;
                                continue;
                        }
                        int pri = thread_static_prio(t);
                        if (pick == NULL || pri > best_pri ||
                            (pri == best_pri && t->sched_fifo_seq < best_seq)) {
                                pick = t;
                                best_pri = pri;
                                best_seq = t->sched_fifo_seq;
                        }
                }
        }

        if (pick == cur) {
                release_irqrestore(&sched_lock, irqf);
                return;
        }

        if (pick) {
                thread_t *prev = cur;
                if (!thread_context_valid(prev)) {
                        prev = &main_thread;
                        sched_set_current(&main_thread);
                        cur = &main_thread;
                }
                sched_set_current(pick);
                cur = pick;
                cur->sched_target_cpu = -1;
                cur->state = THREAD_RUNNING;
                if (cur->kernel_stack) {
                        tss_set_rsp0(cur->kernel_stack);
                }
                if (cur->ring == 3)
                        thread_set_current_user(cur);
                else
                        thread_set_current_user(NULL);
                if (cur->ring == 3) {
                        set_user_fs_base(cur->user_fs_base);
                } else {
                        set_user_fs_base(0);
                }
                mm_switch(cur->mm);
                if (!thread_context_valid(cur)) {
                        cur->state = THREAD_TERMINATED;
                        sched_set_current(&main_thread);
                        cur = &main_thread;
                        cur->sched_target_cpu = -1;
                        cur->state = THREAD_RUNNING;
                        release_irqrestore(&sched_lock, irqf);
                        return;
                }
                context_switch_with_prev(&prev->context, &cur->context, prev);
                restore_irqflags(irqf);
                return;
        }

        if (cur->state == THREAD_RUNNING) {
                release_irqrestore(&sched_lock, irqf);
                return;
        }
        if (my_idle && cur != my_idle && thread_context_valid(my_idle)) {
                thread_t *prev = cur;
                if (!thread_context_valid(prev))
                        prev = &main_thread;
                sched_set_current(my_idle);
                cur = my_idle;
                cur->sched_target_cpu = -1;
                cur->state = THREAD_RUNNING;
                mm_switch(cur->mm);
                context_switch_with_prev(&prev->context, &cur->context, prev);
                restore_irqflags(irqf);
                return;
        }
        sched_set_current(&main_thread);
        cur = &main_thread;
        cur->sched_target_cpu = -1;
        cur->state = THREAD_RUNNING;
        mm_switch(cur->mm);
        release_irqrestore(&sched_lock, irqf);
}

void thread_unblock(int pid) {
        for (int i = 0; i < thread_count; ++i) {
                if (threads[i] && threads[i]->tid == pid && threads[i]->state == THREAD_BLOCKED) {
                        threads[i]->sleep_until = 0;
                        thread_note_ready(threads[i]);
                        return;
                }
        }
}

/* SIGINT (Ctrl+C): terminate all threads in the foreground process group. */
void thread_send_sigint_to_pgrp(int pgrp) {
        if (pgrp < 0) return;
        for (int i = 0; i < thread_count; ++i) {
                thread_t *t = threads[i];
                if (!t) continue;
                if (t->pgid != pgrp) continue;
                if (t->state != THREAD_TERMINATED) {
                        /* Mark pending SIGINT; let thread terminate via regular syscall path.
                           Directly forcing THREAD_TERMINATED breaks vfork/exec parent restore. */
                        t->pending_signals |= (1ULL << (2 - 1)); /* SIGINT */
                        if (t->state == THREAD_BLOCKED || t->state == THREAD_SLEEPING) {
                                t->sleep_until = 0;
                                thread_note_ready(t);
                        }
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