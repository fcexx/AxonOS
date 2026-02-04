#ifndef THREAD_H
#define THREAD_H
#include <stdint.h>
#include <context.h>
#include <fs.h>

typedef enum {
        THREAD_READY,
        THREAD_RUNNING,
        THREAD_BLOCKED,
        THREAD_TERMINATED,
        THREAD_SLEEPING
} thread_state_t;

#define THREAD_MAX_FD 16

typedef struct thread {
        context_t context;
        uint64_t kernel_stack;         // kernel mode stack
        uint64_t user_stack;           // user mode stack
        uint64_t user_rip;             // user mode rip
        uint64_t user_fs_base;         // TLS base for userspace
        uint8_t ring;                  // user mode ring
        thread_state_t state;
        struct thread* next;
        uint64_t tid;
        char name[32];                 // thread name (urmomissofaturmomissofaturmomiss)

        /* POSIX-ish job control identifiers */
        int pgid;                      // process group id
        int sid;                       // session id
        uint32_t sleep_until;          // sleep until (in timer ticks)
        uint64_t clear_child_tid;      // clear child tid
        struct fs_file* fds[THREAD_MAX_FD];

        /* current working directory for userland syscalls (POSIX-like).
           For kernel threads this is ignored; for user processes it's used to resolve relative paths. */
        char cwd[256];
        
        /* POSIX credentials */
        uid_t euid;
        gid_t egid;

        /* file mode creation mask (umask) for mkdir/open */
        unsigned int umask;

        /* attached tty index or -1 */
        int attached_tty;
        
        /* vfork parent PID: if >=0 then this thread was created by vfork and parent is blocked;
           on execve/exit child must unblock parent. */
        int vfork_parent_tid;

        /* vfork parent stack snapshot (to restore parent's frames on child exit).
           In our shared-address-space model, the vfork child can temporarily run on the
           parent's userspace stack; we keep a copy of the active region starting at the
           parent's saved RSP, and restore it right before waking the parent. */
        uint64_t vfork_parent_saved_rsp;
        void *vfork_parent_stack_backup;
        uint64_t vfork_parent_stack_backup_len;
        void *vfork_parent_mem_backup;
        uint64_t vfork_parent_mem_backup_len;
        uint64_t vfork_parent_mem_backup_base;
        uint64_t vfork_parent_brk_saved;

        /* per-thread brk state (heap) */
        uintptr_t user_brk_base;
        uintptr_t user_brk_cur;
        uintptr_t user_mmap_next;

        /* exec trampoline support: when set, kernel will patch the saved syscall return
           frame so that on syscall return the thread resumes at exec_trampoline_rip/rsp
           with RAX=exec_trampoline_rax. Used to implement vfork-by-reusing-current-thread. */
        int exec_trampoline_flag;
        uint64_t exec_trampoline_rip;
        uint64_t exec_trampoline_rsp;
        uint64_t exec_trampoline_rax;

        /* pointer to rseq area in userspace (for minimal rseq support) */
        void *rseq_ptr;

        /* parent thread id (for wait/waitpid) */
        int parent_tid;
        
        /* saved syscall return site for current syscall (per-thread) */
        uint64_t saved_user_rip;
        uint64_t saved_user_rsp;

        /* saved user register snapshot captured at syscall entry (per-thread).
           Needed for vfork trampoline without relying on global, non-reentrant state. */
        uint64_t saved_user_rbx;
        uint64_t saved_user_rbp;
        uint64_t saved_user_r12;
        uint64_t saved_user_r13;
        uint64_t saved_user_r14;
        uint64_t saved_user_r15;
        uint64_t saved_user_rdi;
        uint64_t saved_user_rsi;
        uint64_t saved_user_rdx;
        uint64_t saved_user_r8;
        uint64_t saved_user_r9;
        uint64_t saved_user_r10;
        uint64_t saved_user_r11;
        uint64_t saved_user_rcx;

        /* pointer to saved syscall frame on kernel stack (rsp at entry) */
        uint64_t *saved_syscall_frame;

        /* pending signal bitmask (1-based signal numbers, bit0 unused) */
        uint64_t pending_signals;

        /* if non-negative, tid of thread waiting for this child (wait/waitpid) */
        int waiter_tid;
        
        /* exit status encoded like wait(2) returns (status word) */
        int exit_status;
} thread_t;

extern int init;

void thread_init();
thread_t* thread_create(void (*entry)(void), const char* name);
/* Create a thread but keep it BLOCKED initially (not runnable) so callers can
   safely initialize fields before scheduling can run it. */
thread_t* thread_create_blocked(void (*entry)(void), const char* name);
void thread_yield();
void thread_schedule();
thread_t* thread_current();
void thread_stop(int pid);
thread_t* thread_get(int pid);
int thread_get_pid(const char* name);
void thread_block(int pid);
/* Block until unblock OR timeout_ms expires. block_until stored in sleep_until. */
void thread_block_with_timeout(int pid, uint32_t timeout_ms);
void thread_unblock(int pid);
/* Send SIGINT to foreground process group (Ctrl+C → terminate blocking program) */
void thread_send_sigint_to_pgrp(int pgrp);
int thread_get_state(int pid);
int thread_get_count();
void thread_sleep(uint32_t ms);

// access thread by index (0..thread_get_count()-1)
thread_t* thread_get_by_index(int idx);
int thread_get_init_user_tid(void);
void thread_mark_init_user(thread_t* t);

// register user thread (process) for display in list
thread_t* thread_register_user(uint64_t user_rip, uint64_t user_rsp, const char* name);

// access to current user thread
thread_t* thread_get_current_user();
void thread_set_current_user(thread_t* t);
// find a user thread attached to given tty (or NULL)
thread_t* thread_find_by_tty(int tty);
// find any child of given parent tid, or NULL
thread_t* thread_find_child_of(int parent_tid);

// per-thread fd helpers
int thread_fd_alloc(struct fs_file *file); /* returns fd or -1 */
int thread_fd_close(int fd);
int thread_fd_dup(int oldfd);
int thread_fd_dup2(int oldfd, int newfd);
int thread_fd_isatty(int fd);

#endif // THREAD_H 