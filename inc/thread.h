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
        /* attached tty index or -1 */
        int attached_tty;
        /* vfork parent PID: if >=0 then this thread was created by vfork and parent is blocked;
           on execve/exit child must unblock parent. */
        int vfork_parent_tid;
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
        /* if non-negative, tid of thread waiting for this child (wait/waitpid) */
        int waiter_tid;
        /* exit status encoded like wait(2) returns (status word) */
        int exit_status;
} thread_t;

extern int init;

void thread_init();
thread_t* thread_create(void (*entry)(void), const char* name);
void thread_yield();
void thread_schedule();
thread_t* thread_current();
void thread_stop(int pid);
thread_t* thread_get(int pid);
int thread_get_pid(const char* name);
void thread_block(int pid);
void thread_unblock(int pid);
int thread_get_state(int pid);
int thread_get_count();
void thread_sleep(uint32_t ms);

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