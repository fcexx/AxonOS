#ifndef IOTHREAD_H
#define IOTHREAD_H

#include <stdint.h>
#include <thread.h>

// io operations
typedef enum {
        IO_OP_READ,
        IO_OP_WRITE
} io_op_type_t;

// io request
typedef struct io_request {
        io_op_type_t type;
        uint8_t device_id;
        uint32_t offset;
        uint8_t* buffer;
        uint32_t size;
        thread_t* requesting_thread;
        int id;                                 // unique request id
        int status;                         // 0 = pending, 1 = completed, -1 = error
        struct io_request* next;
} io_request_t;

// initialize io scheduler
void iothread_init();

// add io request to queue
int iothread_schedule_request(io_op_type_t type, uint8_t device_id, uint32_t offset, uint8_t* buffer, uint32_t size);

// wait for io operation completion
int iothread_wait_completion(int request_id);

// check if there are ready io operations
int iothread_check_completed();

// get completed operation
io_request_t* iothread_get_completed();

/* Non-zero while the I/O worker still has queued work (sync/reboot drain). */
int iothread_pending(void);

/* Block until pending_queue is empty (yields to io_worker). */
void iothread_drain(void);

#endif // IOTHREAD_H 