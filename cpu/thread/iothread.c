#include <iothread.h>
#include <vga.h>
#include <heap.h>
#include <debug.h>
#include <string.h>
#include <spinlock.h>
#include <disk.h>
#include <thread.h>

// I/O планировщик
static io_request_t* pending_queue = NULL;
static io_request_t* completed_queue = NULL;
static spinlock_t io_lock;
static int request_count = 0;
static int iothread_initialized = 0;

// I/O поток
static struct thread_t* io_thread = NULL;

// Объявления внутренних функций
static void io_worker_thread(void);
static void process_io_request(io_request_t* request);

// Инициализация I/O планировщика
void iothread_init() {
        if (iothread_initialized) {
            klogprintf("iothread_init: already initialized\n");
                return;
        }
        
        // Инициализируем спинлок
        io_lock.lock = 0;
        
        // Создаем I/O поток
        io_thread = thread_create(io_worker_thread, "io_worker");
        if (io_thread) {
                iothread_initialized = 1;
        }
}

// Рабочий поток для обработки I/O
static void io_worker_thread(void) {
        while (1) {
                io_request_t* request = NULL;
                
                unsigned long _flags = 0;
                acquire_irqsave(&io_lock, &_flags);
                if (pending_queue) {
                        request = pending_queue;
                        pending_queue = pending_queue->next;
                        if (request) request->next = NULL;
                }
                release_irqrestore(&io_lock, _flags);
                
                if (request) {
                        process_io_request(request);
                        
                        unsigned long _flags2 = 0;
                        acquire_irqsave(&io_lock, &_flags2);
                        // push to head is fine for completed; consumer takes specific id
                        request->next = completed_queue;
                        completed_queue = request;
                        release_irqrestore(&io_lock, _flags2);
                } else {
                        // Нет запросов - уступаем квант
                        thread_yield();
                }
        }
}

// Обработка I/O запроса
static void process_io_request(io_request_t* request) {
	int rc = -1;
	switch (request->type) {
		case IO_OP_READ: {
			int devs = disk_count();
			if (request->device_id < devs) {
				/* convert size bytes -> sectors (round up) */
				uint32_t sectors = (request->size + DISK_SECTOR_SIZE - 1) / DISK_SECTOR_SIZE;
				rc = disk_read_sectors(request->device_id, request->offset, request->buffer, sectors);
			}
			break;
		}
		case IO_OP_WRITE: {
			int devs = disk_count();
			if (request->device_id < devs) {
				uint32_t sectors = (request->size + DISK_SECTOR_SIZE - 1) / DISK_SECTOR_SIZE;
				rc = disk_write_sectors(request->device_id, request->offset, request->buffer, sectors);
			}
			break;
		}
		default:
			rc = -1;
			break;
	}
	/* статус операции: 0 = успех, -1 = ошибка */
	request->status = (rc == 0) ? 1 : -1;
}

// Добавить I/O запрос в очередь (FIFO)
int iothread_schedule_request(io_op_type_t type, uint8_t device_id, uint32_t offset, uint8_t* buffer, uint32_t size) {
        if (!iothread_initialized) return -1;
        
        io_request_t* request = (io_request_t*)kmalloc(sizeof(io_request_t));
        if (!request) return -1;
        
        request->type = type;
        request->device_id = device_id;
        request->offset = offset;
        request->buffer = buffer;
        request->size = size;
        request->requesting_thread = thread_current();
        request->status = 0; // pending
        request->next = NULL;
        
        unsigned long _flags3 = 0;
        acquire_irqsave(&io_lock, &_flags3);
        request->id = ++request_count;
        // вставка в хвост для FIFO
        if (!pending_queue) {
        pending_queue = request;
        } else {
                io_request_t* tail = pending_queue;
                while (tail->next) tail = tail->next;
                tail->next = request;
        }
        int rid = request->id;
        release_irqrestore(&io_lock, _flags3);
        
        return rid;
}

// Ждать завершения конкретной I/O операции по id
int iothread_wait_completion(int request_id) {
        if (!iothread_initialized || request_id <= 0) return -1;

        while (1) {
                unsigned long _flags4 = 0;
                acquire_irqsave(&io_lock, &_flags4);
                io_request_t* request = completed_queue;
                io_request_t* prev = NULL;

                while (request) {
                        if (request->id == request_id && request->status != 0) {
                                // удаляем из очереди завершённых
                                if (prev) prev->next = request->next;
                                else completed_queue = request->next;
                                int status = request->status;
                                kfree(request);
                                release_irqrestore(&io_lock, _flags4);
                                return (status == 1) ? 0 : -1; // 0 успех, -1 ошибка
                        }
                        prev = request;
                        request = request->next;
                }
                release_irqrestore(&io_lock, _flags4);

                // уступаем процессор, чтобы IO-поток поработал
                thread_yield();
        }
}

// Проверить число готовых операций
int iothread_check_completed() {
        if (!iothread_initialized) return 0;
        
        unsigned long _flags5 = 0;
        acquire_irqsave(&io_lock, &_flags5);
        int count = 0;
        for (io_request_t* r = completed_queue; r; r = r->next) {
                if (r->status != 0) count++;
        }
        release_irqrestore(&io_lock, _flags5);
        return count;
}

// Получить завершенную операцию (любую)
io_request_t* iothread_get_completed() {
        if (!iothread_initialized) return NULL;
        
        unsigned long _flags6 = 0;
        acquire_irqsave(&io_lock, &_flags6);
        io_request_t* request = completed_queue;
        io_request_t* prev = NULL;
        
        while (request) {
                if (request->status != 0) {
                        if (prev) prev->next = request->next;
                        else completed_queue = request->next;
                        request->next = NULL;
                        release_irqrestore(&io_lock, _flags6);
                        return request;
                }
                prev = request;
                request = request->next;
        }
        release_irqrestore(&io_lock, _flags6);
        return NULL;
}