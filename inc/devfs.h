#pragma once

#include <stddef.h>
#include <fs.h>
#include <stdint.h>
#include <spinlock.h>

/* Number of virtual ttys provided by devfs (default) */
#ifndef DEVFS_TTY_COUNT
#define DEVFS_TTY_COUNT 6
#endif

struct devfs_tty {
    int id;
    uint8_t *screen; /* saved VGA buffer (raw bytes 2 per cell) */
    uint32_t cursor_x;
    uint32_t cursor_y;
    /* foreground process group for this tty (-1 if none) */
    int fg_pgrp;
    /* input buffer (chars) */
    char inbuf[256];
    int in_head;
    int in_tail;
    int in_count;
    spinlock_t in_lock;
    /* waiting threads (tids) */
    int waiters[8];
    int waiters_count;
};

int devfs_register(void);
int devfs_unregister(void);
int devfs_mount(const char *path);
/* Find block device index by path (returns -1 if not found) */
int devfs_find_block_by_path(const char *path);
/* Return underlying disk device_id for block node path, or -1 if not found */
int devfs_get_device_id(const char *path);
/* Switch current active virtual terminal (0..N-1) */
void devfs_switch_tty(int index);

/* Return number of virtual ttys available */
int devfs_tty_count(void);

/* Push input character into tty's input queue (called from keyboard) */
void devfs_tty_push_input(int tty, char c);
/* Return index of currently active tty */
int devfs_get_active(void);
/* Non-blocking push from ISR (tries to acquire lock, drops on failure) */
void devfs_tty_push_input_noblock(int tty, char c);
/* Non-blocking pop: returns -1 if none, or char (0-255) */
int devfs_tty_pop_nb(int tty);
/* Return number of available chars in input buffer */
int devfs_tty_available(int tty);
/* Check whether an fs_file is a devfs tty device */
int devfs_is_tty_file(struct fs_file *file);

/* Helpers to map an open file handle to a tty index and manage per-tty foreground pgrp. */
int devfs_get_tty_index_from_file(struct fs_file *file);
int devfs_get_tty_fg_pgrp(int tty);
void devfs_set_tty_fg_pgrp(int tty, int pgrp);

/* Create a block device node at given path and associate with disk device_id.
   sectors - total number of 512-byte sectors on device (for size reporting). */
int devfs_create_block_node(const char *path, int device_id, uint32_t sectors);



