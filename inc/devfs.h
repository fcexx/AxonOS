#pragma once

#include <stddef.h>
#include "fs.h"

/* Number of virtual ttys provided by devfs (default) */
#ifndef DEVFS_TTY_COUNT
#define DEVFS_TTY_COUNT 6
#endif

int devfs_register(void);
int devfs_unregister(void);
int devfs_mount(const char *path);
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



