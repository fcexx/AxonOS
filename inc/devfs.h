#pragma once

#include <stddef.h>
#include <fs.h>
#include <stdint.h>
#include <spinlock.h>
#include <stat.h>

typedef struct thread thread_t;

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
    /* current attribute/color for this tty (VGA attribute byte) */
    uint8_t cur_attr;
    /* ANSI escape parsing state */
    int esc_state; /* 0=normal,1=ESC,2=CSI */
    char esc_buf[64];
    int esc_len;
    /* saved cursor for DEC smcup/rmcup (alternate screen) */
    uint32_t saved_x;
    uint32_t saved_y;
    uint32_t dec_saved_x; /* CSI s / CSI u */
    uint32_t dec_saved_y;
    uint8_t *alt_screen; /* main-screen backup while alt_active */
    uint8_t alt_active;
    uint8_t attr_reverse; /* SGR 7 active */
    uint32_t scroll_top;    /* DECSTBM inclusive, 0-based */
    uint32_t scroll_bottom; /* DECSTBM inclusive, 0-based */
    /* input buffer (chars) */
    char inbuf[256];
    int in_head;
    int in_tail;
    int in_count;
    spinlock_t in_lock;
    /* waiting threads (tids) */
    int waiters[8];
    int waiters_count;
    /* current VGA attribute for output on this tty (low nibble FG, high nibble BG) */
    uint8_t current_attr;
    /* simple ANSI escape state for CSI parsing (0=normal,1=ESC,2=CSI,3=SS3,4=)G0,5=(G0) */
    uint8_t ansi_escape_state;
    /* DEC line-drawing (ACS):
       - ESC ( 0 / ESC ) 0 select special-graphics for G0/G1
       - ESC ( B / ESC ) B select ASCII for G0/G1
       - SI (0x0F) / SO (0x0E) shift in/out (ncurses uses this) */
    uint8_t g0_is_acs;
    uint8_t acs_mode; /* active shift state (SO=1, SI=0) */
    /* CSI had '?' (DEC private params) */
    uint8_t ansi_csi_private;
    /* simple CSI parameter storage (up to 8 parameters) */
    int ansi_param[8];
    int ansi_param_count;
    int ansi_current_param;
    /* bold/bright flag from SGR (1) */
    uint8_t ansi_bold;
    /* controlling session id for this tty (-1 if none) */
    int controlling_sid;
    /* POSIX termios local flags (c_lflag) for this tty */
    uint32_t term_lflag;
    uint8_t term_vmin;
    uint8_t term_vtime; /* deciseconds */
    /* echo: skip escape sequences (0=normal, 1=after ESC, 2=after ESC [ or ESC O) */
    uint8_t echo_escape_state;
    /* single-byte pushback for readers (e.g. kgetc escape handling); -1 = none */
    int unget_char;
};

int devfs_register(void);
/* Reallocate all virtual-console screen buffers to match current console_max_cols/rows (call after fbcon init). */
void devfs_tty_realloc_for_console(void);
int devfs_unregister(void);
/* True after devfs_register() succeeded; safe to use tty cursor state then. */
int devfs_is_ready(void);
int devfs_mount(const char *path);
/* Open a devfs node directly without requiring a VFS mount. */
struct fs_file *devfs_open_direct(const char *path);
/* Create a character device node at given path and associate with driver_private.
   driver_private is stored and later returned in fs_file->driver_private on open. */
int devfs_create_char_node(const char *path, void *driver_private);
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
/* Push one byte back; will be returned by next pop. Returns 0 on success, -1 if already pushed. */
int devfs_tty_unget(int tty, int c);
/* Return number of available chars in input buffer */
int devfs_tty_available(int tty);
/* Add thread as waiter (for poll); returns 0 on success, -1 if full or already present */
int devfs_tty_add_waiter(int tty, int tid);
/* Remove thread from waiters (call when poll wakes so we are not woken again by other ttys) */
void devfs_tty_remove_waiter(int tty, int tid);
/* Remove tid from every tty waiter list (fixes slot exhaustion after exit_group). */
void devfs_tty_remove_waiter_from_all_ttys(int tid);
/* Restore main TTY buffer after smcup/rmcup or fatal exit (htop/nano). */
void devfs_tty_leave_alt_screen(int tty);
/* Check whether an fs_file is a devfs tty device */
int devfs_is_tty_file(struct fs_file *file);

/* Helpers to map an open file handle to a tty index and manage per-tty foreground pgrp. */
int devfs_get_tty_index_from_file(struct fs_file *file);
int devfs_get_tty_fg_pgrp(int tty);
void devfs_set_tty_fg_pgrp(int tty, int pgrp);
int devfs_tty_get_fg_pgrp(struct fs_file *file);
int devfs_tty_set_fg_pgrp(struct fs_file *file, int pgrp);
ssize_t devfs_tty_debug_dump(char *buf, size_t size);
int devfs_tty_attach_thread(struct fs_file *file, thread_t *th);
int devfs_get_tty_controlling_sid(struct fs_file *file);
int devfs_set_tty_controlling_sid(struct fs_file *file, int sid);
void devfs_clear_controlling_by_sid(int sid);
/* Return pointer to internal tty struct (for callers that need to read/write flags).
   Caller must not free or modify beyond term_lflag; pointer is valid while devfs registered. */
struct devfs_tty *devfs_get_tty_by_index(int idx);

/* Create a block device node at given path and associate with disk device_id.
   sectors - total number of 512-byte sectors on device (for size reporting). */
int devfs_create_block_node(const char *path, int device_id, uint32_t sectors);
/* Create a block node mapped to [start_lba, start_lba+sectors) on parent device. */
int devfs_create_block_node_lba(const char *path, int device_id, uint32_t start_lba, uint32_t sectors);

/* Fill a POSIX-like stat struct for a devfs file handle. */
int devfs_fill_stat(struct fs_file *file, struct stat *st);

/* Enumerate registered block devices (created via devfs_create_block_node). */
int devfs_block_count(void);
int devfs_block_get(int index, char *out_name, size_t out_cap, int *out_device_id, uint32_t *out_sectors);



