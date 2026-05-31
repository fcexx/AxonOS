#ifndef PS2_H
#define PS2_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Специальные коды для стрелок и других клавиш
#define KEY_UP         0x80
#define KEY_DOWN   0x81
#define KEY_LEFT   0x82
#define KEY_RIGHT  0x83
#define KEY_HOME   0x84
#define KEY_END        0x85
#define KEY_PGUP   0x86
#define KEY_PGDN   0x87
#define KEY_INSERT 0x88
#define KEY_DELETE 0x89
#define KEY_TAB         0x8A
#define KEY_ESC        0x8B

// initialize PS/2 keyboard
void ps2_keyboard_init();
/* Publish keyboard nodes to /sys/class/input/* (safe to call multiple times). */
void keyboard_publish_sysfs(void);

// get symbol (blocking function, like in Unix)
char kgetc();

// check if there are available symbols (non-blocking)
int kgetc_available();

// get string with support for arrows and editing
char* kgets(char* buffer, int max_length);

/* Internal helper used by PS/2 routing code. */
void keyboard_process_scancode(uint8_t scancode);

// ctrl+C handling helpers
int keyboard_ctrlc_pending(void);
int keyboard_consume_ctrlc(void);

#ifdef __cplusplus
}
#endif

#endif // PS2_H