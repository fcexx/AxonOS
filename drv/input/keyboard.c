#include <keyboard.h>
#include <idt.h>
#include <vga.h>
#include <spinlock.h>
#include <stdint.h>
#include <serial.h>
#include <string.h>
#include <thread.h>
#include <sysfs.h>
#include <pic.h>
#include <devfs.h>

// Вспомогательные функции для ожидания статусов контроллера PS/2
static int ps2_wait_input_empty(void) {
        // Wait until input buffer (bit1) is clear => we can write to 0x60/0x64
        for (int i = 0; i < 100000; i++) {
                if ((inb(0x64) & 0x02) == 0) return 1;
        }
        return 0;
}

static int ps2_wait_output_full(void) {
        // Wait until output buffer (bit0) is set => data available at 0x60
        for (int i = 0; i < 100000; i++) {
                if ((inb(0x64) & 0x01) != 0) return 1;
        }
        return 0;
}

static inline void io_wait_local(void) {
        /* Classic POST-style I/O wait (QEMU supports it). */
        outb(0x80, 0);
}

static void ps2_flush_output(void) {
        /* Drain any pending bytes in the controller output buffer. */
        for (int i = 0; i < 64; i++) {
                if ((inb(0x64) & 0x01) == 0) break;
                (void)inb(0x60);
                io_wait_local();
        }
}

// Прототип функции обработки байта сканкода (используется в handler и для polling)
void keyboard_process_scancode(uint8_t scancode);

// Размер буфера клавиатуры
#define KEYBOARD_BUFFER_SIZE 256

// Буфер для хранения символов
// We no longer maintain a separate global keyboard buffer; input is routed into devfs tty buffers.

// Таблица сканкодов для преобразования в ASCII
static const char scancode_to_ascii[128] = {
        0, 0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b', 0,
        'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', 0, 'a', 's',
        'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\', 'z', 'x', 'c', 'v',
        'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, '7', '8', '9', '-', '4', '5', '6', '+', '1',
        '2', '3', '0', '.', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// Таблица сканкодов для Shift
static const char scancode_to_ascii_shift[128] = {
        0, 0, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b', 0,
        'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n', 0, 'A', 'S',
        'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0, '|', 'Z', 'X', 'C', 'V',
        'B', 'N', 'M', '<', '>', '?', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, '7', '8', '9', '-', '4', '5', '6', '+', '1',
        '2', '3', '0', '.', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// Флаги состояния клавиатуры
static volatile bool shift_pressed = false;
static volatile bool ctrl_pressed = false;
static volatile bool alt_pressed = false;
static volatile bool ctrlc_pending = false;
static bool keyboard_sysfs_registered = false;
static volatile bool kbd_extended_prefix = false;

static ssize_t keyboard_sysfs_show_text(char *buf, size_t size, void *priv) {
        if (!buf || size == 0) return 0;
        const char *txt = priv ? (const char*)priv : "";
        size_t len = strlen(txt);
        if (len > size) len = size;
        memcpy(buf, txt, len);
        if (len < size) buf[len++] = '\n';
        return (ssize_t)len;
}

static ssize_t keyboard_sysfs_show_ctrlc(char *buf, size_t size, void *priv) {
        (void)priv;
        if (!buf || size == 0) return 0;
        const char *state = ctrlc_pending ? "1\n" : "0\n";
        size_t len = strlen(state);
        if (len > size) len = size;
        memcpy(buf, state, len);
        return (ssize_t)len;
}

static void keyboard_register_sysfs(void) {
        if (keyboard_sysfs_registered) return;
        sysfs_mkdir("/sys/class");
        sysfs_mkdir("/sys/class/input");
        sysfs_mkdir("/sys/class/input/keyboard0");
        struct sysfs_attr attr_name = { keyboard_sysfs_show_text, NULL, (void*)"AT PS/2 keyboard" };
        struct sysfs_attr attr_driver = { keyboard_sysfs_show_text, NULL, (void*)"ps2-keyboard" };
        struct sysfs_attr attr_ctrlc = { keyboard_sysfs_show_ctrlc, NULL, NULL };
        sysfs_create_file("/sys/class/input/keyboard0/name", &attr_name);
        sysfs_create_file("/sys/class/input/keyboard0/driver", &attr_driver);
        sysfs_create_file("/sys/class/input/keyboard0/ctrlc_pending", &attr_ctrlc);
        keyboard_sysfs_registered = true;
}

// Добавить символ в буфер
static void add_to_buffer(char c) {
    /* Legacy wrapper kept for compatibility; push to devfs active tty non-blocking */
    devfs_tty_push_input_noblock(devfs_get_active(), c);
}

// Обработчик прерывания клавиатуры
void keyboard_handler(cpu_registers_t* regs) {
        uint8_t scancode = inb(0x60);
        thread_t* cur = thread_current();
        int curid = cur ? cur->tid : -1;
        //qemu_debug_printf("kbd: scancode=0x%02x (current tid=%d)\n", scancode, curid);
        keyboard_process_scancode(scancode);
        // EOI отправляется центральным диспетчером прерываний в isr_dispatch
}

// Обработка одного байта сканкода (вынесена для возможности polling из PIT)
// Опциональная отладка сканкодов — выключена по умолчанию для минимизации задержек в ISR
#include <debug.h>
#ifndef KBD_DEBUG
#define KBD_DEBUG 0
#endif

static void kbd_push_sequence(int tty, const char *seq) {
    if (!seq) return;
    for (const char *p = seq; *p; ++p) {
        devfs_tty_push_input_noblock(tty, *p);
    }
}

void keyboard_process_scancode(uint8_t scancode) {
#if KBD_DEBUG
    qemu_debug_printf("kbd: scancode=0x%02x\n", scancode);
#endif
        if (scancode == 0xE0) {
                kbd_extended_prefix = true;
                return;
        }
        if (scancode == 0xE1) {
                /* Pause/Break sequence start: ignore for now */
                kbd_extended_prefix = false;
                return;
        }
        // Обрабатываем только нажатие клавиш (не отпускание)
        if (scancode & 0x80) {
                // Клавиша отпущена
                scancode &= 0x7F; // Убираем бит отпускания
                if (kbd_extended_prefix) {
                        /* extended break codes (E0 xx) */
                        switch (scancode) {
                                case 0x1D: /* Right Ctrl */ ctrl_pressed = false; break;
                                case 0x38: /* Right Alt (AltGr) */ alt_pressed = false; break;
                                default: break;
                        }
                        kbd_extended_prefix = false;
                        return;
                } else {
                        switch (scancode) {
                                case 0x2A: // Left Shift
                                case 0x36: // Right Shift
                                        shift_pressed = false;
                                        break;
                                case 0x1D: // Left Ctrl
                                        ctrl_pressed = false;
                                        break;
                                case 0x38: // Left Alt
                                        alt_pressed = false;
                                        break;
                        }
                }
                return;
        }

        // Клавиша нажата
        // determine target tty for user processes (prefer user's attached tty)
        thread_t *tu_for_tty = thread_get_current_user();
        int target_tty_for_user = devfs_get_active();
        if (tu_for_tty && tu_for_tty->attached_tty >= 0) target_tty_for_user = tu_for_tty->attached_tty;

        if (kbd_extended_prefix) {
                /* extended make codes (E0 xx) — always send ANSI sequences to TTY (ISR has no user context) */
                switch (scancode) {
                        case 0x1D: /* Right Ctrl */ ctrl_pressed = true; break;
                        case 0x38: /* Right Alt (AltGr) */ alt_pressed = true; break;
                        case 0x48: /* Up */    kbd_push_sequence(target_tty_for_user, "\x1B[A"); break;
                        case 0x50: /* Down */  kbd_push_sequence(target_tty_for_user, "\x1B[B"); break;
                        case 0x4B: /* Left */  kbd_push_sequence(target_tty_for_user, "\x1B[D"); break;
                        case 0x4D: /* Right */ kbd_push_sequence(target_tty_for_user, "\x1B[C"); break;
                        case 0x47: /* Home */  kbd_push_sequence(target_tty_for_user, "\x1B[H"); break;
                        case 0x4F: /* End */   kbd_push_sequence(target_tty_for_user, "\x1B[F"); break;
                        case 0x49: /* PgUp */  kbd_push_sequence(target_tty_for_user, "\x1B[5~"); break;
                        case 0x51: /* PgDn */  kbd_push_sequence(target_tty_for_user, "\x1B[6~"); break;
                        case 0x52: /* Ins */   kbd_push_sequence(target_tty_for_user, "\x1B[2~"); break;
                        case 0x53: /* Del */   kbd_push_sequence(target_tty_for_user, "\x1B[3~"); break;
                        case 0x1C: /* Keypad Enter */ add_to_buffer('\n'); break;
                        case 0x35: /* Keypad '/' */   add_to_buffer('/'); break;
                        case 0x01: /* Escape (E0 01 on some kbd) */ devfs_tty_push_input_noblock(target_tty_for_user, 27); break;
                        default: break;
                }
                kbd_extended_prefix = false;
                return;
        }

        switch (scancode) {
                case 0x2A: // Left Shift
                case 0x36: // Right Shift
                        shift_pressed = true;
                        break;
                case 0x1D: // Left Ctrl
                        ctrl_pressed = true;
                        break;
                case 0x38: // Left Alt
                        alt_pressed = true;
                        break;
                case 0x0E: // Backspace
                        /* Always send DEL (0x7f) to TTY for userspace; kernel kgetc handles \b */
                        devfs_tty_push_input_noblock(target_tty_for_user, 0x7F);
                        break;
                case 0x48: // Up arrow
                case 0x50: // Down arrow
                case 0x4B: // Left arrow
                case 0x4D: // Right arrow
                case 0x47: // Home
                case 0x4F: // End
                case 0x49: // Page Up
                case 0x51: // Page Down
                case 0x52: // Insert
                case 0x53: // Delete
                        /* Always send ANSI sequences to TTY (thread_get_current_user() is NULL in ISR) */
                        if (scancode == 0x48) kbd_push_sequence(target_tty_for_user, "\x1B[A");
                        else if (scancode == 0x50) kbd_push_sequence(target_tty_for_user, "\x1B[B");
                        else if (scancode == 0x4B) kbd_push_sequence(target_tty_for_user, "\x1B[D");
                        else if (scancode == 0x4D) kbd_push_sequence(target_tty_for_user, "\x1B[C");
                        else if (scancode == 0x47) kbd_push_sequence(target_tty_for_user, "\x1B[H");
                        else if (scancode == 0x4F) kbd_push_sequence(target_tty_for_user, "\x1B[F");
                        else if (scancode == 0x49) kbd_push_sequence(target_tty_for_user, "\x1B[5~");
                        else if (scancode == 0x51) kbd_push_sequence(target_tty_for_user, "\x1B[6~");
                        else if (scancode == 0x52) kbd_push_sequence(target_tty_for_user, "\x1B[2~");
                        else kbd_push_sequence(target_tty_for_user, "\x1B[3~");
                        break;
                case 0x0F: // Tab — отправляем ASCII '\t' (0x09), чтобы в TTY/sh отображался таб, а не неизвестный символ
                        add_to_buffer('\t');
                        break;
                case 0x01: // Escape
                case 0x76: // Escape (alternate scancode)
                        devfs_tty_push_input_noblock(target_tty_for_user, 27);
                        break;
                case 0x3B: // F1
                case 0x3C: // F2
                case 0x3D: // F3
                case 0x3E: // F4
                case 0x3F: // F5
                case 0x40: // F6
                        if (alt_pressed) {
                                int idx = 0;
                                if (scancode == 0x3B) idx = 0;
                                else if (scancode == 0x3C) idx = 1;
                                else if (scancode == 0x3D) idx = 2;
                                else if (scancode == 0x3E) idx = 3;
                                else if (scancode == 0x3F) idx = 4;
                                else if (scancode == 0x40) idx = 5;
                                devfs_switch_tty(idx);
                        } else {
                                if (thread_get_current_user()) {
                                        switch (scancode) {
                                                case 0x3B: kbd_push_sequence(target_tty_for_user, "\x1BOP"); break; /* F1 */
                                                case 0x3C: kbd_push_sequence(target_tty_for_user, "\x1BOQ"); break; /* F2 */
                                                case 0x3D: kbd_push_sequence(target_tty_for_user, "\x1BOR"); break; /* F3 */
                                                case 0x3E: kbd_push_sequence(target_tty_for_user, "\x1BOS"); break; /* F4 */
                                                case 0x3F: kbd_push_sequence(target_tty_for_user, "\x1B[15~"); break; /* F5 */
                                                case 0x40: kbd_push_sequence(target_tty_for_user, "\x1B[17~"); break; /* F6 */
                                        }
                                }
                        }
                        break;
                case 0x41: // F7
                case 0x42: // F8
                case 0x43: // F9
                case 0x44: // F10
                case 0x57: // F11
                case 0x58: // F12
                        if (thread_get_current_user()) {
                                switch (scancode) {
                                        case 0x41: kbd_push_sequence(target_tty_for_user, "\x1B[18~"); break; /* F7 */
                                        case 0x42: kbd_push_sequence(target_tty_for_user, "\x1B[19~"); break; /* F8 */
                                        case 0x43: kbd_push_sequence(target_tty_for_user, "\x1B[20~"); break; /* F9 */
                                        case 0x44: kbd_push_sequence(target_tty_for_user, "\x1B[21~"); break; /* F10 */
                                        case 0x57: kbd_push_sequence(target_tty_for_user, "\x1B[23~"); break; /* F11 */
                                        case 0x58: kbd_push_sequence(target_tty_for_user, "\x1B[24~"); break; /* F12 */
                                }
                        }
                        break;
                default:
                        // Обычная клавиша
                        if (scancode < 128) {
                                char c = shift_pressed ? scancode_to_ascii_shift[scancode] : scancode_to_ascii[scancode];
                                if (c != 0) {
                                        // Обработка Ctrl-комбинаций: Ctrl+A..Z -> 0x01..0x1A
                                        if (ctrl_pressed) {
                                                unsigned char uc = (unsigned char)c;
                                                if (uc >= 'a' && uc <= 'z') uc = (unsigned char)(uc - 'a' + 'A');
                                                if (uc >= 'A' && uc <= 'Z') {
                                                        c = (char)(uc - 'A' + 1);
                                                }
                                        }
                                if (c == 3) {
                                        ctrlc_pending = true;
                                }
                                        add_to_buffer(c);
                                        //qemu_debug_printf("kbd: char '%c' (0x%02x) -> buffer_count=%d\n", c, (unsigned char)c, buffer_count);
                                }
                        }
                        break;
        }
}

// Инициализация PS/2 клавиатуры
void ps2_keyboard_init() {
        // Сбрасываем флаги
        shift_pressed = false;
        ctrl_pressed = false;
        alt_pressed = false;
        ctrlc_pending = false;
        
        // Устанавливаем обработчик прерывания
        idt_set_handler(33, keyboard_handler);
        // Ensure PIC delivers IRQ1
        pic_unmask_irq(1);
        /* Flush stale controller output before programming it. */
        ps2_flush_output();
        // Try to enable first PS/2 port at controller level (command 0xAE)
        if (!ps2_wait_input_empty()) qemu_debug_printf("ps2_keyboard_init: warning input buffer never emptied before 0xAE\n");
        outb(0x64, 0xAE);
        io_wait_local();

        // Read PS/2 controller command byte and ensure keyboard IRQ enabled (bit0)
        if (!ps2_wait_input_empty()) qemu_debug_printf("ps2_keyboard_init: warning input buffer never emptied before reading cmd\n");
        outb(0x64, 0x20); // request command byte
        io_wait_local();
        uint8_t cmd = 0;
        if (!ps2_wait_output_full()) {
                /* Some emulators/controllers may not respond to 0x20 reliably if output
                   already held stale data or timing is tight. Do NOT read random 0x60 here. */
                qemu_debug_printf("ps2_keyboard_init: warning output buffer never filled for cmd; using defaults\n");
                /* Conservative defaults:
                   - enable IRQ1 (bit0)
                   - enable translation (bit6) so set1 scancodes are translated to set2 if needed
                   - keep other bits cleared (ports enabled) */
                cmd = (uint8_t)(0x01u | 0x40u);
        } else {
                cmd = inb(0x60);
                /* Enable IRQ1 and ensure keyboard clock is enabled (clear disable bit4). */
                cmd |= 0x01u;          // enable IRQ1
                cmd &= (uint8_t)~0x10u; // clear "disable keyboard" if set
                /* Translation on helps with some setups; keep as-is if already set. */
        }
        if (!ps2_wait_input_empty()) qemu_debug_printf("ps2_keyboard_init: warning input buffer never emptied before writing cmd\n");
        outb(0x64, 0x60); // write command byte
        if (!ps2_wait_input_empty()) qemu_debug_printf("ps2_keyboard_init: warning input buffer never emptied before writing cmd byte value\n");
        outb(0x60, cmd);
        io_wait_local();

        /* Enable scanning on the keyboard (0xF4) and optionally consume ACK (0xFA). */
        if (!ps2_wait_input_empty()) qemu_debug_printf("ps2_keyboard_init: warning input buffer busy before sending 0xF4\n");
        outb(0x60, 0xF4);
        io_wait_local();
        if (ps2_wait_output_full()) {
                uint8_t resp = inb(0x60);
                if (resp != 0xFA) {
                        /* Not fatal; just report for diagnostics. */
                        qemu_debug_printf("ps2_keyboard_init: keyboard enable scan resp=0x%02x\n", resp);
                }
        }
        keyboard_register_sysfs();
}

// Получить символ (блокирующая функция, как в Unix)
// ESC (27): возвращаем сразу, без ожиданий. Стрелки: только если [ или O уже в буфере — сливаем ESC [ A в KEY_UP и т.д.
char kgetc() {
    int tty = devfs_get_active();
    if (tty < 0) tty = 0;
    int c;
    for (;;) {
        c = devfs_tty_pop_nb(tty);
        if (c >= 0) {
            if (c == 27) {
                int next1 = devfs_tty_pop_nb(tty);
                if (next1 < 0) return (char)27;  /* нет следующего байта — сразу ESC */
                if (next1 == '[' || next1 == 'O') {
                    int next2 = devfs_tty_pop_nb(tty);
                    if (next2 < 0) {
                        devfs_tty_unget(tty, next1);
                        return (char)27;
                    }
                    if (next2 == 'A') return (char)KEY_UP;
                    if (next2 == 'B') return (char)KEY_DOWN;
                    if (next2 == 'C') return (char)KEY_RIGHT;
                    if (next2 == 'D') return (char)KEY_LEFT;
                    devfs_tty_unget(tty, next2);
                    devfs_tty_unget(tty, next1);
                    return (char)27;
                }
                devfs_tty_unget(tty, next1);
                return (char)27;
            }
            return (char)c;
        }
        asm volatile("sti; hlt" ::: "memory");
    }
}

// Проверить, есть ли доступные символы (неблокирующая)
int kgetc_available() {
        int tty = devfs_get_active();
        if (tty < 0) tty = 0;
        return devfs_tty_available(tty);
}

int keyboard_ctrlc_pending(void) {
        return ctrlc_pending ? 1 : 0;
}

int keyboard_consume_ctrlc(void) {
        if (ctrlc_pending) {
                ctrlc_pending = false;
                return 1;
        }
        return 0;
}

// Убрана локальная реализация автодополнения — используется глобальная в sys_read

// Получить строку с поддержкой стрелок и редактирования
char* kgets(char* buffer, int max_length) {
        if (!buffer || max_length <= 0) {
                return NULL;
        }
        
        int buffer_pos = 0;
        int cursor_pos = 0;
        memset(buffer, 0, max_length);

        uint32_t start_x = 0, start_y = 0; vga_get_cursor(&start_x, &start_y);
        
        vga_set_cursor(start_x, start_y);
        
        while (1) {
                char c = kgetc();
                // qemu_debug_printf("kgets got char: %d\n", c);
                
                if (c == 0) {
                        continue;
                }
                
                if (c == '\n') {
                        // VGA hw cursor: nothing to erase; we'll rewrite line
                        buffer[buffer_pos] = '\0';
                        kprint("\n");
                        return buffer;
                }
                
                // Скрываем курсор перед любым изменением
                // VGA hw cursor: nothing to erase
                
                if ((c == '\b' || c == 127) && cursor_pos > 0) {
                        // Backspace
                        for (int i = cursor_pos - 1; i < buffer_pos; i++) {
                                buffer[i] = buffer[i + 1];
                        }
                        buffer_pos--;
                        cursor_pos--;
                } else if (c == (char)KEY_LEFT && cursor_pos > 0) {
                        cursor_pos--;
                } else if (c == (char)KEY_RIGHT && cursor_pos < buffer_pos) {
                        cursor_pos++;
                } else if (c == (char)KEY_HOME && cursor_pos > 0) {
                        cursor_pos = 0;
                } else if (c == (char)KEY_END && cursor_pos < buffer_pos) {
                        cursor_pos = buffer_pos;
                } else if (c == (char)KEY_DELETE && cursor_pos < buffer_pos) {
                        for (int i = cursor_pos; i < buffer_pos - 1; i++) {
                                buffer[i] = buffer[i + 1];
                        }
                        buffer_pos--;
                } else if (c == '\t') {
                        // Вставка символа табуляции (VGA/vbefb отрисуют пробелы до следующей таб-стопы)
                        if (buffer_pos < max_length - 1) {
                                for (int i = buffer_pos; i > cursor_pos; i--) {
                                        buffer[i] = buffer[i - 1];
                                }
                                buffer[cursor_pos] = '\t';
                                buffer_pos++;
                                cursor_pos++;
                        }
                } else if (c >= 32 && c < 127 && buffer_pos < max_length - 1) {
                        // Вставка символа
                        for (int i = buffer_pos; i > cursor_pos; i--) {
                                buffer[i] = buffer[i - 1];
                        }
                        buffer[cursor_pos] = c;
                        buffer_pos++;
                        cursor_pos++;
                }
                
                // Всегда перерисовываем всю строку заново
                // 1. Очищаем всю строку от промпта до конца
                vga_set_cursor(start_x, start_y);
                
                for (int i = 0; i < buffer_pos + 10; i++) { // Очищаем с запасом
                kprint(" ");
                }
                
                // 2. Перерисовываем строку с начала
                vga_set_cursor(start_x, start_y);
                for (int i = 0; i < buffer_pos; i++) {
                        kputchar((uint8_t)buffer[i], GRAY_ON_BLACK);
                }
                
                // 3. Устанавливаем курсор в правильную позицию
                vga_set_cursor(start_x + (uint32_t)cursor_pos, start_y);
        }
        
        return buffer;
}