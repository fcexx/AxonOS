#include <stdint.h>
#include <serial.h>
#include <vga.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <vbe.h>
#include <cirrusfb.h>
#include <spinlock.h>
#include <console.h>
#include <devfs.h>

static uint8_t parse_color_code(char bg, char fg);

/* Serialize console with IRQ-save: timer/keyboard ISRs may flush or move cursor;
 * plain spin + IF=1 deadlocks if an IRQ tries to take this lock while we hold it.
 * kprintf/kprint hold this for an entire format string so SMP log lines do not interleave. */
static spinlock_t vga_lock_spin = { 0 };

/* Internal nolock primitives for callers that already hold the lock. */
static inline void write_nolock(uint8_t character, uint8_t attribute_byte, uint16_t offset) {
	uint8_t *vga = (uint8_t *) VIDEO_ADDRESS;
	vga[offset] = character;
	vga[offset + 1] = attribute_byte;
}

static inline uint16_t get_cursor_nolock(void) {
	outb(REG_SCREEN_CTRL, 14);
	uint8_t high_byte = inb(REG_SCREEN_DATA);
	outb(REG_SCREEN_CTRL, 15);
	uint8_t low_byte = inb(REG_SCREEN_DATA);
	return (((high_byte << 8) + low_byte) * 2);
}

static inline void set_cursor_nolock(uint16_t pos) {
	pos /= 2;
	outb(REG_SCREEN_CTRL, 14);
	outb(REG_SCREEN_DATA, (uint8_t)(pos >> 8));
	outb(REG_SCREEN_CTRL, 15);
	outb(REG_SCREEN_DATA, (uint8_t)(pos & 0xff));
}

/* --- ANSI CSI for plain VGA text (no Cirrus/VBE): otherwise ESC[H prints as "[H" --- */
enum { VGA_TX_ESC_NONE = 0, VGA_TX_ESC = 1, VGA_TX_CSI = 2, VGA_TX_SS3 = 3 };
static int vga_tx_esc = VGA_TX_ESC_NONE;
static int vga_tx_csi_p[8];
static int vga_tx_csi_np = 0;
static int vga_tx_csi_cur = 0;

static void vga_nolock_fill_range(uint32_t x0, uint32_t x1, uint32_t y, uint8_t attr) {
	if (y >= MAX_ROWS || x0 > x1) return;
	if (x1 >= MAX_COLS) x1 = MAX_COLS - 1;
	for (uint32_t x = x0; x <= x1; x++) {
		write_nolock(' ', attr, (uint16_t)((y * MAX_COLS + x) * 2));
	}
}

static void vga_nolock_csi_dispatch(uint8_t fb, uint8_t attr) {
	int np = vga_tx_csi_np;
	int *p = vga_tx_csi_p;

	if (fb == 'm') {
		/* Swallow SGR; per-character attr comes from the caller (e.g. devfs tty). */
		(void)np;
		(void)p;
		return;
	}
	if (fb == 'H' || fb == 'f') {
		int row = (np >= 1) ? p[0] : 1;
		int col = (np >= 2) ? p[1] : 1;
		if (row < 1) row = 1;
		if (col < 1) col = 1;
		if ((uint32_t)row > MAX_ROWS) row = MAX_ROWS;
		if ((uint32_t)col > MAX_COLS) col = MAX_COLS;
		set_cursor_nolock((uint16_t)(((uint32_t)(row - 1) * MAX_COLS + (uint32_t)(col - 1)) * 2));
		return;
	}
	if (fb == 'J') {
		int pm = (np > 0) ? p[0] : 0;
		if (pm == 2 || pm == 3) {
			for (uint32_t i = 0; i < (uint32_t)(MAX_ROWS * MAX_COLS); i++) {
				write_nolock(' ', attr, (uint16_t)(i * 2));
			}
			set_cursor_nolock(0);
			return;
		}
		uint16_t off = get_cursor_nolock();
		uint32_t cy = (uint32_t)((off / 2) / MAX_COLS);
		uint32_t cx = (uint32_t)((off / 2) % MAX_COLS);
		if (pm == 0) {
			vga_nolock_fill_range(cx, MAX_COLS - 1, cy, attr);
			for (uint32_t yy = cy + 1; yy < MAX_ROWS; yy++) {
				vga_nolock_fill_range(0, MAX_COLS - 1, yy, attr);
			}
		} else if (pm == 1) {
			for (uint32_t yy = 0; yy < cy; yy++) {
				vga_nolock_fill_range(0, MAX_COLS - 1, yy, attr);
			}
			vga_nolock_fill_range(0, cx, cy, attr);
		}
		return;
	}
	if (fb == 'K') {
		int pm = (np > 0) ? p[0] : 0;
		uint16_t off = get_cursor_nolock();
		uint32_t cy = (uint32_t)((off / 2) / MAX_COLS);
		uint32_t cx = (uint32_t)((off / 2) % MAX_COLS);
		if (pm == 0) {
			vga_nolock_fill_range(cx, MAX_COLS - 1, cy, attr);
		} else if (pm == 1) {
			vga_nolock_fill_range(0, cx, cy, attr);
		} else {
			vga_nolock_fill_range(0, MAX_COLS - 1, cy, attr);
		}
		return;
	}
	if (fb == 'A' || fb == 'B' || fb == 'C' || fb == 'D') {
		int n = (np > 0 && p[0] > 0) ? p[0] : 1;
		uint16_t off = get_cursor_nolock();
		uint32_t cy = (uint32_t)((off / 2) / MAX_COLS);
		uint32_t cx = (uint32_t)((off / 2) % MAX_COLS);
		if (fb == 'A') {
			if (cy >= (uint32_t)n) cy -= (uint32_t)n; else cy = 0;
		} else if (fb == 'B') {
			if (cy + (uint32_t)n < MAX_ROWS) cy += (uint32_t)n; else cy = MAX_ROWS - 1;
		} else if (fb == 'C') {
			if (cx + (uint32_t)n < MAX_COLS) cx += (uint32_t)n; else cx = MAX_COLS - 1;
		} else {
			if (cx >= (uint32_t)n) cx -= (uint32_t)n; else cx = 0;
		}
		set_cursor_nolock((uint16_t)((cy * MAX_COLS + cx) * 2));
	}
}

static void kputchar_vga_text_nolock(uint8_t character, uint8_t attribute_byte);
static void console_putc_nolock(uint8_t character, uint8_t attribute_byte);
static void kputn_nolock(char ch, int count, uint8_t color);

static int vga_text_ansi_feed_nolock(uint8_t ch, uint8_t attr) {
	if (vga_tx_esc == VGA_TX_ESC_NONE) {
		if (ch == 0x1B) {
			vga_tx_esc = VGA_TX_ESC;
			return 1;
		}
		return 0;
	}
	if (vga_tx_esc == VGA_TX_ESC) {
		if (ch == '[') {
			vga_tx_esc = VGA_TX_CSI;
			vga_tx_csi_np = 0;
			vga_tx_csi_cur = 0;
			return 1;
		}
		if (ch == 'O') {
			vga_tx_esc = VGA_TX_SS3;
			return 1;
		}
		vga_tx_esc = VGA_TX_ESC_NONE;
		kputchar_vga_text_nolock(0x1B, attr);
		kputchar_vga_text_nolock(ch, attr);
		return 1;
	}
	if (vga_tx_esc == VGA_TX_SS3) {
		vga_tx_esc = VGA_TX_ESC_NONE;
		return 1;
	}
	if (ch >= '0' && ch <= '9') {
		vga_tx_csi_cur = vga_tx_csi_cur * 10 + (ch - '0');
		return 1;
	}
	if (ch == ';') {
		if (vga_tx_csi_np < 8) vga_tx_csi_p[vga_tx_csi_np++] = vga_tx_csi_cur;
		vga_tx_csi_cur = 0;
		return 1;
	}
	if (ch == '?' || ch == '>') {
		return 1;
	}
	if (vga_tx_csi_np < 8) vga_tx_csi_p[vga_tx_csi_np++] = vga_tx_csi_cur;
	vga_tx_csi_cur = 0;
	if ((unsigned char)ch >= 0x40 && (unsigned char)ch <= 0x7E) {
		vga_nolock_csi_dispatch((uint8_t)ch, attr);
	}
	vga_tx_esc = VGA_TX_ESC_NONE;
	vga_tx_csi_np = 0;
	return 1;
}

/* Fast direct VGA helpers */
void vga_putch_xy(uint32_t x, uint32_t y, uint8_t ch, uint8_t attr) {
	if (x >= MAX_COLS || y >= MAX_ROWS) return;
	uint16_t off = (uint16_t)((y * MAX_COLS + x) * 2);
	unsigned long fl;
	acquire_irqsave(&vga_lock_spin, &fl);
	write_nolock(ch, attr, off);
	release_irqrestore(&vga_lock_spin, fl);
}

uint8_t vga_get_cell_attr(uint32_t x, uint32_t y) {
	if (cirrusfb_is_ready() || vbe_is_available()) return GRAY_ON_BLACK;
	if (x >= MAX_COLS || y >= MAX_ROWS) return GRAY_ON_BLACK;
	uint16_t off = (uint16_t)((y * MAX_COLS + x) * 2 + 1);
	unsigned long fl;
	acquire_irqsave(&vga_lock_spin, &fl);
	uint8_t attr = ((uint8_t *)VIDEO_ADDRESS)[off];
	release_irqrestore(&vga_lock_spin, fl);
	return attr;
}

void vga_clear_line_segment(uint32_t x0, uint32_t x1, uint32_t y, uint8_t attr) {
	if (y >= MAX_ROWS) return;
	if (x0 > x1) return;
	if (x1 >= MAX_COLS) x1 = MAX_COLS - 1;
	if (cirrusfb_is_ready()) {
		for (uint32_t x = x0; x <= x1; x++)
			cirrusfb_putch_xy(x, y, ' ', attr);
	} else if (vbe_is_available()) {
		for (uint32_t x = x0; x <= x1; x++)
			vbefb_putch_xy(x, y, ' ', attr);
	} else {
		vga_fill_rect(x0, y, x1 - x0 + 1, 1, ' ', attr);
	}
}

void vga_clear_screen_attr(uint8_t attr) {
	if (cirrusfb_is_ready()) {
		cirrusfb_clear(attr);
		return;
	}
	if (vbe_is_available()) {
		vbefb_clear(attr);
		return;
	}
	uint8_t *vga = (uint8_t*)VIDEO_ADDRESS;
	uint32_t total = MAX_ROWS * MAX_COLS;
	for (uint32_t i = 0; i < total; i++) {
		vga[i*2] = ' ';
		vga[i*2 + 1] = attr;
	}
}

void vga_write_str_xy(uint32_t x, uint32_t y, const char *s, uint8_t attr) {
	if (y >= MAX_ROWS) return;
	uint32_t px = x;
	uint32_t py = y;
	unsigned long fl;
	acquire_irqsave(&vga_lock_spin, &fl);
	for (size_t i = 0; s[i]; i++) {
		if (px >= MAX_COLS) { px = 0; py++; }
		if (py >= MAX_ROWS) {
			/* perform scroll while holding lock */
			/* reuse existing scroll_line logic but inline to avoid double-lock */
			uint8_t i2 = 1;
			while (i2 < MAX_ROWS) {
				memcpy(
					(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * (i2-1) * 2)), /* dst <- src */
					(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * i2 * 2)),	 /* src */
					(MAX_COLS*2)
				);
				i2++;
			}
			uint16_t last_line = (MAX_COLS*MAX_ROWS*2) - MAX_COLS*2;
			for (uint32_t ii = 0; ii < MAX_COLS; ii++) {
				write_nolock('\0', WHITE_ON_BLACK, (uint16_t)(last_line + ii * 2));
			}
			set_cursor_nolock(last_line);
			py = MAX_ROWS - 1;
		}
		write_nolock((uint8_t)s[i], attr, (uint16_t)((py * MAX_COLS + px) * 2));
		px++;
	}
	release_irqrestore(&vga_lock_spin, fl);
}

void vga_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint8_t ch, uint8_t attr) {
	for (uint32_t ry = 0; ry < h; ry++) {
		if (y + ry >= MAX_ROWS) break;
		for (uint32_t rx = 0; rx < w; rx++) {
			if (x + rx >= MAX_COLS) break;
			vga_putch_xy(x + rx, y + ry, ch, attr);
		}
	}
}

uint32_t vga_write_colorized_xy(uint32_t x, uint32_t y, const char *s, uint8_t default_attr) {
	if (y >= MAX_ROWS) return 0;
	/* Color tags are no longer supported; print the string as-is. */
	(void)default_attr;
	vga_write_str_xy(x, y, s, GRAY_ON_BLACK);
	return (uint32_t)strlen(s);
}

void kprint(uint8_t *str) {
	if (!str) return;
	unsigned long fl;
	acquire_irqsave(&vga_lock_spin, &fl);
	while (*str) console_putc_nolock(*str++, GRAY_ON_BLACK);
	release_irqrestore(&vga_lock_spin, fl);
}

static void kputchar_vga_text_nolock(uint8_t character, uint8_t attribute_byte)
{
	uint16_t offset = get_cursor_nolock();
	if (character == '\r')
	{
		/* Carriage return: move to start of current line. */
		set_cursor_nolock((uint16_t)(offset - (offset % (MAX_COLS * 2))));
	}
	if (character == '\n')
	{
		if ((offset / 2 / MAX_COLS) != (MAX_ROWS - 1))
			set_cursor_nolock((uint16_t)((offset - offset % (MAX_COLS*2)) + MAX_COLS*2));

		/* if we're on last line, perform scroll now */
		if ((offset / 2 / MAX_COLS) == (MAX_ROWS - 1)) {
			/* scroll */
			uint8_t i = 1;
			while (i < MAX_ROWS) {
				memcpy(
					(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * (i-1) * 2)), /* dst <- src */
					(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * i * 2)),	 /* src */
					(MAX_COLS*2)
				);
				i++;
			}
			uint16_t last_line = (MAX_COLS*MAX_ROWS*2) - MAX_COLS*2;
			for (uint32_t ii = 0; ii < MAX_COLS; ii++) {
				write_nolock('\0', WHITE_ON_BLACK, (uint16_t)(last_line + ii * 2));
			}
			set_cursor_nolock(last_line);
		}
	}
	else if (character == '\t')
	{
		// move to next tab stop (8 columns)
		uint16_t col = (uint16_t)((offset / 2) % MAX_COLS);
		uint16_t spaces = (uint16_t)(8 - (col % 8));
		for (uint16_t i = 0; i < spaces; i++) {
			if (offset == (MAX_COLS * MAX_ROWS * 2)) {
				/* scroll */
				uint8_t i2 = 1;
				while (i2 < MAX_ROWS) {
					memcpy(
						(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * (i2-1) * 2)),
						(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * i2 * 2)),
						(MAX_COLS*2)
					);
					i2++;
				}
				uint16_t last_line = (MAX_COLS*MAX_ROWS*2) - MAX_COLS*2;
				for (uint32_t ii = 0; ii < MAX_COLS; ii++) {
					write_nolock('\0', WHITE_ON_BLACK, (uint16_t)(last_line + ii * 2));
				}
				set_cursor_nolock(last_line);
				offset = last_line;
			}
			write_nolock(' ', attribute_byte, offset);
			offset += 2;
		}
		set_cursor_nolock(offset);
	}
	else if (character == '\b')
	{
		/* Move left one cell, clear it; do not wrap from column 0 to previous line.
		 * Use the cell's current attribute so the erased cell doesn't change color (TTY). */
		uint16_t col = (uint16_t)((offset / 2) % MAX_COLS);
		if (col > 0) {
			offset -= 2;
			{
				uint8_t *vga = (uint8_t *)VIDEO_ADDRESS;
				uint8_t attr = vga[offset + 1]; /* preserve existing cell attribute */
				write_nolock(' ', attr, offset);
			}
			set_cursor_nolock(offset);
		}
	}
	else
	{
		/* write char and handle end-of-line / scroll correctly */
		if (offset >= (MAX_COLS * MAX_ROWS * 2)) {
			/* scroll */
			uint8_t i = 1;
			while (i < MAX_ROWS) {
				memcpy(
					(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * (i-1) * 2)),
					(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * i * 2)),
					(MAX_COLS*2)
				);
				i++;
			}
			uint16_t last_line = (MAX_COLS*MAX_ROWS*2) - MAX_COLS*2;
			for (uint32_t ii = 0; ii < MAX_COLS; ii++) {
				write_nolock('\0', WHITE_ON_BLACK, (uint16_t)(last_line + ii * 2));
			}
			/* reset offset to start of last line */
			offset = (MAX_ROWS - 1) * MAX_COLS * 2;
		}
		write_nolock(character, attribute_byte, offset);
		uint32_t new_offset = offset + 2;
		if (new_offset >= (MAX_COLS * MAX_ROWS * 2)) {
			/* writing past the last cell: scroll and set cursor to start of last line */
			uint8_t i = 1;
			while (i < MAX_ROWS) {
				memcpy(
					(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * (i-1) * 2)),
					(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * i * 2)),
					(MAX_COLS*2)
				);
				i++;
			}
			uint16_t last_line = (MAX_COLS*MAX_ROWS*2) - MAX_COLS*2;
			for (uint32_t ii = 0; ii < MAX_COLS; ii++) {
				write_nolock('\0', WHITE_ON_BLACK, (uint16_t)(last_line + ii * 2));
			}
			set_cursor_nolock((uint16_t)((MAX_ROWS - 1) * MAX_COLS * 2));
		} else {
			set_cursor_nolock((uint16_t)new_offset);
		}
	}
}

/* One character worth of output without taking vga_lock_spin (caller must hold lock). */
static void console_putc_nolock(uint8_t character, uint8_t attribute_byte)
{
	if (cirrusfb_is_ready()) { cirrusfb_putchar(character, attribute_byte); return; }
	if (vbe_is_available()) { vbefb_putchar(character, attribute_byte); return; }
	if (vga_text_ansi_feed_nolock(character, attribute_byte))
		return;
	kputchar_vga_text_nolock(character, attribute_byte);
}

static void kputn_nolock(char ch, int count, uint8_t color)
{
	for (int i = 0; i < count; i++)
		console_putc_nolock((uint8_t)ch, color);
}

void kputchar(uint8_t character, uint8_t attribute_byte)
{
	unsigned long fl;
	acquire_irqsave(&vga_lock_spin, &fl);
	console_putc_nolock(character, attribute_byte);
	release_irqrestore(&vga_lock_spin, fl);
}

void kprint_colorized(const char* str)
{
	/* Color tags removed: print text literally using default color. */
	kprint((uint8_t*)str);
}

void	scroll_line()
{
	unsigned long fl;
	acquire_irqsave(&vga_lock_spin, &fl);
	uint8_t i = 1;
	uint16_t last_line;

	while (i < MAX_ROWS)
	{
		memcpy(
			(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * (i-1) * 2)), /* dst <- src */
			(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * i * 2)),	 /* src */
			(MAX_COLS*2)
		);
		i++;
	}

	last_line = (MAX_COLS*MAX_ROWS*2) - MAX_COLS*2;
	i = 0;
	while (i < MAX_COLS)
	{
		write_nolock('\0', WHITE_ON_BLACK, (uint16_t)(last_line + i * 2));
		i++;
	}
	set_cursor_nolock(last_line);
	release_irqrestore(&vga_lock_spin, fl);
}

void	kclear()
{
	if (cirrusfb_is_ready()) {
		cirrusfb_clear(WHITE_ON_BLACK);
	} else if (vbe_is_available()) {
		vbefb_clear(WHITE_ON_BLACK);
	} else {
	uint16_t	offset = 0;
	while (offset < (MAX_ROWS * MAX_COLS * 2))
	{
		write('\0', WHITE_ON_BLACK, offset);
		offset += 2;
	}
	set_cursor(0);
	}

	/* Sync devfs TTY cursor to (0,0) so interactive programs don't overwrite.
	   kclear is a "global clear" primitive and should affect the active tty. */
	{
		struct devfs_tty *tty = devfs_get_tty_by_index(devfs_get_active());
		if (tty) {
			tty->cursor_x = 0;
			tty->cursor_y = 0;
		}
	}
	console_set_cursor(0, 0);
}

void kclear_col(uint8_t attribute_byte)
{
	uint16_t offset = 0;
	while (offset < (MAX_ROWS * MAX_COLS * 2))
	{
		write('\0', attribute_byte, offset);
		offset += 2;
	}
	set_cursor(0);
}

void	write(uint8_t character, uint8_t attribute_byte, uint16_t offset)
{
	unsigned long fl;
	acquire_irqsave(&vga_lock_spin, &fl);
	write_nolock(character, attribute_byte, offset);
	release_irqrestore(&vga_lock_spin, fl);
}

uint16_t		get_cursor()
{
	unsigned long fl;
	acquire_irqsave(&vga_lock_spin, &fl);
	uint16_t r = get_cursor_nolock();
	release_irqrestore(&vga_lock_spin, fl);
	return r;
}

void	set_cursor(uint16_t pos)
{
	unsigned long fl;
	acquire_irqsave(&vga_lock_spin, &fl);
	set_cursor_nolock(pos);
	release_irqrestore(&vga_lock_spin, fl);
}

// Получить текущую позицию курсора по X
uint16_t get_cursor_x() {
	uint16_t offset = get_cursor();
	return offset % (MAX_COLS * 2);
}

// Получить текущую позицию курсора по Y
uint16_t get_cursor_y() {
	uint16_t offset = get_cursor();
	return offset / (MAX_COLS * 2);
}

// Установить позицию курсора по X
void set_cursor_x(uint16_t x) {
	uint16_t offset = get_cursor();
	uint16_t new_offset = (offset / (MAX_COLS * 2)) * (MAX_COLS * 2) + x * 2;
	set_cursor(new_offset);
}

// Установить позицию курсора по Y
void set_cursor_y(uint16_t y) {
	uint16_t offset = get_cursor();
	uint16_t new_offset = (y * MAX_COLS * 2) + (offset % (MAX_COLS * 2));
	set_cursor(new_offset);
}

void hex_to_str(uint32_t num, char *str);
void hex_to_str(uint32_t num, char *str) {
	int i = 0;
	
	if (num == 0) {
		str[i++] = '0';
		str[i] = '\0';
		return;
	}

	while (num != 0) {
		uint32_t rem = num % 16;
		if (rem < 10) {
			str[i++] = rem + '0';
		} else {
			str[i++] = (rem - 10) + 'A';
		}
		num = num / 16;
	}

	str[i] = '\0';

	// Reverse the string
	int start = 0;
	int end = i - 1;
	while (start < end) {
		char temp = str[start];
		str[start] = str[end];
		str[end] = temp;
		start++;
		end--;
	}
}

static uint8_t parse_color_code(char bg, char fg) {
	uint8_t background = 0;
	uint8_t foreground = 0;
	
	// Преобразование шестнадцатеричного символа в число
	if (bg >= '0' && bg <= '9') {
		background = bg - '0';
	} else if (bg >= 'a' && bg <= 'f') {
		background = bg - 'a' + 0xa;
	} else if (bg >= 'A' && bg <= 'F') {
		background = bg - 'A' + 0xa;
	}

	if (fg >= '0' && fg <= '9') {
		foreground = fg - '0';
	} else if (fg >= 'a' && fg <= 'f') {
		foreground = fg - 'a' + 0xa;
	} else if (fg >= 'A' && fg <= 'F') {
		foreground = fg - 'A' + 0xa;
	}
	
	return (background << 4) | foreground;
}

void ftos(double n, char *buf, int precision) {
	int i = 0;
	int sign = 1;
	if (n < 0) {
		sign = -1;
		n = -n;
	}

	double integer_part = (int)n;
	double fractional_part = n - integer_part;

	// Вывод целой части
	while (integer_part > 0) {
		buf[i++] = ((int)integer_part % 10) + '0';
		integer_part /= 10;
	}

	// Вывод точки
	buf[i++] = '.';

	// Вывод дробной части
	for (int j = 0; j < precision; j++) {
		fractional_part *= 10;
		buf[i++] = (int)fractional_part + '0';
		fractional_part -= (int)fractional_part;
	}

	// Добавление знака
	if (sign == -1) {
		buf[i++] = '-';
	}

	// Обратная запись строки
	for (int j = 0; j < i / 2; j++) {
		char temp = buf[j];
		buf[j] = buf[i - j - 1];
		buf[i - j - 1] = temp;
	}

	buf[i] = '\0';
}

static int utoa_rev(unsigned long long v, unsigned base, int upper, char *out)
{
	const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	int n = 0;
	if (v == 0) { out[n++] = '0'; return n; }
	while (v) { out[n++] = digits[v % base]; v /= base; }
	return n;
}

/* kprintf may bypass devfs tty writes; keep active tty cursor in sync.
   Caller must hold vga_lock_spin. We set/get cursor once per kprintf to avoid
   early-boot backend quirks around frequent cursor I/O. */
static inline void kprintf_putc_locked(struct devfs_tty *tty, uint8_t ch, uint8_t color) {
	(void)tty;
	console_putc_nolock(ch, color);
}

static inline void kprintf_putn_locked(struct devfs_tty *tty, uint8_t ch, int count, uint8_t color) {
	(void)tty;
	for (int i = 0; i < count; i++) console_putc_nolock(ch, color);
}

void kprintf(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	uint8_t color = 0x07; // светло-серый на чёрном
	unsigned long vga_fl;
	acquire_irqsave(&vga_lock_spin, &vga_fl);
	/* Keep devfs active tty cursor in sync, same motivation as klogprintf:
	   kernel prints must not desync interactive tty cursor. */
	struct devfs_tty *tty = NULL;
	if (devfs_is_ready()) {
		tty = devfs_get_tty_by_index(devfs_get_active());
		if (tty) console_set_cursor(tty->cursor_x, tty->cursor_y);
	}
	for (const char *p = fmt; *p; ) {
		// Color tags are no longer supported; treat them as normal characters.
		// support tab character: move to next tab stop (8 columns) like Linux
		if (*p == '\t') {
			uint32_t cx = 0, cy = 0;
			if (cirrusfb_is_ready()) cirrusfb_get_cursor(&cx, &cy);
			else if (vbe_is_available()) vbefb_get_cursor(&cx, &cy);
			else {
				uint16_t pos = get_cursor_nolock();
				cx = (uint32_t)((pos % (MAX_COLS * 2)) / 2);
				cy = (uint32_t)(pos / (MAX_COLS * 2));
			}
			uint32_t spaces = 8u - (cx % 8u);
			if (spaces == 0) spaces = 8;
			kprintf_putn_locked(tty, ' ', (int)spaces, color);
			p++; continue;
		}

		if (*p != '%') { kprintf_putc_locked(tty, (uint8_t)*p++, color); continue; }
 		p++;
		// flags
 		int left = 0, plus = 0, space = 0, alt = 0, zero = 0;
 		for (;;){
 			if (*p == '-') { left = 1; p++; }
 			else if (*p == '+') { plus = 1; p++; }
 			else if (*p == ' ') { space = 1; p++; }
 			else if (*p == '#') { alt = 1; p++; }
 			else if (*p == '0') { zero = 1; p++; }
 			else break;
 		}
 		// width
 		int width = 0;
 		if (*p == '*') { width = va_arg(ap, int); p++; }
 		else while (*p >= '0' && *p <= '9') { width = width*10 + (*p++ - '0'); }
 		// precision
 		int prec = -1;
 		if (*p == '.') {
 			p++;
 			if (*p == '*') { prec = va_arg(ap, int); p++; }
 			else { prec = 0; while (*p >= '0' && *p <= '9') prec = prec*10 + (*p++ - '0'); }
 		}
 		// совместимость с нестандартным %10-4x (ширина-точность)
 		if (prec < 0 && *p == '-') {
 			p++;
 			prec = 0; while (*p >= '0' && *p <= '9') prec = prec*10 + (*p++ - '0');
 		}
 		// length (минимальный набор)
 		enum { LEN_DEF, LEN_HH, LEN_H, LEN_L, LEN_LL, LEN_Z } len = LEN_DEF;
 		if (*p == 'h') { p++; if (*p == 'h') { len = LEN_HH; p++; } else len = LEN_H; }
 		else if (*p == 'l') { p++; if (*p == 'l') { len = LEN_LL; p++; } else len = LEN_L; }
 		else if (*p == 'z') { len = LEN_Z; p++; }

 		char spec = *p ? *p++ : '\0';
 		char tmp[64];
 		int tmplen = 0;
 		int negative = 0;
 		char signch = 0;

 		switch (spec) {
 		case 'c': {
 			int ch = va_arg(ap, int);
 			int pad = (width > 1) ? width - 1 : 0;
 			if (!left) kprintf_putn_locked(tty, ' ', pad, color);
 			kprintf_putc_locked(tty, (uint8_t)ch, color);
 			if (left) kprintf_putn_locked(tty, ' ', pad, color);
 			break; }

 		case 's': {
 			const char *s = va_arg(ap, const char*);
 			if (!s) s = "(null)";
 			int slen = 0; while (s[slen]) slen++;
 			if (prec >= 0 && prec < slen) slen = prec;
 			int pad = (width > slen) ? width - slen : 0;
 			if (!left) kprintf_putn_locked(tty, ' ', pad, color);
 			for (int i = 0; i < slen; i++) kprintf_putc_locked(tty, (uint8_t)s[i], color);
 			if (left) kprintf_putn_locked(tty, ' ', pad, color);
 			break; }

 		case 'd': case 'i': {
 			long long v;
 			if (len == LEN_LL) v = va_arg(ap, long long);
 			else if (len == LEN_L) v = va_arg(ap, long);
 			else v = va_arg(ap, int);
 			unsigned long long u = (v < 0) ? (unsigned long long)(-v) : (unsigned long long)v;
 			negative = (v < 0);
 			tmplen = utoa_rev(u, 10, 0, tmp);
 			signch = negative ? '-' : (plus ? '+' : (space ? ' ' : 0));
 			goto PRINT_NUMBER_BASE10;
 		}

 		case 'u': case 'x': case 'X': case 'o': case 'p': {
 			unsigned base = 10; int upper = 0;
 			unsigned long long u;
 			if (spec == 'p') { u = (unsigned long long)(uintptr_t)va_arg(ap, void*); base = 16; alt = 1; }
 			else {
 				if (len == LEN_LL) u = va_arg(ap, unsigned long long);
 				else if (len == LEN_L) u = va_arg(ap, unsigned long);
 				else if (len == LEN_Z) u = va_arg(ap, size_t);
 				else u = va_arg(ap, unsigned int);
 				if (spec == 'x' || spec == 'X') { base = 16; upper = (spec == 'X'); }
 				else if (spec == 'o') { base = 8; }
 			}
 			tmplen = utoa_rev(u, base, upper, tmp);
 			signch = 0;

 			// точность для целых
 			int num_digits = tmplen;
 			int prec_zeros = 0;
 			if (prec >= 0) {
 				zero = 0; // при точности флаг 0 игнорируется
 				if (prec > num_digits) prec_zeros = prec - num_digits;
 			}

 			// префиксы
 			char prefix[2]; int plen = 0;
 			if (alt && base == 16 && u != 0) { prefix[0] = '0'; prefix[1] = (upper ? 'X' : 'x'); plen = 2; }
 			else if (alt && base == 8 && (u != 0 || prec == 0)) { prefix[0] = '0'; plen = 1; }

 			int field_len = plen + prec_zeros + num_digits;
 			int pad = (width > field_len) ? width - field_len : 0;
 			char padch = (zero && !left) ? '0' : ' ';

 			if (!left && padch == ' ') kputn_nolock(' ', pad, color);
 			// вывод префикса/нулями заполнение
 			if (!left && padch == '0') kputn_nolock('0', pad, color);
 			if (plen) { for (int i = 0; i < plen; i++) console_putc_nolock(prefix[i], color); }
 			kputn_nolock('0', prec_zeros, color);
 			for (int i = num_digits - 1; i >= 0; i--) console_putc_nolock(tmp[i], color);
 			if (left) kputn_nolock(' ', pad, color);
 			break; }

 		case '%':
 			console_putc_nolock('%', color);
 			break;

 		default:
			kprintf_putc_locked(tty, (uint8_t)spec, color);
 			break;

PRINT_NUMBER_BASE10:
 		{
 			int num_digits = tmplen;
 			int prec_zeros = 0;
 			if (prec >= 0) { zero = 0; if (prec > num_digits) prec_zeros = prec - num_digits; }
 			int sign_len = signch ? 1 : 0;
 			int field_len = sign_len + prec_zeros + num_digits;
 			int pad = (width > field_len) ? width - field_len : 0;
 			char padch = (zero && !left) ? '0' : ' ';
			if (!left && padch == ' ' ) kprintf_putn_locked(tty, ' ', pad, color);
			if (signch) kprintf_putc_locked(tty, (uint8_t)signch, color);
			if (!left && padch == '0') kprintf_putn_locked(tty, '0', pad, color);
			kprintf_putn_locked(tty, '0', prec_zeros, color);
			for (int i = num_digits - 1; i >= 0; i--) kprintf_putc_locked(tty, (uint8_t)tmp[i], color);
			if (left) kprintf_putn_locked(tty, ' ', pad, color);
 			break;
 		}
 		}
 	}
	if (tty) console_get_cursor(&tty->cursor_x, &tty->cursor_y);

	release_irqrestore(&vga_lock_spin, vga_fl);
	va_end(ap);
}

void vga_set_cursor(uint32_t x, uint32_t y) {
	if (cirrusfb_is_ready()) { cirrusfb_set_cursor(x, y); return; }
	if (vbe_is_available()) { vbefb_set_cursor(x, y); return; }
	set_cursor_x((uint16_t)x);
	set_cursor_y((uint16_t)y);
}

void vga_get_cursor(uint32_t* x, uint32_t* y) {
	if (cirrusfb_is_ready()) { cirrusfb_get_cursor(x, y); return; }
	if (vbe_is_available()) { vbefb_get_cursor(x, y); return; }
	uint16_t pos = get_cursor();
	if (x) *x = (pos % (MAX_COLS * 2)) / 2;
	if (y) *y = pos / (MAX_COLS * 2);
}

uint16_t cell_offset(uint8_t x, uint8_t y) {
	return (uint16_t)((y * MAX_COLS + x) * 2);
}

void draw_cell(uint8_t x, uint8_t y, uint8_t ch, uint8_t color) {
	write(ch, color, cell_offset(x, y));
}

void draw_text(uint8_t x, uint8_t y, const char* s, uint8_t color) {
	for (uint8_t i = 0; s[i]; i++) draw_cell(x + i, y, (uint8_t)s[i], color);
}

/* Set hardware cursor shape (scanline start/end). */
void set_cursor_shape(uint8_t start, uint8_t end) {
	outb(REG_SCREEN_CTRL, 0x0A);
	outb(REG_SCREEN_DATA, start & 0x1F);
	outb(REG_SCREEN_CTRL, 0x0B);
	outb(REG_SCREEN_DATA, end & 0x1F);
}

// ---- minimal printf-to-buffer (vsnprintf/snprintf/sprintf) ----
typedef struct { char* buf; size_t cap; size_t len; } __bufw;
static void __bw_putc(__bufw* w, char ch) {
	if (w->len + 1 < w->cap) w->buf[w->len] = ch;
	w->len++;
}

static void __bw_putn(__bufw* w, char ch, int count) {
	for (int i = 0; i < count; i++) __bw_putc(w, ch);
}

static void __bw_putstrn(__bufw* w, const char* s, int slen) {
	for (int i = 0; i < slen; i++) __bw_putc(w, s[i]);
}

int __vsnprintf(char* out, size_t outsz, const char* fmt, va_list ap_in) {
	if (!out || outsz==0) return 0;
	__bufw W = { .buf = out, .cap = outsz, .len = 0 };
	va_list ap; va_copy(ap, ap_in);
	for (const char *p = fmt; *p; ) {
		if (*p != '%') { __bw_putc(&W, *p++); continue; }
		p++;

		/* flags */
		int left = 0, plus = 0, space = 0, alt = 0, zero = 0;
		for (;;) {
			if (*p == '-') { left = 1; p++; }
			else if (*p == '+') { plus = 1; p++; }
			else if (*p == ' ') { space = 1; p++; }
			else if (*p == '#') { alt = 1; p++; }
			else if (*p == '0') { zero = 1; p++; }
			else break;
		}

		/* width */
		int width = 0;
		if (*p == '*') { width = va_arg(ap, int); p++; }
		else while (*p >= '0' && *p <= '9') { width = width * 10 + (*p++ - '0'); }
		if (width < 0) { left = 1; width = -width; }

		/* precision */
		int prec = -1;
		if (*p == '.') {
			p++;
			if (*p == '*') { prec = va_arg(ap, int); p++; }
			else { prec = 0; while (*p >= '0' && *p <= '9') prec = prec * 10 + (*p++ - '0'); }
		}

		/* length */
		enum { LEN_DEF, LEN_HH, LEN_H, LEN_L, LEN_LL, LEN_Z } len = LEN_DEF;
		if (*p == 'h') { p++; if (*p == 'h') { len = LEN_HH; p++; } else len = LEN_H; }
		else if (*p == 'l') { p++; if (*p == 'l') { len = LEN_LL; p++; } else len = LEN_L; }
		else if (*p == 'z') { len = LEN_Z; p++; }

		char spec = *p ? *p++ : '\0';

		char num[64];
		int n = 0;

		switch (spec) {
		case 'c': {
			int ch = va_arg(ap, int);
			int pad = (width > 1) ? width - 1 : 0;
			if (!left) __bw_putn(&W, ' ', pad);
			__bw_putc(&W, (char)ch);
			if (left) __bw_putn(&W, ' ', pad);
			break; }

		case 's': {
			const char *s = va_arg(ap, const char*);
			if (!s) s = "(null)";
			int slen = 0; while (s[slen]) slen++;
			if (prec >= 0 && prec < slen) slen = prec;
			int pad = (width > slen) ? width - slen : 0;
			if (!left) __bw_putn(&W, ' ', pad);
			__bw_putstrn(&W, s, slen);
			if (left) __bw_putn(&W, ' ', pad);
			break; }

			case 'd': case 'i': {
			long long v;
			if (len == LEN_LL) v = va_arg(ap, long long);
			else if (len == LEN_L) v = va_arg(ap, long);
			else if (len == LEN_Z) v = (long long)va_arg(ap, size_t);
			else v = va_arg(ap, int);
			unsigned long long u = (v < 0) ? (unsigned long long)(-v) : (unsigned long long)v;
			n = utoa_rev(u, 10, 0, num);
			char signch = 0;
			if (v < 0) signch = '-';
			else if (plus) signch = '+';
			else if (space) signch = ' ';
			int digits = n;
			int tot = digits + (signch ? 1 : 0);
			int pad = (width > tot) ? width - tot : 0;
			char padch = (zero && !left && prec < 0) ? '0' : ' ';
			if (!left) __bw_putn(&W, padch, pad);
			if (signch) __bw_putc(&W, signch);
			for (int i = n - 1; i >= 0; i--) __bw_putc(&W, num[i]);
			if (left) __bw_putn(&W, ' ', pad);
			break; }

			case 'u': case 'x': case 'X': {
			unsigned base = (spec == 'u') ? 10u : 16u;
			int upper = (spec == 'X');
			unsigned long long u;
			if (len == LEN_LL) u = va_arg(ap, unsigned long long);
			else if (len == LEN_L) u = va_arg(ap, unsigned long);
			else if (len == LEN_Z) u = (unsigned long long)va_arg(ap, size_t);
			else u = va_arg(ap, unsigned int);
			n = utoa_rev(u, base, upper, num);
			int prefix = 0;
			if (alt && base == 16 && u != 0) prefix = 2;
			int tot = n + prefix;
			int pad = (width > tot) ? width - tot : 0;
			char padch = (zero && !left && prec < 0) ? '0' : ' ';
			if (!left) __bw_putn(&W, padch, pad);
			if (prefix) { __bw_putc(&W, '0'); __bw_putc(&W, upper ? 'X' : 'x'); }
			for (int i = n - 1; i >= 0; i--) __bw_putc(&W, num[i]);
			if (left) __bw_putn(&W, ' ', pad);
			break; }

		case 'p': {
			void *pv = va_arg(ap, void*);
			unsigned long long u = (unsigned long long)(uintptr_t)pv;
			n = utoa_rev(u, 16, 0, num);
			/* always 0x prefix */
			int tot = n + 2;
			int pad = (width > tot) ? width - tot : 0;
			if (!left) __bw_putn(&W, ' ', pad);
			__bw_putc(&W, '0'); __bw_putc(&W, 'x');
			for (int i = n - 1; i >= 0; i--) __bw_putc(&W, num[i]);
			if (left) __bw_putn(&W, ' ', pad);
			break; }

		case '%': __bw_putc(&W, '%'); break;
		default:
			/* unknown specifier: print it literally to avoid desync */
			__bw_putc(&W, '%');
			__bw_putc(&W, spec);
				break;
		}
	}
	// NUL
	if (W.len < W.cap) W.buf[W.len] = '\0'; else W.buf[W.cap-1] = '\0';
	va_end(ap);
	return (int)W.len;
}

void enable_cursor() {
	outb(0x3D4, 0x0A);
	char curstart = inb(0x3D5) & 0x1F; // cursor scanline start (bits 0-4)

	// Clear bit 5 (cursor disable) to enable the cursor
	outb(0x3D4, 0x0A);
	outb(0x3D5, (curstart & ~0x20));

	// custom shape!
	set_cursor_shape(14, 15);
}

int vsnprintf(char* out, size_t outsz, const char* fmt, va_list ap) { return __vsnprintf(out, outsz, fmt, ap); }
int snprintf(char* out, size_t outsz, const char* fmt, ...) { va_list ap; va_start(ap, fmt); int r=__vsnprintf(out,outsz,fmt,ap); va_end(ap); return r; }
int sprintf(char* out, const char* fmt, ...) { va_list ap; va_start(ap, fmt); int r=__vsnprintf(out,(size_t)-1,fmt,ap); va_end(ap); return r; }