#include <stdint.h>
#include <serial.h>
#include <vga.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>

static uint8_t parse_color_code(char bg, char fg);

/* Fast direct VGA helpers */
void vga_putch_xy(uint32_t x, uint32_t y, uint8_t ch, uint8_t attr) {
    uint8_t *vga = (uint8_t*)VIDEO_ADDRESS;
    if (x >= MAX_COLS || y >= MAX_ROWS) return;
    uint32_t off = (y * MAX_COLS + x) * 2;
    vga[off] = ch;
    vga[off + 1] = attr;
}

void vga_clear_screen_attr(uint8_t attr) {
    uint8_t *vga = (uint8_t*)VIDEO_ADDRESS;
    uint32_t total = MAX_ROWS * MAX_COLS;
    for (uint32_t i = 0; i < total; i++) {
        vga[i*2] = ' ';
        vga[i*2 + 1] = attr;
    }
}

void vga_write_str_xy(uint32_t x, uint32_t y, const char *s, uint8_t attr) {
    uint8_t *vga = (uint8_t*)VIDEO_ADDRESS;
    if (y >= MAX_ROWS) return;
    uint32_t off = (y * MAX_COLS + x) * 2;
    for (size_t i = 0; s[i] && (x + i) < MAX_COLS; i++) {
        vga[off + i*2] = (uint8_t)s[i];
        vga[off + i*2 + 1] = attr;
    }
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
    uint8_t color = default_attr;
    uint32_t vx = 0;
    const char* p = s;
    while (*p && (x + vx) < MAX_COLS) {
        size_t ahead = strnlen(p, 6);
        if (ahead >= 6 && p[0] == '<' && p[1] == '(' && p[4] == ')' && p[5] == '>') {
            color = parse_color_code(p[2], p[3]);
            p += 6;
            continue;
        }
        vga_putch_xy(x + vx, y, (uint8_t)*p++, color);
        vx++;
    }
    return vx;
}

void	kprint(uint8_t *str)
{
	while (*str)
	{
		kputchar(*str, GRAY_ON_BLACK);
		str++;
	}
}

void	kputchar(uint8_t character, uint8_t attribute_byte)
{
	uint16_t offset;

	offset = get_cursor();
	if (character == '\n')
	{
		if ((offset / 2 / MAX_COLS) == (MAX_ROWS - 1)) 
			scroll_line();
		else
			set_cursor((offset - offset % (MAX_COLS*2)) + MAX_COLS*2);
	}
	else if (character == '\b')
    {
        set_cursor(get_cursor() - 1);
        kputchar(' ', attribute_byte);
        set_cursor(get_cursor() - 2);
    }
	else 
	{
		if (offset == (MAX_COLS * MAX_ROWS * 2)) scroll_line();
		write(character, attribute_byte, offset);
		set_cursor(offset+2);
	}
}

void kprint_colorized(const char* str)
{
    uint8_t color = 0x07;
    const char* p = str;
    while (*p) {
        // Чтобы исключить чтение за пределы буфера, проверяем доступную длину вперёд
        // и лишь затем считаем это цветовым тегом.
        size_t ahead = strnlen(p, 6);
        if (ahead >= 6 && p[0] == '<' && p[1] == '(' && p[4] == ')' && p[5] == '>') {
            color = parse_color_code(p[2], p[3]);
            p += 6;
            continue;
        }
        kputchar(*p++, color);
    }
}

void	scroll_line()
{
	uint8_t i = 1;
	uint16_t last_line;

	while (i < MAX_ROWS)
	{
		memcpy(
			(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * (i-1) * 2)), /* src */
			(uint8_t *)(VIDEO_ADDRESS + (MAX_COLS * i * 2)),     /* dst */
			(MAX_COLS*2)
		);
		i++;
	}

	last_line = (MAX_COLS*MAX_ROWS*2) - MAX_COLS*2;
	i = 0;
	while (i < MAX_COLS)
	{
		write('\0', WHITE_ON_BLACK, (last_line + i * 2));
		i++;
	}
	set_cursor(last_line);
}

void	kclear()
{
	uint16_t	offset = 0;
	while (offset < (MAX_ROWS * MAX_COLS * 2))
	{
		write('\0', WHITE_ON_BLACK, offset);
		offset += 2;
	}
	set_cursor(0);
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
	uint8_t *vga = (uint8_t *) VIDEO_ADDRESS;
	vga[offset] = character;
	vga[offset + 1] = attribute_byte;
}

uint16_t		get_cursor()
{
	outb(REG_SCREEN_CTRL, 14);
	uint8_t high_byte = inb(REG_SCREEN_DATA);
	outb(REG_SCREEN_CTRL, 15);
	uint8_t low_byte = inb(REG_SCREEN_DATA);
	return (((high_byte << 8) + low_byte) * 2);
}

void	set_cursor(uint16_t pos)
{
	pos /= 2;
	outb(REG_SCREEN_CTRL, 14);
	outb(REG_SCREEN_DATA, (uint8_t)(pos >> 8));
	outb(REG_SCREEN_CTRL, 15);
	outb(REG_SCREEN_DATA, (uint8_t)(pos & 0xff));
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

static void kputn(char ch, int count, uint8_t color)
{
	for (int i = 0; i < count; i++) kputchar(ch, color);
}

static int utoa_rev(unsigned long long v, unsigned base, int upper, char *out)
{
	const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	int n = 0;
	if (v == 0) { out[n++] = '0'; return n; }
	while (v) { out[n++] = digits[v % base]; v /= base; }
	return n;
}

void kprintf(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

    uint8_t color = 0x07; // светло-серый на чёрном
    for (const char *p = fmt; *p; ) {
        // inline цветовой код <(bgfg)> — два шестнадцатеричных символа
        if (*p == '<' && p[1] == '(' && p[2] && p[3] && p[4] == ')' && p[5] == '>') {
            color = parse_color_code(p[2], p[3]);
            p += 6;
            continue;
        }

        // support tab character: move to next tab stop (8 columns) like Linux
        if (*p == '\t') {
            uint32_t cx = 0, cy = 0;
            vga_get_cursor(&cx, &cy);
            uint32_t spaces = 8 - (cx % 8);
            if (spaces == 0) spaces = 8;
            kputn(' ', spaces, color);
            p++; continue;
        }

		if (*p != '%') { kputchar(*p++, color); continue; }
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
 			if (!left) kputn(' ', pad, color);
 			kputchar((char)ch, color);
 			if (left) kputn(' ', pad, color);
 			break; }

 		case 's': {
 			const char *s = va_arg(ap, const char*);
 			if (!s) s = "(null)";
 			int slen = 0; while (s[slen]) slen++;
 			if (prec >= 0 && prec < slen) slen = prec;
 			int pad = (width > slen) ? width - slen : 0;
 			if (!left) kputn(' ', pad, color);
 			for (int i = 0; i < slen; i++) kputchar(s[i], color);
 			if (left) kputn(' ', pad, color);
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

 			if (!left && padch == ' ') kputn(' ', pad, color);
 			// вывод префикса/нулями заполнение
 			if (!left && padch == '0') kputn('0', pad, color);
 			if (plen) { for (int i = 0; i < plen; i++) kputchar(prefix[i], color); }
 			kputn('0', prec_zeros, color);
 			for (int i = num_digits - 1; i >= 0; i--) kputchar(tmp[i], color);
 			if (left) kputn(' ', pad, color);
 			break; }

 		case '%':
 			kputchar('%', color);
 			break;

 		default:
 			kputchar(spec, color);
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
 			if (!left && padch == ' ' ) kputn(' ', pad, color);
 			if (signch) kputchar(signch, color);
 			if (!left && padch == '0') kputn('0', pad, color);
 			kputn('0', prec_zeros, color);
 			for (int i = num_digits - 1; i >= 0; i--) kputchar(tmp[i], color);
 			if (left) kputn(' ', pad, color);
 			break;
 		}
 		}
 	}

	va_end(ap);
}

void vga_set_cursor(uint32_t x, uint32_t y)
{
    set_cursor_x(x);
    set_cursor_y(y);
}

void vga_get_cursor(uint32_t* x, uint32_t* y)
{
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

// ---- minimal printf-to-buffer (vsnprintf/snprintf/sprintf) ----
typedef struct { char* buf; size_t cap; size_t len; } __bufw;
static void __bw_putc(__bufw* w, char ch) {
	if (w->len + 1 < w->cap) w->buf[w->len] = ch;
	w->len++;
}

static char tmp[64];

static int __vsnprintf(char* out, size_t outsz, const char* fmt, va_list ap_in) {
	if (!out || outsz==0) return 0;
	__bufw W = { .buf = out, .cap = outsz, .len = 0 };
	va_list ap; va_copy(ap, ap_in);
	for (const char *p = fmt; *p; ) {
		if (*p != '%') { __bw_putc(&W, *p++); continue; }
		p++;
		// flags (ignored mostly)
		while (*p=='-'||*p=='+'||*p==' '||*p=='#'||*p=='0') p++;
		// width
		if (*p=='*') { (void)va_arg(ap,int); p++; } else { while (*p>='0'&&*p<='9') p++; }
		// precision
		if (*p=='.') { p++; if (*p=='*'){ (void)va_arg(ap,int); p++; } else { while (*p>='0'&&*p<='9') p++; } }
		// length
		if (*p=='h'||*p=='l'||*p=='z') { if ((p[0]=='h'&&p[1]=='h')||(p[0]=='l'&&p[1]=='l')) p+=2; else p++; }
		char spec = *p ? *p++ : '\0'; int n=0;
		switch (spec) {
			case 'c': { int ch=va_arg(ap,int); __bw_putc(&W,(char)ch); break; }
			case 's': { const char* s=va_arg(ap,const char*); if(!s)s="(null)"; while(*s) __bw_putc(&W,*s++); break; }
			case 'd': case 'i': {
				long long v = va_arg(ap,int);
				unsigned long long u = (v<0)?(unsigned long long)(-v):(unsigned long long)v;
				if (u==0) tmp[n++]='0';
				while(u){ tmp[n++]=(char)('0'+(u%10)); u/=10; }
				if (v<0) __bw_putc(&W,'-');
				for (int i=n-1;i>=0;i--) __bw_putc(&W,tmp[i]);
				break;
			}
			case 'u': case 'x': case 'X': {
				unsigned base = (spec=='u')?10:16; int upper = (spec=='X');
				unsigned long long u = va_arg(ap,unsigned int);
				const char* D = upper?"0123456789ABCDEF":"0123456789abcdef";
				if (u==0) tmp[n++]='0';
				while(u){ tmp[n++]=D[u%base]; u/=base; }
				for (int i=n-1;i>=0;i--) __bw_putc(&W,tmp[i]);
				break;
			}
			case '%': __bw_putc(&W,'%'); break;
			default: __bw_putc(&W,spec); break;
		}
	}
	// NUL
	if (W.len < W.cap) W.buf[W.len] = '\0'; else W.buf[W.cap-1] = '\0';
	va_end(ap);
	return (int)W.len;
}

int vsnprintf(char* out, size_t outsz, const char* fmt, va_list ap) { return __vsnprintf(out, outsz, fmt, ap); }
int snprintf(char* out, size_t outsz, const char* fmt, ...) { va_list ap; va_start(ap, fmt); int r=__vsnprintf(out,outsz,fmt,ap); va_end(ap); return r; }
int sprintf(char* out, const char* fmt, ...) { va_list ap; va_start(ap, fmt); int r=__vsnprintf(out,(size_t)-1,fmt,ap); va_end(ap); return r; }