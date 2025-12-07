// AxonOS fullscreen text editor (Turbo Pascal-like)
#include "../inc/editor.h"
#include "../inc/vga.h"
#include "../inc/keyboard.h"
#include "../inc/fs.h"
#include "../inc/string.h"
#include "../inc/heap.h"
#include "../inc/axosh.h"
#include <stdint.h>

// ---- UI layout ----
#define VIEW_Y0 1
#define VIEW_H (MAX_ROWS - 2) // 1..23
#define VIEW_W (MAX_COLS)
#define TAB_WIDTH 4

// Темы оформления
typedef struct {
	const char *name;
	uint8_t menu_attr;
	uint8_t status_attr;
	uint8_t text_attr;
	uint8_t text_dim_attr;
} Theme;

static const Theme THEMES[] = {
	{"Classic",   0x78, 0x78, 0x8F, 0x87}, // white on blue menu, black on light gray status, white text, gray tildes
	{"Midnight",  0x17, 0x71, 0x1F, 0x19}, // white on navy, blue-ish status, bright text, dim blue tildes
	{"Solarized", 0x3F, 0xE0, 0x0E, 0x06}, // white on cyan menu, black on yellow status, yellow text, brown tildes
	{"Contrast",  0xF0, 0x0F, 0xF0, 0x70}, // black on white menu, white on black status, black on white text, dim gray
};
static const int THEME_COUNT = sizeof(THEMES)/sizeof(THEMES[0]);
static int g_theme_index = 0;
static uint8_t g_attr_menu = 0x78;
static uint8_t g_attr_status = 0x78;
static uint8_t g_attr_text = 0x8F;
static uint8_t g_attr_text_dim = 0x87;

// View cache to avoid flicker (only update changed cells)
static uint16_t g_view_cache[VIEW_H][VIEW_W];
static int g_view_cache_valid = 0;

static inline void view_cache_invalidate(void) { g_view_cache_valid = 0; }
static inline void view_cache_invalidate_row_idx(int idx) {
    if (idx < 0 || idx >= VIEW_H) return;
    for (uint32_t x = 0; x < VIEW_W; x++) g_view_cache[idx][x] = 0xFFFF;
    g_view_cache_valid = 1; // keep valid but row invalidated
}
static inline void view_cache_invalidate_line_with_viewtop(int view_top, int row) {
    int v = row - view_top;
    view_cache_invalidate_row_idx(v);
}

static void apply_theme(int idx) {
	if (idx < 0) idx = 0; if (idx >= THEME_COUNT) idx = THEME_COUNT - 1;
	g_theme_index = idx;
	// mask out VGA blink bit (bit7) to avoid VMware blinking/flicker
	g_attr_menu = (uint8_t)(THEMES[idx].menu_attr & 0x7F);
	g_attr_status = (uint8_t)(THEMES[idx].status_attr & 0x7F);
	g_attr_text = (uint8_t)(THEMES[idx].text_attr & 0x7F);
    g_attr_text_dim = (uint8_t)(THEMES[idx].text_dim_attr & 0x7F);
    view_cache_invalidate();
}

static void cycle_theme(void) { int ni = g_theme_index + 1; if (ni >= THEME_COUNT) ni = 0; apply_theme(ni); }

typedef struct {
	char *data;
	size_t len;
	size_t cap;
} Line;

typedef struct {
	Line *lines;
	int line_count;
	int line_cap;

	int cursor_row; // 0-based in buffer
	int cursor_col; // 0-based in line
	int view_top;   // first visible buffer row
	int view_left;  // first visible buffer column (for horizontal scrolling)

	int insert_mode; // 1 insert, 0 overwrite
	int modified;

	char filename[256];
    int syntax_mode; // 0 - none, 1 - asm, 2 - osh
} Editor;

static void ui_draw_menu(void);
static void ui_draw_status(Editor *E, const char *msg);
static void ui_draw_view(Editor *E);
static void ui_place_cursor(Editor *E);
static void ensure_cursor_visible(Editor *E);

static void buf_init(Editor *E);
static void buf_free(Editor *E);
static void buf_clear(Editor *E);
static void buf_ensure_lines(Editor *E, int need);
static void line_reserve(Line *L, size_t need_cap);
static void buf_insert_char(Editor *E, int r, int c, char ch);
static void buf_overwrite_char(Editor *E, int r, int c, char ch);
static void buf_delete_char(Editor *E, int r, int c);
static void buf_backspace(Editor *E);
static void buf_newline(Editor *E);
static void buf_join_with_next(Editor *E, int r);

static int prompt_input(const char *title, char *out, int out_size, const char *initial);
static int file_load(Editor *E, const char *path);
static int file_save(Editor *E, const char *path);

// ---- Syntax highlighting (ASM) ----
static void editor_update_syntax(Editor *E);
static void draw_line_text_asm(uint32_t y, const char *s, size_t len);
static void draw_line_text_osh(uint32_t y, const char *s, size_t len);

// ---- Buffer management ----
static void buf_init(Editor *E) {
	E->lines = (Line*)kcalloc(16, sizeof(Line));
	E->line_cap = 16;
	E->line_count = 1;
	E->cursor_row = 0;
	E->cursor_col = 0;
	E->view_top = 0;
	E->view_left = 0;
	E->insert_mode = 1;
	E->modified = 0;
	E->filename[0] = '\0';
    E->syntax_mode = 0;
	E->lines[0].data = (char*)kcalloc(64, 1);
	E->lines[0].len = 0;
	E->lines[0].cap = 64;
}

static void buf_free(Editor *E) {
	if (!E->lines) return;
	for (int i = 0; i < E->line_count; i++) if (E->lines[i].data) kfree(E->lines[i].data);
	kfree(E->lines);
	E->lines = 0; E->line_count = E->line_cap = 0;
}

static void buf_clear(Editor *E) {
	for (int i = 0; i < E->line_count; i++) if (E->lines[i].data) { kfree(E->lines[i].data); E->lines[i].data = 0; }
	E->line_count = 1;
	E->lines[0].data = (char*)kcalloc(64, 1);
	E->lines[0].len = 0;
	E->lines[0].cap = 64;
	E->cursor_row = 0; E->cursor_col = 0; E->view_top = 0; E->view_left = 0; E->modified = 0;
}

static void buf_ensure_lines(Editor *E, int need) {
	if (need <= E->line_cap) return;
	int cap = E->line_cap ? E->line_cap : 16;
	while (cap < need) cap *= 2;
	Line *nl = (Line*)kcalloc(cap, sizeof(Line));
	for (int i=0;i<E->line_count;i++) nl[i] = E->lines[i];
	kfree(E->lines);
	E->lines = nl;
	E->line_cap = cap;
}

static void line_reserve(Line *L, size_t need_cap) {
	if (need_cap <= L->cap) return;
	size_t cap = L->cap ? L->cap : 16;
	while (cap < need_cap) cap *= 2;
	char *nd = (char*)kcalloc(cap, 1);
	if (L->data && L->len) memcpy(nd, L->data, L->len);
	if (L->data) kfree(L->data);
	L->data = nd; L->cap = cap;
}

static void buf_insert_char(Editor *E, int r, int c, char ch) {
	if (r < 0 || r >= E->line_count) return;
	Line *L = &E->lines[r];
	if (c < 0) c = 0; if ((size_t)c > L->len) c = (int)L->len;
	line_reserve(L, L->len + 2);
	// shift right
	memmove(L->data + c + 1, L->data + c, L->len - (size_t)c);
	L->data[c] = ch;
	L->len++;
	E->modified = 1;
}

static void buf_overwrite_char(Editor *E, int r, int c, char ch) {
	if (r < 0 || r >= E->line_count) return;
	Line *L = &E->lines[r];
	if (c < 0) c = 0;
	if ((size_t)c < L->len) {
		L->data[c] = ch;
		E->modified = 1;
	} else {
		// extend with spaces
		line_reserve(L, (size_t)c + 2);
		while ((size_t)c > L->len) { L->data[L->len++] = ' '; }
		L->data[L->len++] = ch;
		E->modified = 1;
	}
}

static void buf_delete_char(Editor *E, int r, int c) {
	if (r < 0 || r >= E->line_count) return;
	Line *L = &E->lines[r];
	if ((size_t)c >= L->len) {
		// join with next line if exists
		if (r + 1 < E->line_count) buf_join_with_next(E, r);
		return;
	}
	memmove(L->data + c, L->data + c + 1, L->len - (size_t)c - 1);
	L->len--;
	E->modified = 1;
}

static void buf_backspace(Editor *E) {
	if (E->cursor_col > 0) {
		buf_delete_char(E, E->cursor_row, E->cursor_col - 1);
		E->cursor_col--;
	} else if (E->cursor_row > 0) {
		int prev_len = (int)E->lines[E->cursor_row - 1].len;
		buf_join_with_next(E, E->cursor_row - 1);
		E->cursor_row--; E->cursor_col = prev_len;
	}
}

static void buf_newline(Editor *E) {
	// split current line at cursor
	if (E->cursor_row < 0 || E->cursor_row >= E->line_count) return;
	Line *L = &E->lines[E->cursor_row];
	int c = E->cursor_col; if (c < 0) c = 0; if ((size_t)c > L->len) c = (int)L->len;
	Line newL = {0};
	newL.cap = (L->len - (size_t)c) + 16; newL.data = (char*)kcalloc(newL.cap, 1);
	newL.len = L->len - (size_t)c;
	if (newL.len) memcpy(newL.data, L->data + c, newL.len);
	L->len = (size_t)c;
	// insert new line after current
	buf_ensure_lines(E, E->line_count + 1);
	for (int i = E->line_count; i > E->cursor_row + 1; i--) E->lines[i] = E->lines[i - 1];
	E->lines[E->cursor_row + 1] = newL;
	E->line_count++;
	E->cursor_row++; E->cursor_col = 0;
	E->modified = 1;
}

static void buf_join_with_next(Editor *E, int r) {
	if (r < 0 || r + 1 >= E->line_count) return;
	Line *A = &E->lines[r];
	Line *B = &E->lines[r + 1];
	line_reserve(A, A->len + B->len + 1);
	memcpy(A->data + A->len, B->data, B->len);
	A->len += B->len;
	// remove B
	kfree(B->data); B->data = 0;
	for (int i = r + 1; i + 1 < E->line_count; i++) E->lines[i] = E->lines[i + 1];
	E->line_count--;
	E->modified = 1;
}

// ---- UI ----
static void ui_draw_menu(void) {
	// верхняя панель с пунктами File / View
	vga_fill_rect(0, 0, MAX_COLS, 1, ' ', g_attr_menu);
	char line[128];
	const char *name = THEMES[g_theme_index].name;
	strcpy(line, " AxonEdit v1 |  Ctrl+O Open  Ctrl+S Save  Ctrl+N New  Ctrl+G Goto  Ctrl+X Quit  Ctrl+T Theme: ");
	strcat(line, name);
	vga_write_str_xy(2, 0, line, g_attr_menu);
}

static void ui_draw_status(Editor *E, const char *msg) {
	char buf[128];
	vga_fill_rect(0, MAX_ROWS - 1, MAX_COLS, 1, ' ', g_attr_status);
	// left: file name and modified flag
	buf[0] = '\0';
	if (E->filename[0]) { strncpy(buf, E->filename, sizeof(buf)-1); buf[sizeof(buf)-1]='\0'; }
	else { strcpy(buf, "[No Name]"); }
	if (E->modified) strcat(buf, " *");
	vga_write_str_xy(1, MAX_ROWS - 1, buf, g_attr_status);
	// right: Ln/Col and mode
	char rbuf[64];
	int ln = E->cursor_row + 1; int col = E->cursor_col + 1;
	char num[16]; num[0]=0; // small itoa inline
	{
		int v=ln,n=0,s[10]; if(v==0){num[0]='0';num[1]='\0';} else {while(v){s[n++]=v%10; v/=10;} for(int i=0;i<n;i++) num[i]=(char)('0'+s[n-1-i]); num[n]='\0';}
	}
	strcpy(rbuf, "Ln "); strcat(rbuf, num); strcat(rbuf, ", Col ");
	{
		int v=col,n=0,s[10]; char nn[16]; if(v==0){nn[0]='0';nn[1]='\0';} else {while(v){s[n++]=v%10; v/=10;} for(int i=0;i<n;i++) nn[i]=(char)('0'+s[n-1-i]); nn[n]='\0';}
		strcat(rbuf, nn);
	}
	strcat(rbuf, "  "); strcat(rbuf, E->insert_mode?"INS":"OVR");
	int x = MAX_COLS - (int)strlen(rbuf) - 2; if (x < 0) x = 0;
	vga_write_str_xy((uint32_t)x, MAX_ROWS - 1, rbuf, g_attr_status);
	// center message if any
	if (msg && msg[0]) {
		int cx = (MAX_COLS - (int)strlen(msg)) / 2; if (cx < 0) cx = 0;
		vga_write_str_xy((uint32_t)cx, MAX_ROWS - 1, msg, g_attr_status);
	}
}

static int g_view_left_cur = 0;
static void draw_line_text(uint32_t y, const char *s, size_t len) {
	// draw line content starting from horizontal offset g_view_left_cur
	uint32_t x = 0;
    if (!s) { s=""; len=0; }
    if ((size_t)g_view_left_cur < len) { s += g_view_left_cur; len -= (size_t)g_view_left_cur; }
    else { s += len; len = 0; }
    if (!g_view_cache_valid) { for (uint32_t iy=0; iy<VIEW_H; iy++) for (uint32_t ix=0; ix<VIEW_W; ix++) g_view_cache[iy][ix]=0xFFFF; g_view_cache_valid=1; }
    for (; x < VIEW_W && x < (uint32_t)len; x++) {
        uint16_t v = ((uint16_t)g_attr_text << 8) | (uint8_t)s[x];
        uint32_t iy = y - VIEW_Y0; if (iy < VIEW_H) {
            if (g_view_cache[iy][x] != v) { vga_putch_xy(x, y, (uint8_t)s[x], g_attr_text); g_view_cache[iy][x] = v; }
        } else {
            vga_putch_xy(x, y, (uint8_t)s[x], g_attr_text);
        }
    }
    for (; x < VIEW_W; x++) {
        uint16_t v = ((uint16_t)g_attr_text << 8) | (uint8_t)' ';
        uint32_t iy = y - VIEW_Y0; if (iy < VIEW_H) {
            if (g_view_cache[iy][x] != v) { vga_putch_xy(x, y, ' ', g_attr_text); g_view_cache[iy][x] = v; }
        } else {
            vga_putch_xy(x, y, ' ', g_attr_text);
        }
    }
}

static void ui_draw_view(Editor *E) {
	// draw visible buffer lines
    g_view_left_cur = (E->view_left < 0) ? 0 : E->view_left;
    if (!g_view_cache_valid) {
        // Clear view area to prevent mixing after large viewport jumps
        for (uint32_t iy = 0; iy < VIEW_H; iy++) {
            uint32_t y = VIEW_Y0 + iy;
            for (uint32_t x = 0; x < VIEW_W; x++) {
                vga_putch_xy(x, y, ' ', g_attr_text);
                g_view_cache[iy][x] = 0xFFFF;
            }
        }
        g_view_cache_valid = 1;
    }
	for (int i = 0; i < VIEW_H; i++) {
		int r = E->view_top + i;
		if (r >= 0 && r < E->line_count) {
			Line *L = &E->lines[r];
            const char* ls = L->data ? L->data : "";
            size_t llen = L->len;
            if ((size_t)g_view_left_cur < llen) { ls += g_view_left_cur; llen -= (size_t)g_view_left_cur; }
            else { ls += llen; llen = 0; }
			if (E->syntax_mode == 1) draw_line_text_asm(VIEW_Y0 + (uint32_t)i, ls, llen);
			else if (E->syntax_mode == 2) draw_line_text_osh(VIEW_Y0 + (uint32_t)i, ls, llen);
			else draw_line_text(VIEW_Y0 + (uint32_t)i, ls, llen);
		} else {
			// beyond EOF -> dim tildes like vim
			if (r >= E->line_count) {
                uint32_t y = VIEW_Y0 + (uint32_t)i;
                if (!g_view_cache_valid) { for (uint32_t iy=0; iy<VIEW_H; iy++) for (uint32_t ix=0; ix<VIEW_W; ix++) g_view_cache[iy][ix]=0xFFFF; g_view_cache_valid=1; }
                // draw '~' at x=0
                uint16_t v0 = ((uint16_t)g_attr_text_dim << 8) | (uint8_t)'~';
                if (g_view_cache[i][0] != v0) { vga_putch_xy(0, y, '~', g_attr_text_dim); g_view_cache[i][0] = v0; }
                for (uint32_t x=1;x<VIEW_W;x++) {
                    uint16_t v = ((uint16_t)g_attr_text << 8) | (uint8_t)' ';
                    if (g_view_cache[i][x] != v) { vga_putch_xy(x, y, ' ', g_attr_text); g_view_cache[i][x] = v; }
                }
			}
		}
	}
}

// -------- Syntax detection and drawing (ASM) --------
static int str_ends_with(const char* s, const char* suf) {
    size_t ls = strlen(s), le = strlen(suf);
    if (le > ls) return 0;
    return (strncmp(s + ls - le, suf, le) == 0);
}

static void editor_update_syntax(Editor *E) {
    E->syntax_mode = 0;
    // detect by shebang first
    if (E->line_count > 0 && E->lines[0].data && E->lines[0].len >= 5) {
        const char* l0 = E->lines[0].data;
        if (l0[0]=='#' && l0[1]=='!' && l0[2]=='o' && l0[3]=='s' && l0[4]=='h') {
            E->syntax_mode = 2; // OSH script by shebang
            return;
        }
    }
    if (E->filename[0]) {
        if (str_ends_with(E->filename, ".asm") || str_ends_with(E->filename, ".ASM") ||
            str_ends_with(E->filename, ".s")   || str_ends_with(E->filename, ".S")) {
            E->syntax_mode = 1; // ASM
        }
    }
}

static inline uint8_t attr_with_fg(uint8_t base_attr, uint8_t fg) {
    // clear blink bit (bit7), keep background (bits 4..6) and set foreground
    return (uint8_t)(((base_attr & 0x70)) | (fg & 0x0F));
}

static int is_ident_char(char c) { return (c=='_' || (c>='0'&&c<='9') || (c>='a'&&c<='z') || (c>='A'&&c<='Z')); }

static int is_hex_prefix(const char* s, size_t i, size_t len) {
    return (i+1 < len && s[i]=='0' && (s[i+1]=='x' || s[i+1]=='X'));
}

static int is_number_start(const char* s, size_t i, size_t len) {
    if (i < len && (s[i]>='0' && s[i]<='9')) return 1;
    if (is_hex_prefix(s,i,len)) return 1;
    return 0;
}

static int token_eq(const char* s, size_t start, size_t end, const char* kw) {
    size_t L = end - start; size_t K = strlen(kw); if (L != K) return 0;
    for (size_t i=0;i<K;i++) { char a=s[start+i], b=kw[i]; if (a>='A'&&a<='Z') a=(char)(a-'A'+'a'); if (b>='A'&&b<='Z') b=(char)(b-'A'+'a'); if (a!=b) return 0; }
    return 1;
}

static int is_asm_mnemonic(const char* s, size_t st, size_t en) {
    static const char* K[] = {
        "mov","add","sub","mul","imul","div","idiv","and","or","xor","not","neg",
        "push","pop","pushf","popf","lea","cmp","test","inc","dec","shl","shr","sar","rol","ror",
        "jmp","je","jne","jg","jge","jl","jle","ja","jb","call","ret","int","nop","hlt","sti","cli"
    };
    for (size_t i=0;i<sizeof(K)/sizeof(K[0]);i++) if (token_eq(s,st,en,K[i])) return 1; return 0;
}

static int is_asm_register(const char* s, size_t st, size_t en) {
    static const char* R[] = {
        "al","ah","ax","eax","rax","bl","bh","bx","ebx","rbx","cl","ch","cx","ecx","rcx",
        "dl","dh","dx","edx","rdx","si","esi","rsi","di","edi","rdi","bp","ebp","rbp","sp","esp","rsp",
        "cs","ds","es","ss","fs","gs"
    };
    for (size_t i=0;i<sizeof(R)/sizeof(R[0]);i++) if (token_eq(s,st,en,R[i])) return 1; return 0;
}

static int is_asm_directive(const char* s, size_t st, size_t en) {
    if (s[st]=='.') return 1;
    static const char* D[] = {"db","dw","dd","dq","dt","section","global","extern","equ","org"};
    for (size_t i=0;i<sizeof(D)/sizeof(D[0]);i++) if (token_eq(s,st,en,D[i])) return 1; return 0;
}

static void draw_line_text_asm(uint32_t y, const char *s, size_t len) {
    uint8_t attr_norm = g_attr_text;
    uint8_t attr_cmt  = attr_with_fg(g_attr_text, 0x02); // green
    uint8_t attr_lbl  = attr_with_fg(g_attr_text, 0x0E); // yellow
    uint8_t attr_mn   = attr_with_fg(g_attr_text, 0x0B); // cyan
    uint8_t attr_reg  = attr_with_fg(g_attr_text, 0x0D); // magenta
    uint8_t attr_num  = attr_with_fg(g_attr_text, 0x0C); // red
    uint8_t attr_str  = attr_with_fg(g_attr_text, 0x0A); // light green

    uint32_t x = 0; size_t i = 0; int in_str = 0; char str_quote = 0;
    if (!g_view_cache_valid) { for (uint32_t iy=0; iy<VIEW_H; iy++) for (uint32_t ix=0; ix<VIEW_W; ix++) g_view_cache[iy][ix]=0xFFFF; g_view_cache_valid=1; }
    while (x < VIEW_W) {
        if (i >= len) { vga_putch_xy(x++, y, ' ', attr_norm); continue; }
        char c = s[i];
        if (!in_str && c == ';') { // comment until end of line
            for (; x < VIEW_W && i < len; i++, x++) {
                uint16_t v = ((uint16_t)attr_cmt<<8) | (uint8_t)s[i];
                uint32_t iy = y - VIEW_Y0; if (iy < VIEW_H && g_view_cache[iy][x] == v) continue; vga_putch_xy(x,y,(uint8_t)s[i],attr_cmt); if (iy<VIEW_H) g_view_cache[iy][x]=v;
            }
            break;
        }
        if (!in_str && (c=='\'' || c=='"')) { in_str = 1; str_quote=c; vga_putch_xy(x++, y, (uint8_t)c, attr_str); i++; continue; }
        if (in_str) {
            uint16_t v = ((uint16_t)attr_str<<8)|(uint8_t)c; uint32_t iy=y-VIEW_Y0; if (iy<VIEW_H && g_view_cache[iy][x]==v) { x++; i++; } else { vga_putch_xy(x++,y,(uint8_t)c,attr_str); if (iy<VIEW_H) g_view_cache[iy][x-1]=v; i++; }
            if (c == str_quote) in_str = 0;
            continue;
        }
        // common punctuation
        if (c==' ' || c=='\t' || c==',' || c=='+' || c=='-' || c=='/' || c=='[' || c==']' || c=='(' || c==')' || c=='*') {
            uint16_t v = ((uint16_t)attr_norm<<8)|(uint8_t)c; uint32_t iy=y-VIEW_Y0; if (iy<VIEW_H && g_view_cache[iy][x]==v) { x++; i++; } else { vga_putch_xy(x++,y,(uint8_t)c,attr_norm); if (iy<VIEW_H) g_view_cache[iy][x-1]=v; i++; } continue;
        }
        // dot-directive: .section, .globl etc.
        if (c=='.') {
            size_t st = i; i++; while (i < len && is_ident_char(s[i])) i++; size_t en = i;
            for (size_t j=st;j<en && x<VIEW_W;j++,x++) { uint16_t v=((uint16_t)attr_mn<<8)|(uint8_t)s[j]; uint32_t iy=y-VIEW_Y0; if (iy<VIEW_H && g_view_cache[iy][x]==v) continue; vga_putch_xy(x,y,(uint8_t)s[j],attr_mn); if (iy<VIEW_H) g_view_cache[iy][x]=v; }
            continue;
        }
        // token
        size_t st = i; while (i < len && is_ident_char(s[i])) i++;
        size_t en = i;
        if (en == st) { // not an identifier - output raw char to avoid infinite loop
            uint16_t v=((uint16_t)attr_norm<<8)|(uint8_t)s[i]; uint32_t iy=y-VIEW_Y0; if (iy<VIEW_H && g_view_cache[iy][x]==v) { x++; i++; } else { vga_putch_xy(x++,y,(uint8_t)s[i],attr_norm); if (iy<VIEW_H) g_view_cache[iy][x-1]=v; i++; } continue;
        }
        uint8_t a = attr_norm;
        if (en>st && s[en-1]==':') { // label like 'start:'
            en--; a = attr_lbl; // draw token without ':' then draw ':'
            for (size_t j=st;j<en && x<VIEW_W;j++,x++) vga_putch_xy(x,y,(uint8_t)s[j],a);
            if (x<VIEW_W) { vga_putch_xy(x++,y,':',a); }
            continue;
        }
        if (is_asm_mnemonic(s,st,en)) a = attr_mn;
        else if (is_asm_register(s,st,en)) a = attr_reg;
        else if (is_asm_directive(s,st,en)) a = attr_mn;
        else if (is_number_start(s,st,len)) a = attr_num;
        for (size_t j=st;j<en && x<VIEW_W;j++,x++) { uint16_t v=((uint16_t)a<<8)|(uint8_t)s[j]; uint32_t iy=y-VIEW_Y0; if (iy<VIEW_H && g_view_cache[iy][x]==v) continue; vga_putch_xy(x,y,(uint8_t)s[j],a); if (iy<VIEW_H) g_view_cache[iy][x]=v; }
    }
}

static int is_shell_ident(char c) { return (c=='_' || (c>='0'&&c<='9') || (c>='a'&&c<='z') || (c>='A'&&c<='Z')); }
static int is_shell_kw(const char* s, size_t st, size_t en) {
    static const char* K[] = {
        "echo","pwd","cd","clear","cls","ls","cat","mkdir","touch","rm",
        "about","time","date","uptime","edit", "reboot","shutdown","osh",
		"art","pause","chipset","help","mem"
    };
    size_t L = en - st;
    for (size_t i=0;i<sizeof(K)/sizeof(K[0]);i++) {
        const char* k = K[i]; size_t KL = strlen(k);
        if (KL != L) continue; int ok=1;
        for (size_t j=0;j<KL;j++){ char a=s[st+j], b=k[j]; if (a>='A'&&a<='Z') a=(char)(a-'A'+'a'); if (a!=b) { ok=0; break; } }
        if (ok) return 1;
    }
    return 0;
}

static void draw_line_text_osh(uint32_t y, const char *s, size_t len) {
    uint8_t attr_norm = g_attr_text;
    uint8_t attr_cmt  = attr_with_fg(g_attr_text, 0x02); // green
    uint8_t attr_kw   = attr_with_fg(g_attr_text, 0x0B); // cyan
    uint8_t attr_var  = attr_with_fg(g_attr_text, 0x0D); // magenta
    uint8_t attr_num  = attr_with_fg(g_attr_text, 0x0C); // red
    uint8_t attr_str  = attr_with_fg(g_attr_text, 0x0A); // light green
    uint8_t attr_op   = attr_with_fg(g_attr_text, 0x0E); // yellow

    uint32_t x = 0; size_t i = 0; int in_str = 0;
    if (!g_view_cache_valid) { for (uint32_t iy=0; iy<VIEW_H; iy++) for (uint32_t ix=0; ix<VIEW_W; ix++) g_view_cache[iy][ix]=0xFFFF; g_view_cache_valid=1; }
    while (x < VIEW_W) {
        if (i >= len) { vga_putch_xy(x++, y, ' ', attr_norm); continue; }
        char c = s[i];
        if (!in_str && c == '#') { // comment
            for (; x < VIEW_W && i < len; i++, x++) {
                uint16_t v = ((uint16_t)attr_cmt<<8) | (uint8_t)s[i];
                uint32_t iy = y - VIEW_Y0; if (iy < VIEW_H && g_view_cache[iy][x] == v) continue; vga_putch_xy(x,y,(uint8_t)s[i],attr_cmt); if (iy<VIEW_H) g_view_cache[iy][x]=v;
            }
            break;
        }
        if (!in_str && c == '"') { in_str = 1; vga_putch_xy(x++, y, (uint8_t)c, attr_str); i++; continue; }
        if (in_str) {
            uint16_t v = ((uint16_t)attr_str<<8)|(uint8_t)c; uint32_t iy=y-VIEW_Y0; if (iy<VIEW_H && g_view_cache[iy][x]==v) { x++; i++; } else { vga_putch_xy(x++,y,(uint8_t)c,attr_str); if (iy<VIEW_H) g_view_cache[iy][x-1]=v; i++; }
            if (c == '"') in_str = 0;
            continue;
        }
        // operators
        if (c=='&' || c=='|' || c=='<' || c=='>' || c=='=' || c=='(' || c==')') {
            uint16_t v = ((uint16_t)attr_op<<8)|(uint8_t)c; uint32_t iy=y-VIEW_Y0; if (iy<VIEW_H && g_view_cache[iy][x]==v) { x++; i++; } else { vga_putch_xy(x++,y,(uint8_t)c,attr_op); if (iy<VIEW_H) g_view_cache[iy][x-1]=v; i++; } continue;
        }
        // whitespace and common punctuation
        if (c==' ' || c=='\t' || c==',' || c=='+' || c=='-' || c=='/') {
            uint16_t v = ((uint16_t)attr_norm<<8)|(uint8_t)c; uint32_t iy=y-VIEW_Y0; if (iy<VIEW_H && g_view_cache[iy][x]==v) { x++; i++; } else { vga_putch_xy(x++,y,(uint8_t)c,attr_norm); if (iy<VIEW_H) g_view_cache[iy][x-1]=v; i++; } continue;
        }
        // variable $name
        if (c=='$') {
            size_t st=i; i++; while (i<len && is_shell_ident(s[i])) i++; size_t en=i;
            for (size_t j=st;j<en && x<VIEW_W;j++,x++) { uint16_t v=((uint16_t)attr_var<<8)|(uint8_t)s[j]; uint32_t iy=y-VIEW_Y0; if (iy<VIEW_H && g_view_cache[iy][x]==v) continue; vga_putch_xy(x,y,(uint8_t)s[j],attr_var); if (iy<VIEW_H) g_view_cache[iy][x]=v; }
            continue;
        }
        // number
        if (c>='0'&&c<='9') {
            size_t st=i; while (i<len && s[i]>='0' && s[i]<='9') i++; size_t en=i;
            for (size_t j=st;j<en && x<VIEW_W;j++,x++) { uint16_t v=((uint16_t)attr_num<<8)|(uint8_t)s[j]; uint32_t iy=y-VIEW_Y0; if (iy<VIEW_H && g_view_cache[iy][x]==v) continue; vga_putch_xy(x,y,(uint8_t)s[j],attr_num); if (iy<VIEW_H) g_view_cache[iy][x]=v; }
            continue;
        }
        // identifier / keyword
        if (is_shell_ident(c)) {
            size_t st=i; while (i<len && is_shell_ident(s[i])) i++; size_t en=i;
            uint8_t a = is_shell_kw(s, st, en) ? attr_kw : attr_norm;
            for (size_t j=st;j<en && x<VIEW_W;j++,x++) { uint16_t v=((uint16_t)a<<8)|(uint8_t)s[j]; uint32_t iy=y-VIEW_Y0; if (iy<VIEW_H && g_view_cache[iy][x]==v) continue; vga_putch_xy(x,y,(uint8_t)s[j],a); if (iy<VIEW_H) g_view_cache[iy][x]=v; }
            continue;
        }
        // default
        { uint16_t v=((uint16_t)attr_norm<<8)|(uint8_t)s[i]; uint32_t iy=y-VIEW_Y0; if (iy<VIEW_H && g_view_cache[iy][x]==v) { x++; i++; } else { vga_putch_xy(x++,y,(uint8_t)s[i],attr_norm); if (iy<VIEW_H) g_view_cache[iy][x-1]=v; i++; } }
    }
}

static void ensure_cursor_visible(Editor *E) {
	if (E->cursor_row < E->view_top) E->view_top = E->cursor_row;
	if (E->cursor_row >= E->view_top + VIEW_H) E->view_top = E->cursor_row - VIEW_H + 1;
	if (E->view_top < 0) E->view_top = 0;
    if (E->cursor_col < E->view_left) E->view_left = E->cursor_col;
    if (E->cursor_col >= E->view_left + (int)VIEW_W) E->view_left = E->cursor_col - (int)VIEW_W + 1;
    if (E->view_left < 0) E->view_left = 0;
}

static void ui_place_cursor(Editor *E) {
	int scr_y = VIEW_Y0 + (E->cursor_row - E->view_top);
	int scr_x = E->cursor_col - E->view_left;
	if (scr_y < VIEW_Y0) scr_y = VIEW_Y0;
	if (scr_y >= VIEW_Y0 + VIEW_H) scr_y = VIEW_Y0 + VIEW_H - 1;
	if (scr_x < 0) scr_x = 0;
	if (scr_x >= (int)VIEW_W) scr_x = (int)VIEW_W - 1;
    // avoid redundant hardware cursor updates (helps on VMware)
    static uint32_t last_x = 0xFFFFFFFFu, last_y = 0xFFFFFFFFu;
    if ((uint32_t)scr_x != last_x || (uint32_t)scr_y != last_y) {
        vga_set_cursor((uint32_t)scr_x, (uint32_t)scr_y);
        last_x = (uint32_t)scr_x; last_y = (uint32_t)scr_y;
    }
}

// ---- ESC top menu ----
static void draw_menu_panel_header(void) {
	vga_fill_rect(0, 0, MAX_COLS, 1, ' ', g_attr_menu);
	vga_write_str_xy(2, 0, "Menu  (Esc: close, Enter: select)", g_attr_menu);
}

static void draw_menu_items(int sel) {
	const char *items[] = {"Open", "Save", "Exit", "About"};
	const int n = 4;
	// clear area under header
	for (uint32_t y = 1; y < 6; y++) vga_fill_rect(0, y, MAX_COLS, 1, ' ', g_attr_status);
	for (int i = 0; i < n; i++) {
		uint32_t y = 1 + (uint32_t)i;
		if (i == sel) {
			vga_write_str_xy(2, y, "> ", g_attr_status);
		} else {
			vga_write_str_xy(2, y, "  ", g_attr_status);
		}
		vga_write_str_xy(4, y, items[i], g_attr_status);
	}
	// hint
	vga_write_str_xy(2, 6, "Open/Save work with current buffer; Exit asks if modified", g_attr_status);
}

static void show_about_screen(void) {
	// simple about text overlaying top area
	for (uint32_t y = 1; y < 6; y++) vga_fill_rect(0, y, MAX_COLS, 1, ' ', g_attr_status);
	vga_write_str_xy(4, 2, "AxonEdit - text editor for AxonOS", g_attr_status);
	vga_write_str_xy(4, 3, "ESC: close menu, Ctrl+O/S/N/G/X, Ctrl+T: themes", g_attr_status);
	vga_write_str_xy(4, 4, "Press any key to return", g_attr_status);
	(void)kgetc();
}

// returns 1 if should quit editor
static int menu_show(Editor *E) {
	int sel = 0;
	draw_menu_panel_header();
	draw_menu_items(sel);
	for (;;) {
		char c = kgetc();
		if ((unsigned char)c == KEY_UP) { if (sel > 0) sel--; draw_menu_items(sel); continue; }
		if ((unsigned char)c == KEY_DOWN) { if (sel < 3) sel++; draw_menu_items(sel); continue; }
		if (c == 27) {
			// close menu
			return 0;
		}
		if (c == '\n' || c == '\r') {
			if (sel == 0) {
				char name[256];
				if (prompt_input("Open: ", name, sizeof(name), 0)) {
					if (file_load(E, name) == 0) { strncpy(E->filename, name, sizeof(E->filename)-1); E->filename[sizeof(E->filename)-1] = '\0'; ui_draw_status(E, "Opened."); }
					else { ui_draw_status(E, "Open failed!"); }
				}
				return 0;
			} else if (sel == 1) {
				if (!E->filename[0]) {
					char name[256];
					if (prompt_input("Save as: ", name, sizeof(name), 0)) { strncpy(E->filename, name, sizeof(E->filename)-1); E->filename[sizeof(E->filename)-1] = '\0'; }
				}
				if (E->filename[0]) {
					int rc = file_save(E, E->filename);
					ui_draw_status(E, rc==0?"Saved.":"Save failed!");
				}
				return 0;
			} else if (sel == 2) {
				if (E->modified) {
					char ans[8]; if (prompt_input("Unsaved changes. Quit? (y/N): ", ans, sizeof(ans), 0) && (ans[0]=='y'||ans[0]=='Y')) return 1; else return 0;
				} else return 1;
			} else if (sel == 3) {
				show_about_screen();
				draw_menu_panel_header();
				draw_menu_items(sel);
			}
		}
		// printable shortcuts inside menu
		if (c == 'o' || c == 'O') sel = 0;
		else if (c == 's' || c == 'S') sel = 1;
		else if (c == 'x' || c == 'X' || c == 'q' || c == 'Q') sel = 2;
		else if (c == 'a' || c == 'A') sel = 3;
		draw_menu_items(sel);
	}
}

// ---- Prompt input on status bar ----
static int prompt_input(const char *title, char *out, int out_size, const char *initial) {
	if (!out || out_size <= 1) return 0;
	int len = 0;
	if (initial) { len = (int)strnlen(initial, (size_t)(out_size - 1)); memcpy(out, initial, (size_t)len); }
	out[len] = '\0';
	for (;;) {
		// draw prompt on status line
		vga_fill_rect(0, MAX_ROWS - 1, MAX_COLS, 1, ' ', g_attr_status);
		vga_write_str_xy(1, MAX_ROWS - 1, title, g_attr_status);
		vga_write_str_xy((uint32_t)(1 + (int)strlen(title)), MAX_ROWS - 1, out, g_attr_status);
		vga_set_cursor((uint32_t)(1 + (int)strlen(title) + len), MAX_ROWS - 1);
		char c = kgetc();
		if (c == '\n' || c == '\r') { out[len] = '\0'; return len > 0; }
		if (c == 27) { return 0; } // ESC cancel
		if (c == 8 || c == 127) { if (len > 0) { len--; out[len] = '\0'; } continue; }
		if (c >= 32 && c < 127) {
			if (len < out_size - 1) { out[len++] = c; out[len] = '\0'; }
		}
	}
}

// ---- File I/O ----
static int file_load(Editor *E, const char *path) {
	struct fs_file *f = fs_open(path);
	if (!f) return -1;
    char *buf = 0;
    size_t sz = f->size;
    if (sz > 0) {
        buf = (char*)kmalloc(sz + 1);
        if (!buf) { fs_file_free(f); return -1; }
        ssize_t rd = fs_read(f, buf, sz, 0);
        if (rd < 0) { kfree(buf); fs_file_free(f); return -1; }
        /* Treat embedded NUL as logical end of text file.
           This hides padding/garbage bytes from cpio archives. */
        if (rd > 0) {
            size_t used = strnlen(buf, (size_t)rd);
            sz = used;
            buf[used] = '\0';
        } else {
            buf[0] = '\0';
            sz = 0;
        }
    } else {
        // fallback: unknown size, read in chunks until EOF
        size_t cap = 4096; buf = (char*)kmalloc(cap + 1); if (!buf) { fs_file_free(f); return -1; }
        sz = 0;
        for (;;) {
            if (sz + 4096 > cap) { size_t ncap = cap * 2; char *nb = (char*)krealloc(buf, ncap + 1); if (!nb) break; buf = nb; cap = ncap; }
            ssize_t rd = fs_read(f, buf + sz, 4096, sz);
            if (rd <= 0) break; sz += (size_t)rd;
        }
        /* same rule: stop at first NUL */
        if (sz > 0) {
            size_t used = strnlen(buf, sz);
            sz = used;
            buf[used] = '\0';
        } else {
            buf[0] = '\0';
        }
    }
	fs_file_free(f);
	// parse into lines
	buf_clear(E);
	if (!buf || sz == 0) { if (buf) kfree(buf); return 0; }
	// count lines
	int lines = 1; for (size_t i=0;i<sz;i++) if (buf[i]=='\n') lines++;
	buf_ensure_lines(E, lines);
	E->line_count = 0;
	size_t i = 0; while (i < sz) {
		// extract line up to \n (handle CRLF)
		size_t start = i; while (i < sz && buf[i] != '\n') i++;
		size_t end = i; // [start,end)
		if (end > start && buf[end-1] == '\r') end--;
		Line L = {0}; L.cap = (end - start) + 16; L.data = (char*)kcalloc(L.cap, 1); L.len = (end - start);
		if (L.len) memcpy(L.data, buf + start, L.len);
		E->lines[E->line_count++] = L;
		if (i < sz && buf[i] == '\n') i++;
	}
	if (E->line_count == 0) { E->line_count = 1; E->lines[0].data = (char*)kcalloc(16,1); E->lines[0].len=0; E->lines[0].cap=16; }
	E->cursor_row = 0; E->cursor_col = 0; E->view_top = 0; E->view_left = 0; E->modified = 0;
	kfree(buf);
	return 0;
}

static int file_save(Editor *E, const char *path) {
	// join all lines with \n
	// compute size
	size_t total = 0;
	for (int i=0;i<E->line_count;i++) total += E->lines[i].len + (i+1<E->line_count ? 1 : 0);
	char *buf = (char*)kmalloc(total ? total : 1);
	if (!buf) return -1;
	size_t off = 0;
	for (int i=0;i<E->line_count;i++) {
		if (E->lines[i].len) { memcpy(buf + off, E->lines[i].data, E->lines[i].len); off += E->lines[i].len; }
		if (i + 1 < E->line_count) buf[off++] = '\n';
	}
    char abs[512];
    char path_copy[512];
    const char *use_path = path;
    if (path) {
        size_t plen = strlen(path);
        if (plen >= sizeof(path_copy)) plen = sizeof(path_copy) - 1;
        memcpy(path_copy, path, plen);
        path_copy[plen] = '\0';
        // strip quotes if present
        if (path_copy[0] == '"' || path_copy[0] == '\'') {
            size_t ln = strlen(path_copy);
            if (ln >= 2 && path_copy[ln-1] == path_copy[0]) {
                memmove(path_copy, path_copy+1, ln-2);
                path_copy[ln-2] = '\0';
            }
        }
        use_path = path_copy;
    }
    if (path && path[0] != '/') {
        char cwd[256]; osh_get_cwd(cwd, sizeof(cwd));
        osh_resolve_path(cwd, path, abs, sizeof(abs));
        use_path = abs;
    }
    struct fs_file *f = fs_open(use_path);
    if (!f) f = fs_create_file(use_path);
	if (!f) { kfree(buf); return -1; }
	ssize_t wr = fs_write(f, buf, total, 0);
	fs_file_free(f);
	kfree(buf);
	if (wr < 0 || (size_t)wr != total) return -1;
	E->modified = 0;
	return 0;
}

// ---- Path helpers ----
static void path_dirname(const char* path, char* out, size_t out_sz) {
    if (!path || !path[0]) { strncpy(out, "/", out_sz-1); out[out_sz-1]='\0'; return; }
    size_t len = strlen(path);
    if (len == 0) { strncpy(out, "/", out_sz-1); out[out_sz-1]='\0'; return; }
    // skip trailing slash except root
    while (len>1 && path[len-1]=='/') len--;
    // find last '/'
    size_t i = len; while (i>0 && path[i-1] != '/') i--;
    if (i==0) { strncpy(out, "/", out_sz-1); out[out_sz-1]='\0'; return; }
    if (i==1) { out[0]='/'; out[1]='\0'; return; }
    size_t copy = (i-1 < out_sz-1) ? (i-1) : (out_sz-1);
    memcpy(out, path, copy); out[copy]='\0';
}

static void make_absolute_path(const char* base_dir, const char* name, char* out, size_t out_sz) {
    if (name && name[0]=='/') { strncpy(out, name, out_sz-1); out[out_sz-1]='\0'; return; }
    if (!base_dir || !base_dir[0]) { strncpy(out, name, out_sz-1); out[out_sz-1]='\0'; return; }
    size_t bl = strlen(base_dir);
    if (bl==1 && base_dir[0]=='/') { // root
        size_t nlen = strlen(name);
        if (out_sz>0) {
            out[0] = '/';
            size_t rem = (out_sz > 2) ? (out_sz - 2) : 0;
            size_t copy = (nlen < rem) ? nlen : rem;
            if (copy) memcpy(out+1, name, copy);
            out[1 + copy] = '\0';
        }
        return;
    }
    // ensure no trailing '/'
    char tmp[512]; strncpy(tmp, base_dir, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0';
    while (bl>1 && tmp[bl-1]=='/') { tmp[bl-1]='\0'; bl--; }
    size_t nlen = strlen(name);
    size_t need = bl + 1 + nlen + 1;
    if (out_sz>0) {
        size_t copy = (need < out_sz) ? need : out_sz;
        size_t pos = 0; memcpy(out+pos, tmp, bl); pos+=bl; out[pos++] = '/';
        size_t rem = copy - pos - 1; if ((int)rem < 0) rem = 0; if (rem > nlen) rem = nlen;
        if (rem) memcpy(out+pos, name, rem); pos += rem; out[pos] = '\0';
        if (copy==out_sz) out[out_sz-1]='\0';
    }
}

static void fix_duplicate_tail(char* path) {
    if (!path) return;
    size_t len = strlen(path); if (len == 0) return;
    // remove trailing slash unless root
    while (len > 1 && path[len-1] == '/') { path[--len] = '\0'; }
    // find last and previous segment
    int i = (int)len - 1; while (i > 0 && path[i] != '/') i--;
    if (i <= 0) return; // no parent
    const char* name = path + i + 1; int end1 = (int)strlen(name);
    int j = i - 1; while (j > 0 && path[j] != '/') j--;
    const char* prev = path + (j > 0 ? j + 1 : 1);
    int len_prev = i - (j > 0 ? j + 1 : 1);
    if (len_prev == end1 && strncmp(prev, name, (size_t)end1) == 0) {
        // truncate at last slash -> collapse duplicate tail
        path[i] = '\0';
    }
}

// ---- Key handling helpers ----
static void move_left(Editor *E) {
	if (E->cursor_col > 0) { E->cursor_col--; }
	else if (E->cursor_row > 0) { E->cursor_row--; E->cursor_col = (int)E->lines[E->cursor_row].len; }
    ensure_cursor_visible(E);
}

static void move_right(Editor *E) {
	Line *L = &E->lines[E->cursor_row];
	if (E->cursor_col < (int)L->len) { E->cursor_col++; }
	else if (E->cursor_row + 1 < E->line_count) { E->cursor_row++; E->cursor_col = 0; }
    ensure_cursor_visible(E);
}

static void move_up(Editor *E) {
	if (E->cursor_row > 0) E->cursor_row--;
	int len = (int)E->lines[E->cursor_row].len; if (E->cursor_col > len) E->cursor_col = len;
    ensure_cursor_visible(E);
}

static void move_down(Editor *E) {
	if (E->cursor_row + 1 < E->line_count) E->cursor_row++;
	int len = (int)E->lines[E->cursor_row].len; if (E->cursor_col > len) E->cursor_col = len;
    ensure_cursor_visible(E);
}

static void move_home(Editor *E) { E->cursor_col = 0; }
static void move_end(Editor *E) { E->cursor_col = (int)E->lines[E->cursor_row].len; }

static void page_up(Editor *E) {
	E->cursor_row -= VIEW_H; if (E->cursor_row < 0) E->cursor_row = 0; ensure_cursor_visible(E);
}
static void page_down(Editor *E) {
	E->cursor_row += VIEW_H; if (E->cursor_row >= E->line_count) E->cursor_row = E->line_count - 1; ensure_cursor_visible(E);
}

static void insert_tab(Editor *E) {
	int col = E->cursor_col;
	int spaces = TAB_WIDTH - (col % TAB_WIDTH);
	for (int i = 0; i < spaces; i++) {
		buf_insert_char(E, E->cursor_row, E->cursor_col, ' ');
		E->cursor_col++;
	}
}

// ---- Public entry ----
void editor_run(const char *path) {
	Editor E; buf_init(&E);
	apply_theme(0);
	if (path && path[0]) {
		char abs[512]; const char* use = path;
        if (path[0] != '/') { char cwd[256]; osh_get_cwd(cwd, sizeof(cwd)); make_absolute_path(cwd, path, abs, sizeof(abs)); use = abs; }
        // strip surrounding quotes from use
        char use_copy[512];
        strncpy(use_copy, use, sizeof(use_copy)-1); use_copy[sizeof(use_copy)-1]='\0';
        if ((use_copy[0] == '"' || use_copy[0] == '\'') && strlen(use_copy) >= 2) {
            size_t ln = strlen(use_copy);
            if (use_copy[ln-1] == use_copy[0]) {
                memmove(use_copy, use_copy+1, ln-2);
                use_copy[ln-2] = '\0';
            }
        }
        use = use_copy;
        if (file_load(&E, use) == 0) { strncpy(E.filename, use, sizeof(E.filename)-1); E.filename[sizeof(E.filename)-1]='\0'; fix_duplicate_tail(E.filename); editor_update_syntax(&E); }
		else { strncpy(E.filename, use, sizeof(E.filename)-1); E.filename[sizeof(E.filename)-1]='\0'; fix_duplicate_tail(E.filename); editor_update_syntax(&E); }
	}
	// initial draw
	kclear_col(0x08);
	ui_draw_menu();
	ui_draw_view(&E);                                            ///
	ui_draw_status(&E, "                                    ");
	ui_place_cursor(&E);

	int running = 1;
	while (running) {
		char c = kgetc();
        int redraw = 0, restatus = 0;
        int old_view_top = E.view_top;
        int old_view_left = E.view_left;
		if (c == 27) { // ESC: игнорировать (меню отключено)
			continue;
		}
		if ((unsigned char)c == KEY_LEFT) { move_left(&E); redraw = 0; }
		else if ((unsigned char)c == KEY_RIGHT) { move_right(&E); redraw = 0; }
		else if ((unsigned char)c == KEY_UP) { move_up(&E); redraw = 0; }
		else if ((unsigned char)c == KEY_DOWN) { move_down(&E); redraw = 0; }
		else if ((unsigned char)c == KEY_HOME) { move_home(&E); }
		else if ((unsigned char)c == KEY_END) { move_end(&E); }
		else if ((unsigned char)c == KEY_PGUP) { page_up(&E); redraw = 1; }
		else if ((unsigned char)c == KEY_PGDN) { page_down(&E); redraw = 1; }
		else if ((unsigned char)c == KEY_INSERT) { E.insert_mode = !E.insert_mode; restatus = 1; }
		else if ((unsigned char)c == KEY_DELETE) { buf_delete_char(&E, E.cursor_row, E.cursor_col); redraw = 1; }
		else if (c == '\n' || c == '\r') { buf_newline(&E); redraw = 1; }
		else if (c == 8 || c == 127) { buf_backspace(&E); redraw = 1; }
		else if (c == 0x13) { // Ctrl+S
			if (!E.filename[0]) {
				char name[256];
				if (prompt_input("Save as: ", name, sizeof(name), 0)) {
					char base[256];
					if (E.filename[0] == '/') { path_dirname(E.filename, base, sizeof(base)); }
					else { osh_get_cwd(base, sizeof(base)); }
					char abs[512]; make_absolute_path(base, name, abs, sizeof(abs));
					strncpy(E.filename, abs, sizeof(E.filename)-1); E.filename[sizeof(E.filename)-1]='\0'; editor_update_syntax(&E);
				}
			}
			if (E.filename[0]) {
				int rc = file_save(&E, E.filename);
				ui_draw_status(&E, rc==0?"Saved.":"Save failed!");
				restatus = 1;
			}
		}
		else if (c == 0x0F) { // Ctrl+O
			char name[256];
			if (prompt_input("Open: ", name, sizeof(name), 0)) {
				char abs[512]; const char* use = name;
				if (name[0] != '/') { char cwd[256]; osh_get_cwd(cwd, sizeof(cwd)); make_absolute_path(cwd, name, abs, sizeof(abs)); use = abs; }
				if (file_load(&E, use) == 0) { strncpy(E.filename, use, sizeof(E.filename)-1); E.filename[sizeof(E.filename)-1]='\0'; editor_update_syntax(&E); redraw = 1; ui_draw_status(&E, "Opened."); }
				else { ui_draw_status(&E, "Open failed!"); }
				restatus = 1;
			}
		}
		else if (c == 0x0E) { // Ctrl+N
			buf_clear(&E); E.filename[0]='\0'; redraw = 1; ui_draw_status(&E, "New buffer."); restatus = 1;
		}
		else if (c == 0x07) { // Ctrl+G goto line
			char s[16];
			if (prompt_input("Goto line: ", s, sizeof(s), 0)) {
				int n = atoi(s); if (n < 1) n = 1; if (n > E.line_count) n = E.line_count;
				E.cursor_row = n - 1; int len = (int)E.lines[E.cursor_row].len; if (E.cursor_col > len) E.cursor_col = len; ensure_cursor_visible(&E); redraw = 1;
			}
		}
		else if (c == 0x18) { // Ctrl+X
			if (E.modified) {
				char ans[8]; if (prompt_input("Unsaved changes. Quit? (y/N): ", ans, sizeof(ans), 0) && (ans[0]=='y'||ans[0]=='Y')) running = 0;
			} else running = 0;
		}
		else if (c == 0x14) { // Ctrl+T -> смена темы (View)
			cycle_theme();
			ui_draw_menu();
			ui_draw_view(&E);
			restatus = 1; // обновить статус, чтобы перерисовать цвет
			redraw = 0;
		}
		else if ((unsigned char)c == KEY_TAB) { // Tab -> до следующей таб-стопы
			insert_tab(&E);
			redraw = 1;
		}
		else if (c >= 32 && c < 127) {
			if (E.insert_mode) buf_insert_char(&E, E.cursor_row, E.cursor_col, c);
			else buf_overwrite_char(&E, E.cursor_row, E.cursor_col, c);
			E.cursor_col++;
			redraw = 1;
		}

		ensure_cursor_visible(&E);
        // invalidate cache rows affected by edit to guarantee stable repaint under heavy typing
        if (redraw) {
            view_cache_invalidate_line_with_viewtop(E.view_top, E.cursor_row);
            view_cache_invalidate_line_with_viewtop(E.view_top, E.cursor_row - 1);
        }
        // If viewport changed in any direction, force full redraw and reset cache
        if (E.view_top != old_view_top || E.view_left != old_view_left) {
            g_view_cache_valid = 0;
            redraw = 1;
        }
        if (redraw) { ui_draw_view(&E); }
        if (redraw || restatus) { ui_draw_status(&E, 0); }
		ui_place_cursor(&E);
	}

	// leave screen clean
	kclear();
	buf_free(&E);
}


