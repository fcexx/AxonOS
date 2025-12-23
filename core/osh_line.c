#include <osh_line.h>
#include <vga.h>
#include <keyboard.h>
#include <fs.h>
#include <ext2.h>
#include <heap.h>
#include <axosh.h>
#include <stdint.h>
#include <string.h>
#include <devfs.h>

#define OSH_MAX_HISTORY 32
#define OSH_MAX_LINE 512
static char g_hist[DEVFS_TTY_COUNT][OSH_MAX_HISTORY][OSH_MAX_LINE];
static int g_hist_count[DEVFS_TTY_COUNT];
static int g_hist_pos[DEVFS_TTY_COUNT];
static int g_last_ctrlc = 0;
/* navigation state per-tty: saved current line when starting navigation,
   current navigation index and active flag */
static char g_nav_saved[DEVFS_TTY_COUNT][OSH_MAX_LINE];
static int g_nav_index[DEVFS_TTY_COUNT];
static int g_nav_active[DEVFS_TTY_COUNT];

void osh_history_init(void) {
    for (int i = 0; i < DEVFS_TTY_COUNT; i++) { g_hist_count[i] = 0; g_hist_pos[i] = 0; }
    for (int i = 0; i < DEVFS_TTY_COUNT; i++) { g_nav_active[i] = 0; g_nav_index[i] = 0; g_nav_saved[i][0] = '\0'; }
}

void osh_history_add(const char* line) {
    if (!line || !line[0]) return;
    int t = devfs_get_active();
    if (t < 0 || t >= DEVFS_TTY_COUNT) t = 0;
    // skip duplicate of last
    if (g_hist_count[t] > 0 && strncmp(g_hist[t][g_hist_count[t]-1], line, OSH_MAX_LINE)==0) return;
    if (g_hist_count[t] < OSH_MAX_HISTORY) {
        strncpy(g_hist[t][g_hist_count[t]++], line, OSH_MAX_LINE-1);
        g_hist[t][g_hist_count[t]-1][OSH_MAX_LINE-1] = '\0';
    } else {
        // shift up
        for (int i=1;i<OSH_MAX_HISTORY;i++) strncpy(g_hist[t][i-1], g_hist[t][i], OSH_MAX_LINE);
        strncpy(g_hist[t][OSH_MAX_HISTORY-1], line, OSH_MAX_LINE-1);
        g_hist[t][OSH_MAX_HISTORY-1][OSH_MAX_LINE-1] = '\0';
    }
    g_hist_pos[t] = g_hist_count[t];
    /* reset navigation state on new entry */
    g_nav_active[t] = 0;
    g_nav_index[t] = g_hist_count[t];
}

// helpers
#define OSH_PROMPT_CACHE (OSH_MAX_LINE)

static uint32_t measure_colorized_visible(const char* s) {
    if (!s) return 0;
    return (uint32_t)strlen(s);
}

static void redraw_line_xy(uint32_t sx, uint32_t sy, const char* prompt, const char* buf, int len, int cur, const char* sugg, int sugg_len) {
    uint32_t prompt_len = measure_colorized_visible(prompt);
    uint32_t px = sx + prompt_len;

    static uint32_t last_sy = 0xFFFFFFFFu;
    static uint32_t last_sx = 0;
    static uint32_t last_prompt_len = 0;
    static uint32_t last_buf_len = 0;
    static char last_prompt[OSH_PROMPT_CACHE];

    int need_full = 0;
    if (sy != last_sy || sx != last_sx) need_full = 1;
    else if (prompt_len != last_prompt_len || strncmp(prompt, last_prompt, OSH_PROMPT_CACHE) != 0) need_full = 1;

    if (px >= MAX_COLS) {
        px = MAX_COLS;
        need_full = 1;
    }

    if (need_full) {
        for (uint32_t x = sx; x < MAX_COLS; x++) vga_putch_xy(x, sy, ' ', GRAY_ON_BLACK);
        (void)vga_write_str_xy(sx, sy, prompt, GRAY_ON_BLACK);
    } else {
        if (prompt_len < last_prompt_len) {
            uint32_t clear_from = sx + prompt_len;
            uint32_t clear_to = sx + last_prompt_len;
            if (clear_to > MAX_COLS) clear_to = MAX_COLS;
            for (uint32_t x = clear_from; x < clear_to; x++) vga_putch_xy(x, sy, ' ', GRAY_ON_BLACK);
        }
        (void)vga_write_str_xy(sx, sy, prompt, GRAY_ON_BLACK);
    }

    if (px < MAX_COLS) {
        vga_write_str_xy(px, sy, buf, GRAY_ON_BLACK);
        if (!need_full && (uint32_t)len < last_buf_len) {
            uint32_t clear_from = px + (uint32_t)len;
            uint32_t clear_to = px + last_buf_len;
            if (clear_to > MAX_COLS) clear_to = MAX_COLS;
            for (uint32_t x = clear_from; x < clear_to; x++) vga_putch_xy(x, sy, ' ', GRAY_ON_BLACK);
        }
    }

    last_sy = sy;
    last_sx = sx;
    last_buf_len = (uint32_t)len;
    last_prompt_len = prompt_len;
    size_t copy_len = prompt_len;
    if (copy_len >= OSH_PROMPT_CACHE) copy_len = OSH_PROMPT_CACHE - 1;
    if (copy_len > 0) memcpy(last_prompt, prompt, copy_len);
    last_prompt[copy_len] = '\0';

    uint32_t cx = px + (uint32_t)cur;
    if (cx >= MAX_COLS) cx = MAX_COLS ? MAX_COLS - 1 : 0;
    vga_set_cursor(cx, sy);
}

static int list_dir_entries(const char* path, const char*** out_names, int* out_count) {
    *out_names = NULL; *out_count = 0;
    struct fs_file* f = fs_open(path);
    if (!f) return -1;
    if (f->type != FS_TYPE_DIR) { fs_file_free(f); return -1; }
    /* Read directory stream fully (sysfs/devfs can exceed 4K and a single read
       would miss entries, breaking tab completion). */
    size_t cap_bytes = 4096;
    size_t len_bytes = 0;
    uint8_t* buf = (uint8_t*)kmalloc(cap_bytes);
    if (!buf) { fs_file_free(f); return -1; }
    for (;;) {
        if (len_bytes + 1024 > cap_bytes) {
            size_t ncap = cap_bytes * 2;
            if (ncap > 256 * 1024) break; /* hard cap */
            uint8_t* nb = (uint8_t*)kmalloc(ncap);
            if (!nb) break;
            memcpy(nb, buf, len_bytes);
            kfree(buf);
            buf = nb;
            cap_bytes = ncap;
        }
        ssize_t r = fs_read(f, buf + len_bytes, cap_bytes - len_bytes, len_bytes);
        if (r < 0) { kfree(buf); fs_file_free(f); return -1; }
        if (r == 0) break;
        len_bytes += (size_t)r;
    }
    fs_file_free(f);
    if (len_bytes == 0) { kfree(buf); return -1; }
    // грубо посчитаем кол-во записей
    int cap = 64, cnt = 0;
    const char** names = (const char**)kmalloc(sizeof(char*) * cap);
    if (!names) { kfree(buf); return -1; }
    uint32_t off = 0;
    while ((size_t)off + sizeof(struct ext2_dir_entry) <= (size_t)len_bytes) {
        struct ext2_dir_entry* de = (struct ext2_dir_entry*)(buf + off);
        if (de->inode == 0 || de->rec_len == 0) break;
        if (de->rec_len < sizeof(struct ext2_dir_entry)) break;
        if ((size_t)off + (size_t)de->rec_len > (size_t)len_bytes) break;
        if ((size_t)de->name_len > (size_t)de->rec_len - sizeof(struct ext2_dir_entry)) { off += de->rec_len; continue; }
        int nlen = de->name_len; if (nlen <= 0 || nlen > 255) { off += de->rec_len; continue; }
        if (cnt >= cap) {
            int ncap = cap * 2;
            const char** nn = (const char**)kmalloc(sizeof(char*)*ncap);
            if (!nn) break;
            for (int i=0;i<cnt;i++) nn[i]=names[i];
            kfree(names);
            names = nn;
            cap = ncap;
        }
        // создаём временные C-строки поверх нового буфера
        char* s = (char*)kmalloc(nlen+1); if (!s) { off += de->rec_len; continue; }
        memcpy(s, buf + off + sizeof(*de), (size_t)nlen); s[nlen]='\0';
        names[cnt++] = s;
        off += de->rec_len;
    }
    kfree(buf);
    *out_names = names; *out_count = cnt;
    return 0;
}

static void free_name_list(const char** names, int count) {
    for (int i=0;i<count;i++) if (names[i]) kfree((void*)names[i]);
    kfree((void*)names);
}

static int is_sep(char c){ return c==' ' || c=='\t'; }

static void complete_token(const char* cwd, char* buf, int* io_len, int* io_cur, char* sugg, int sugg_cap, int* sugg_len) {
    int len = *io_len, cur = *io_cur;
    if (sugg && sugg_cap>0) { sugg[0]='\0'; *sugg_len = 0; }
    // найдём начало токена
    int start = cur; while (start>0 && !is_sep(buf[start-1])) start--;
    // текущий токен
    char token[256]; int tlen = cur - start; if (tlen<0) tlen=0; if (tlen > 255) tlen = 255;
    memcpy(token, buf+start, (size_t)tlen); token[tlen]='\0';
    /* определим каталог для поиска */
    enum { DIR_CAP = 256, BASE_CAP = 256, ABS_CAP = 512 };
    char *dir = (char*)kmalloc(DIR_CAP);
    if (!dir) return;
    dir[0] = '\0';
    char *base = (char*)kmalloc(BASE_CAP);
    if (!base) { kfree(dir); return; }
    base[0] = '\0';
    const char* slash = NULL; for (int i=0;i<tlen;i++) if (token[i]=='/') slash = &token[i];
    if (slash) {
        int dlen = (int)(slash - token);
        /* Special case: absolute path with slash at position 0 (e.g. "/de").
           In that case directory for listing is "/" (not ""), otherwise
           osh_resolve_path() would treat "" as cwd and completion would fail. */
        if (dlen == 0 && token[0] == '/') {
            strcpy(dir, "/");
        } else {
            if (dlen >= DIR_CAP) dlen = DIR_CAP - 1;
            memcpy(dir, token, (size_t)dlen);
            dir[dlen]='\0';
        }
        strncpy(base, slash+1, BASE_CAP-1);
        base[BASE_CAP-1]='\0';
    } else {
        strcpy(dir, "."); strncpy(base, token, BASE_CAP-1); base[BASE_CAP-1]='\0';
    }
    // построим абсолютный нормализованный путь для dir с учётом '.', '..' и cwd
    /* allocate absolute path buffer sized to cwd+dir when needed to avoid overflow */
    size_t abs_cap = ABS_CAP;
    size_t need_len = 0;
    if (cwd) need_len += strlen(cwd);
    if (dir) need_len += strlen(dir);
    /* +2 for optional '/' and NUL */
    if (need_len + 2 > abs_cap) abs_cap = need_len + 2;
    if (abs_cap > 4096) abs_cap = 4096; /* hard cap */
    char *abs = (char*)kmalloc(abs_cap);
    if (!abs) { kfree(base); kfree(dir); return; }
    osh_resolve_path(cwd, dir, abs, abs_cap);
    // получим список файлов
    const char** fs_names = NULL; int fs_count = 0;
    (void)list_dir_entries(abs, &fs_names, &fs_count); // игнорируем ошибку, просто 0 кандидатов
    // если токен первый (start==0) и нет '/' — добавим builtin команды
    const char** bnames = NULL; int bcount = 0;
    const char** builtin = NULL; int n_builtin = 0;
    if (start == 0 && !slash) {
        n_builtin = osh_get_builtin_names(&builtin);
        if (n_builtin > 0) { bnames = builtin; bcount = n_builtin; }
    }
    // теперь фильтруем по base
    int matches = 0; char common[256]; common[0]='\0';
    char **candidates = NULL;
    // 1) builtin
    for (int i=0;i<bcount;i++) {
        if (strncmp(bnames[i], base, strlen(base))==0) {
            if (matches==0) { strncpy(common, bnames[i], sizeof(common)-1); common[sizeof(common)-1]='\0'; }
            else {
                int k=0; while (common[k] && bnames[i][k] && common[k]==bnames[i][k]) k++;
                common[k]='\0';
            }
            matches++;
        }
    }
    // 2) файловая система
    for (int i=0;i<fs_count;i++) {
        if (strncmp(fs_names[i], base, strlen(base))==0) {
            if (matches==0) { strncpy(common, fs_names[i], sizeof(common)-1); common[sizeof(common)-1]='\0'; }
            else {
                int k=0; while (common[k] && fs_names[i][k] && common[k]==fs_names[i][k]) k++;
                common[k]='\0';
            }
            matches++;
        }
    }
    // отфильтруем по base и найдём общий префикс
    if (matches == 0) goto cleanup;
    // вставим недостающую часть общего префикса
    int add = (int)strlen(common) - (int)strlen(base);
    if (add > 0) {
        /* allow filling up to OSH_MAX_LINE-1 (space for trailing NUL) */
        if (len + add < OSH_MAX_LINE) {
            memmove(buf + cur + add, buf + cur, (size_t)(len - cur + 1));
            memcpy(buf + cur, common + strlen(base), (size_t)add);
            cur += add; len += add;
        }
    } else if (matches > 1 && sugg && sugg_cap>0) {
        /* build list of matches and print them in columns */
        int max_candidates = bcount + fs_count;
        if (max_candidates <= 0) goto after_sugg;
        candidates = (char**)kmalloc(sizeof(char*) * (size_t)max_candidates);
        if (!candidates) goto after_sugg;
        int cand = 0;
        int maxlen = 0;
        size_t baselen = strlen(base);
        for (int i = 0; i < bcount; i++) {
            if (strncmp(bnames[i], base, baselen) == 0) {
                candidates[cand++] = (char*)bnames[i];
                int L = (int)strlen(bnames[i]);
                if (L > maxlen) maxlen = L;
            }
        }
        for (int i = 0; i < fs_count; i++) {
            if (strncmp(fs_names[i], base, baselen) == 0) {
                candidates[cand++] = (char*)fs_names[i];
                int L = (int)strlen(fs_names[i]);
                if (L > maxlen) maxlen = L;
            }
        }
        if (cand > 0) {
            int colw = maxlen + 2;
            if (colw < 8) colw = 8;
            int cols = (int)(MAX_COLS / colw);
            if (cols < 1) cols = 1;
            int rows = (cand + cols - 1) / cols;
            /* build lines into sugg buffer without extra leading/trailing blank lines */
            int outpos = 0;
            for (int r = 0; r < rows; r++) {
                int p = 0;
                for (int c = 0; c < cols; c++) {
                    int idx = c * rows + r;
                    if (idx >= cand) break;
                    const char *nm = candidates[idx];
                    int L = (int)strlen(nm);
                    /* if next name won't fit into MAX_COLS, stop adding more to this line */
                    if (p + L >= MAX_COLS) break;
                    /* append name to a temporary line buffer and then to sugg */
                    if (outpos + L >= (int)sugg_cap) break;
                    memcpy(sugg + outpos, nm, (size_t)L);
                    outpos += L;
                    p += L;
                    /* pad */
                    int pad = colw - L;
                    if (pad < 0) pad = 0;
                    if (p + pad > MAX_COLS) pad = MAX_COLS - p;
                    if (outpos + pad >= (int)sugg_cap) pad = sugg_cap - outpos - 1;
                    for (int z = 0; z < pad; z++) {
                        sugg[outpos++] = ' ';
                        p++;
                    }
                }
                /* terminate line */
                if (outpos + 1 < (int)sugg_cap) {
                    sugg[outpos++] = '\n';
                } else {
                    break;
                }
            }
            if (outpos < (int)sugg_cap) sugg[outpos] = '\0'; else sugg[sugg_cap-1] = '\0';
            *sugg_len = outpos;
        } else {
            *sugg_len = 0;
        }
    }
after_sugg:
    // Если единственное совпадение — файл и это директория, добавим '/' как в bash
    if (matches == 1) {
        // common содержит имя совпадения; abs — абсолютный путь к каталогу для поиска
        char candidate[1024];
        size_t alen = strlen(abs);
        size_t clen = strlen(common);
        if (alen + 1 + clen + 1 < 1024) {
            // сформируем путь abs + '/' + common (без дублирования '/')
            strcpy(candidate, abs);
            if (alen > 0 && candidate[alen-1] != '/') {
                candidate[alen] = '/';
                candidate[alen+1] = '\0';
            }
            strncat(candidate, common, 1024 - strlen(candidate) - 1);
            struct fs_file* cf = fs_open(candidate);
            if (cf) {
                int is_dir = (cf->type == FS_TYPE_DIR);
                fs_file_free(cf);
                if (is_dir) {
                    // вставим '/' если его ещё нет после текущего курсора
                    if (len + 1 < OSH_MAX_LINE) {
                        memmove(buf + cur + 1, buf + cur, (size_t)(len - cur + 1));
                        buf[cur] = '/';
                        cur++; len++;
                    }
                } else {
                    /* single match and not a directory -> append space (like bash) */
                    if (len + 1 < OSH_MAX_LINE) {
                        if (cur >= len || !is_sep(buf[cur])) {
                            memmove(buf + cur + 1, buf + cur, (size_t)(len - cur + 1));
                            buf[cur] = ' ';
                            cur++; len++;
                        }
                    }
                }
            } else {
                /* candidate not found in filesystem -> likely a builtin; append space */
                if (len + 1 < OSH_MAX_LINE) {
                    if (cur >= len || !is_sep(buf[cur])) {
                        memmove(buf + cur + 1, buf + cur, (size_t)(len - cur + 1));
                        buf[cur] = ' ';
                        cur++; len++;
                    }
                }
            }
        }
    }
    *io_len = len; *io_cur = cur;
cleanup:
    if (candidates) kfree(candidates);
    if (fs_names) free_name_list(fs_names, fs_count);
    if (abs) kfree(abs);
    if (base) kfree(base);
    if (dir) kfree(dir);
}

int osh_line_read(const char* prompt, const char* cwd, char* out, int out_size) {
    if (!out || out_size <= 1) return -1;
    g_last_ctrlc = 0;
    char buf[OSH_MAX_LINE]; int len = 0, cur = 0;
    buf[0]='\0';
    uint32_t sx=0, sy=0; vga_get_cursor(&sx, &sy);
    char sugg[512]; int sugg_len = 0; sugg[0] = '\0';
    redraw_line_xy(sx, sy, prompt, buf, len, cur, sugg, sugg_len);
    for (;;) {
        char c = kgetc();
        if (c == 3) {
            keyboard_consume_ctrlc();
            g_last_ctrlc = 1;
            kprint((uint8_t*)"^C\n");
            return -1;
        }
        if (c == '\n' || c == '\r') {
            buf[len]='\0'; strncpy(out, buf, (size_t)out_size-1); out[out_size-1]='\0';
            kprint((uint8_t*)"\n");
            /* reset history navigation/position for current tty */
            int t = devfs_get_active(); if (t < 0 || t >= DEVFS_TTY_COUNT) t = 0;
            g_hist_pos[t] = g_hist_count[t];
            g_nav_active[t] = 0;
            g_nav_index[t] = g_hist_count[t];
            g_nav_saved[t][0] = '\0';
            return len;
        }
        if ((unsigned char)c == KEY_LEFT) { if (cur>0) cur--; }
        else if ((unsigned char)c == KEY_RIGHT) { if (cur<len) cur++; }
        else if ((unsigned char)c == KEY_HOME) { cur = 0; }
        else if ((unsigned char)c == KEY_END) { cur = len; }
        else if ((unsigned char)c == KEY_UP) {
            int t = devfs_get_active(); if (t < 0 || t >= DEVFS_TTY_COUNT) t = 0;
            if (g_hist_count[t] == 0) {
                /* nothing to show */
            } else {
                /* start navigation if not active */
                if (!g_nav_active[t]) {
                    g_nav_active[t] = 1;
                    g_nav_index[t] = g_hist_count[t]; /* one-past-last */
                    /* save current line */
                    strncpy(g_nav_saved[t], buf, OSH_MAX_LINE-1);
                    g_nav_saved[t][OSH_MAX_LINE-1] = '\0';
                }
                /* move up */
                if (g_nav_index[t] > 0) g_nav_index[t]--;
                /* show entry or saved */
                if (g_nav_index[t] >= 0 && g_nav_index[t] < g_hist_count[t]) {
                    strncpy(buf, g_hist[t][g_nav_index[t]], OSH_MAX_LINE - 1);
                    buf[OSH_MAX_LINE-1] = '\0';
                    len = (int)strlen(buf); cur = len;
                } else {
                    /* one-past-last -> show saved original */
                    strncpy(buf, g_nav_saved[t], OSH_MAX_LINE-1);
                    buf[OSH_MAX_LINE-1] = '\0';
                    len = (int)strlen(buf); cur = len;
                }
            }
        }
        else if ((unsigned char)c == KEY_DOWN) {
            int t = devfs_get_active(); if (t < 0 || t >= DEVFS_TTY_COUNT) t = 0;
            if (g_hist_count[t] == 0) {
                buf[0] = '\0'; len = 0; cur = 0;
                g_nav_active[t] = 0;
                g_nav_index[t] = g_hist_count[t];
            } else {
                if (!g_nav_active[t]) {
                    g_nav_active[t] = 1;
                    g_nav_index[t] = g_hist_count[t]; /* start from saved */
                    strncpy(g_nav_saved[t], buf, OSH_MAX_LINE-1);
                    g_nav_saved[t][OSH_MAX_LINE-1] = '\0';
                }
                if (g_nav_index[t] < g_hist_count[t]) g_nav_index[t]++;
                if (g_nav_index[t] >= 0 && g_nav_index[t] < g_hist_count[t]) {
                    strncpy(buf, g_hist[t][g_nav_index[t]], OSH_MAX_LINE - 1);
                    buf[OSH_MAX_LINE-1] = '\0';
                    len = (int)strlen(buf); cur = len;
                } else {
                    /* one-past-last -> saved/or empty */
                    strncpy(buf, g_nav_saved[t], OSH_MAX_LINE-1);
                    buf[OSH_MAX_LINE-1] = '\0';
                    len = (int)strlen(buf); cur = len;
                }
            }
        }
        else if ((unsigned char)c == KEY_DELETE) {
            int t = devfs_get_active(); if (t < 0 || t >= DEVFS_TTY_COUNT) t = 0;
            g_nav_active[t] = 0;
            if (cur < len) { memmove(buf+cur, buf+cur+1, (size_t)(len-cur)); len--; buf[len]='\0'; }
        }
        else if (c == 8 || c == 127) {
            int t = devfs_get_active(); if (t < 0 || t >= DEVFS_TTY_COUNT) t = 0;
            g_nav_active[t] = 0;
            if (cur>0) { memmove(buf+cur-1, buf+cur, (size_t)(len-cur+1)); cur--; len--; }
        }
        else if ((unsigned char)c == KEY_TAB) {
            complete_token(cwd, buf, &len, &cur, sugg, (int)sizeof(sugg), &sugg_len);
            if (sugg_len > 0) {
                /* Print matches in columns; only insert leading newline if prompt not at column 0 */
                uint32_t cx = 0, cy = 0;
                vga_get_cursor(&cx, &cy);
                if (cx != 0) kprintf("\n");
                kprintf("%s\n", sugg);
                vga_get_cursor(&sx, &sy);
            }
        }
        else if (c >= 32 && c < 127) {
            int t = devfs_get_active(); if (t < 0 || t >= DEVFS_TTY_COUNT) t = 0;
            /* typing clears history navigation state */
            g_nav_active[t] = 0;
            if (len+1 < OSH_MAX_LINE) {
                memmove(buf+cur+1, buf+cur, (size_t)(len-cur+1));
                buf[cur]=c; cur++; len++;
            }
            // любой обычный ввод — очистить подсказки
            sugg[0]='\0'; sugg_len=0;
        }
        redraw_line_xy(sx, sy, prompt, buf, len, cur, sugg, sugg_len);
    }
}

int osh_line_was_ctrlc(void) {
    int v = g_last_ctrlc;
    g_last_ctrlc = 0;
    return v;
}




