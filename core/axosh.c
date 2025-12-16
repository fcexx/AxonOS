// AxonOS shell (osh): bash-like minimal interpreter with pipes and redirections
#include "../inc/stdint.h"
#include <stddef.h>
#include <string.h>
#include "../inc/axosh.h"
#include "../inc/vga.h"
#include "../inc/keyboard.h"
#include "../inc/heap.h"
#include "../inc/fs.h"
#include "../inc/ext2.h"
#include "../inc/ramfs.h"
#include "../inc/devfs.h"
#include "../inc/fat32.h"
#include "../inc/osh_line.h"
#include "../inc/user.h"
// local prototype for kprintf
void kprintf(const char* fmt, ...);
/* snprintf is implemented in drv/vga.c, declare it here */
int snprintf(char* out, size_t outsz, const char* fmt, ...);
/* forward declare password reader and util */
static int read_password(const char *prompt, char *buf, int bufsize);
static unsigned int parse_uint(const char *s);
// forward decls for optional chipset commands
void intel_print_chipset_info(void);
void intel_chipset_reset(void);
#include "../inc/thread.h"
#include "../inc/editor.h"
#include "../inc/sysinfo.h"

typedef long ssize_t;

// forward declare minimal RTC API to avoid include issues
typedef struct { uint8_t second, minute, hour, day, month; uint16_t year; } rtc_datetime_t;
extern volatile uint64_t rtc_ticks;
void rtc_read_datetime(rtc_datetime_t* dt);

// -------- util --------
static char g_cwd[256] = "/";

// -------- variables (simple key->string store) --------
typedef struct { char name[32]; char* value; } osh_var;
static osh_var g_vars[128];
static int g_var_count = 0;

static int is_var_name_char1(char c){ return (c=='_' || (c>='a'&&c<='z') || (c>='A'&&c<='Z')); }
static int is_var_name_char(char c){ return (c=='_' || (c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9')); }

static int is_valid_varname(const char* s){
    if (!s||!s[0]) return 0;
    if (!is_var_name_char1(s[0])) return 0;
    for (int i=1;s[i];i++) if (!is_var_name_char(s[i])) return 0;
    return 1;
}

static int var_lookup(const char* name, const char** out_val){
    if (!name) return 0;
    for (int i=0;i<g_var_count;i++){
        if (strcmp(g_vars[i].name, name)==0){
            if (out_val) *out_val = g_vars[i].value ? g_vars[i].value : "";
            return 1;
        }
    }
    if (out_val) *out_val = "";
    return 0;
}

static const char* var_get(const char* name){
    const char* val = "";
    (void)var_lookup(name, &val);
    return val;
}

static void var_set(const char* name, const char* value){
    if (!name) return;
    for (int i=0;i<g_var_count;i++){
        if (strcmp(g_vars[i].name, name)==0){
            if (g_vars[i].value) kfree(g_vars[i].value);
            size_t n = value ? strlen(value) : 0;
            g_vars[i].value = (char*)kcalloc(n+1,1);
            if (g_vars[i].value && value) memcpy(g_vars[i].value, value, n);
            return;
        }
    }
    if (g_var_count < (int)(sizeof(g_vars)/sizeof(g_vars[0]))){
        strncpy(g_vars[g_var_count].name, name, sizeof(g_vars[g_var_count].name)-1);
        g_vars[g_var_count].name[sizeof(g_vars[g_var_count].name)-1]='\0';
        size_t n = value ? strlen(value) : 0;
        g_vars[g_var_count].value = (char*)kcalloc(n+1,1);
        if (g_vars[g_var_count].value && value) memcpy(g_vars[g_var_count].value, value, n);
        g_var_count++;
    }
}

static char* expand_vars(const char* in) {
    if (!in) return NULL;
    size_t n = strlen(in);
    size_t cap = n + 1;
    char* out = (char*)kmalloc(cap);
    if (!out) return NULL;
    size_t oi=0;
    for (size_t i=0;i<n;i++){
        if (in[i] == '$' && i+1 < n && is_var_name_char1(in[i+1])) {
            size_t j = i+1;
            char name[32]; int k=0;
            while (j<n && is_var_name_char(in[j]) && k < (int)sizeof(name)-1) name[k++] = in[j++];
            name[k]='\0';
            const char* val = var_get(name);
            size_t vl = strlen(val);
            // ensure capacity
            if (oi + vl + 1 > cap) {
                size_t ncap = cap; while (oi + vl + 1 > ncap) ncap *= 2;
                char* nb = (char*)kmalloc(ncap);
                if (!nb) { kfree(out); return NULL; }
                if (oi) memcpy(nb, out, oi);
                kfree(out); out = nb; cap = ncap;
            }
            if (vl) { memcpy(out+oi, val, vl); oi += vl; }
            i = j - 1;
            continue;
        }
        if (oi + 2 > cap) {
            size_t ncap = cap*2; char* nb=(char*)kmalloc(ncap); if (!nb){ kfree(out); return NULL; }
            if (oi) memcpy(nb, out, oi); kfree(out); out=nb; cap=ncap;
        }
        out[oi++] = in[i];
    }
    if (oi < cap) out[oi] = '\0'; else { char* nb=(char*)kmalloc(cap+1); if(nb){ memcpy(nb,out,cap); nb[cap]='\0'; kfree(out); out=nb; } }
    return out;
}

// Replace bare identifiers with their variable values (for conditions like "a == 2")
static char* osh_expand_idents(const char* in) {
    if (!in) return NULL;
    size_t cap = strlen(in) + 1;
    char* out = (char*)kmalloc(cap);
    if (!out) return NULL;
    size_t oi = 0;
    for (size_t i=0; in[i]; ) {
        char c = in[i];
        if (is_var_name_char1(c)) {
            // collect identifier
            char name[32]; int ni=0;
            size_t j=i;
            while (in[j] && is_var_name_char(in[j]) && ni < (int)sizeof(name)-1) { name[ni++] = in[j++]; }
            name[ni]='\0';
            const char* val = NULL;
            if (var_lookup(name, &val)) {
                size_t vl = val ? strlen(val) : 0;
                if (oi + vl + 1 > cap) {
                    size_t ncap = cap; while (oi + vl + 1 > ncap) ncap *= 2;
                    char* nb = (char*)kmalloc(ncap);
                    if (!nb) { kfree(out); return NULL; }
                    if (oi) memcpy(nb, out, oi);
                    kfree(out); out = nb; cap = ncap;
                }
                if (vl) { memcpy(out+oi, val, vl); oi += vl; }
                i = j;
                continue;
            } else {
                size_t vl = (size_t)ni;
                if (oi + vl + 1 > cap) {
                    size_t ncap = cap; while (oi + vl + 1 > ncap) ncap *= 2;
                    char* nb = (char*)kmalloc(ncap);
                    if (!nb) { kfree(out); return NULL; }
                    if (oi) memcpy(nb, out, oi);
                    kfree(out); out = nb; cap = ncap;
                }
                if (vl) { memcpy(out+oi, name, vl); oi += vl; }
                i = j;
                continue;
            }
        }
        // copy single char
        if (oi + 2 > cap) {
            size_t ncap = cap*2; char* nb=(char*)kmalloc(ncap); if (!nb){ kfree(out); return NULL; }
            if (oi) memcpy(nb, out, oi); kfree(out); out=nb; cap=ncap;
        }
        out[oi++] = c; i++;
    }
    if (oi < cap) out[oi] = '\0'; else { char* nb=(char*)kmalloc(cap+1); if(nb){ memcpy(nb,out,cap); nb[cap]='\0'; kfree(out); out=nb; } }
    return out;
}

static char* osh_dup_trim(const char* src) {
    if (!src) return (char*)kcalloc(1,1);
    while (*src==' '||*src=='\t') src++;
    size_t len = strlen(src);
    while (len>0 && (src[len-1]==' '||src[len-1]=='\t')) len--;
    char* out = (char*)kcalloc(len+1,1);
    if (!out) return NULL;
    if (len) memcpy(out, src, len);
    out[len]='\0';
    return out;
}

static double osh_parse_expr(const char** ps);

static void trim_spaces(char* s) {
    if (!s) return;
    char* p = s;
    while (*p==' '||*p=='\t') p++;
    if (p != s) {
        size_t rem = strlen(p);
        memmove(s, p, rem + 1);
    }
    size_t len = strlen(s);
    while (len>0 && (s[len-1]==' '||s[len-1]=='\t')) s[--len]='\0';
}

static void strip_matching_quotes(char* s) {
    if (!s) return;
    size_t len = strlen(s);
    if (len >= 2) {
        char first = s[0];
        char last = s[len-1];
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            memmove(s, s + 1, len - 2);
            s[len - 2] = '\0';
        }
    }
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int osh_exec_subcommand(const char* line, char **out_value);
static int osh_eval_command_subst(char* expr_buf, int* handled, char** out_value);
static int osh_eval_function_call(char* expr_buf, int* handled, char** out_value);
static int osh_eval_rhs(char* expr_buf, char** out_value);
static int osh_eval_expr_to_string(const char* expr, char** out_value);
static int osh_assign_value(const char* name, char* rhs);

static int osh_try_parse_number(const char* text, double* out_val) {
    if (!text) return 0;
    const char* p = text;
    double v = osh_parse_expr(&p);
    while (*p==' '||*p=='\t') p++;
    if (*p != '\0') return 0;
    if (out_val) *out_val = v;
    return 1;
}

static int line_is_brace_only(const char* s) {
    if (!s) return 0;
    while (*s==' '||*s=='\t') s++;
    if (!*s) return 0;
    for (const char* p = s; *p; p++) {
        if (!(*p=='{' || *p=='}' || *p==' ' || *p=='\t')) return 0;
    }
    return 1;
}

static void osh_write(char **out, size_t *len, size_t *cap, const char *s) {
    if (!s) return;
    size_t add = strlen(s);
    if (add == 0) return;
    size_t need = *len + add + 1;
    if (need > *cap) {
        size_t ncap = (*cap ? *cap : 128);
        while (ncap < need) ncap *= 2;
        char *nb = (char*)kmalloc(ncap);
        if (!nb) return;
        if (*out && *len) memcpy(nb, *out, *len);
        if (*out) kfree(*out);
        *out = nb; *cap = ncap;
    }
    memcpy(*out + *len, s, add);
    *len += add; (*out)[*len] = '\0';
}

// very simple join: if arg starts with '/', copy; else cwd + '/' + arg (no normalization)
static void resolve_path(const char *cwd, const char *arg, char *out, size_t outlen);

static void join_cwd(const char* cwd, const char* arg, char* out, size_t outsz) {
    resolve_path(cwd, arg, out, outsz);
}

static void resolve_path(const char *cwd, const char *arg, char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    if (!cwd || !cwd[0]) cwd = "/";
    if (!arg || !arg[0]) {
        size_t copy = strlen(cwd);
        if (copy >= outlen) copy = outlen - 1;
        memcpy(out, cwd, copy);
        out[copy] = '\0';
        return;
    }

    char tmp[512];
    size_t pos = 0;
    if (arg[0] == '/') {
        size_t copy = strlen(arg);
        if (copy >= sizeof(tmp)) copy = sizeof(tmp) - 1;
        memcpy(tmp, arg, copy);
        tmp[copy] = '\0';
    } else {
        size_t base_len = strlen(cwd);
        if (base_len >= sizeof(tmp)) base_len = sizeof(tmp) - 1;
        if (cwd[0] != '/') {
            tmp[pos++] = '/';
        }
        if (base_len == 0) {
            tmp[pos++] = '/';
        } else {
            size_t bl = base_len;
            while (bl > 1 && cwd[bl - 1] == '/') bl--;
            if (pos + bl >= sizeof(tmp)) bl = sizeof(tmp) - 1 - pos;
            if (bl > 0) {
                memcpy(tmp + pos, cwd, bl);
                pos += bl;
            }
        }
        if (pos == 0) {
            tmp[pos++] = '/';
        }
        if (tmp[pos - 1] != '/' && pos < sizeof(tmp) - 1) {
            tmp[pos++] = '/';
        }
        size_t arg_len = strlen(arg);
        if (pos + arg_len >= sizeof(tmp)) arg_len = sizeof(tmp) - 1 - pos;
        memcpy(tmp + pos, arg, arg_len);
        pos += arg_len;
        tmp[pos] = '\0';
    }

    char *parts[64];
    size_t plen[64];
    int pc = 0;
    char *cursor = tmp;
    while (*cursor) {
        while (*cursor == '/') cursor++;
        if (!*cursor) break;
        char *seg = cursor;
        while (*cursor && *cursor != '/') cursor++;
        size_t len = (size_t)(cursor - seg);
        if (len == 0) { if (*cursor == '/') cursor++; continue; }
        if (len == 1 && seg[0] == '.') {
            /* skip '.' */
        } else if (len == 2 && seg[0] == '.' && seg[1] == '.') {
            if (pc > 0) pc--;
        } else {
            if (pc < (int)(sizeof(parts)/sizeof(parts[0]))) {
                parts[pc] = seg;
                plen[pc] = len;
                pc++;
            }
        }
        if (*cursor == '/') cursor++;
    }

    if (pc == 0) {
        out[0] = '/';
        out[1] = '\0';
        return;
    }

    size_t w = 0;
    for (int i = 0; i < pc; i++) {
        size_t seg_len = plen[i];
        if (w + 1 >= outlen) {
            out[outlen - 1] = '\0';
            return;
        }
        out[w++] = '/';
        size_t copy = seg_len;
        if (w + copy >= outlen) copy = outlen - 1 - w;
        if (copy > 0) {
            memcpy(out + w, parts[i], copy);
            w += copy;
        }
    }
    out[w] = '\0';
}

static int is_dir_path(const char *path) {
    if (!path || !path[0]) return 0;
    /* Trim trailing slashes to avoid confusing drivers with "/dir///" */
    char norm[256];
    strncpy(norm, path, sizeof(norm)-1);
    norm[sizeof(norm)-1] = '\0';
    size_t nl = strlen(norm);
    while (nl > 1 && norm[nl - 1] == '/') { norm[--nl] = '\0'; }
    struct fs_file *f = fs_open(norm);
    if (!f) return 0;
    int dir = (f->type == FS_TYPE_DIR);
    if (!dir && f->type == FS_TYPE_UNKNOWN) {
        size_t want = f->size ? f->size : 512; if (want > 8192) want = 8192; void *buf = kmalloc(want+1);
        if (buf) {
            ssize_t r = fs_read(f, buf, want, 0);
            if (r > 0) { struct ext2_dir_entry *de = (struct ext2_dir_entry*)buf; if (de->rec_len) dir = 1; }
            kfree(buf);
        }
    }
    fs_file_free(f); return dir;
}

// -------- lexer --------
typedef enum { T_WORD, T_AND, T_OR, T_PIPE, T_BG, T_GT, T_LT } tok_t;
typedef struct { tok_t t; char *s; } token;

static token* lex(const char *line, int *out_n) {
    int cap = 16, n = 0; token *v = (token*)kcalloc((size_t)cap, sizeof(token));
    const char *p = line; while (*p) {
        while (*p==' '||*p=='\t') p++;
        if (!*p) break;
        // treat '>' and '<' as redirection operators
        if (*p == '>') { if (n==cap){cap*=2; v=(token*)krealloc(v, (size_t)cap*sizeof(token));} v[n++] = (token){T_GT, NULL}; p++; continue; }
        if (*p == '<') { if (n==cap){cap*=2; v=(token*)krealloc(v, (size_t)cap*sizeof(token));} v[n++] = (token){T_LT, NULL}; p++; continue; }
        if (p[0]=='&' && p[1]=='&') { if (n==cap){cap*=2; v=(token*)krealloc(v, (size_t)cap*sizeof(token));} v[n++] = (token){T_AND, NULL}; p+=2; continue; }
        if (p[0]=='|' && p[1]=='|') { if (n==cap){cap*=2; v=(token*)krealloc(v, (size_t)cap*sizeof(token));} v[n++] = (token){T_OR, NULL}; p+=2; continue; }
        if (*p=='|') { if (n==cap){cap*=2; v=(token*)krealloc(v, (size_t)cap*sizeof(token));} v[n++] = (token){T_PIPE, NULL}; p++; continue; }
        if (*p=='&') { if (n==cap){cap*=2; v=(token*)krealloc(v, (size_t)cap*sizeof(token));} v[n++] = (token){T_BG, NULL}; p++; continue; }
        // word (support quotes)
        const char *start = p; char buf[512]; int bi=0; int inq=0;
        while (*p && !( !inq && (*p==' '||*p=='\t'||*p=='|'||*p=='&') )) {
            if (*p=='"') { 
                /* preserve quotes in token so strip_matching_quotes can remove them later */
                if (bi < (int)sizeof(buf)-1) buf[bi++] = *p;
                p++;
                inq = !inq;
                continue;
            }
            (void)start;
            if (bi < (int)sizeof(buf)-1) buf[bi++] = *p; p++;
        }
        buf[bi] = '\0';
        char *ws = expand_vars(buf); if (!ws) { ws = (char*)kmalloc((size_t)bi+1); memcpy(ws, buf, (size_t)bi+1); }
        if (n==cap){cap*=2; v=(token*)krealloc(v, (size_t)cap*sizeof(token));}
        v[n++] = (token){T_WORD, ws}; (void)start;
    }
    *out_n = n; return v;
}

static void free_tokens(token *v, int n) { for (int i=0;i<n;i++) if (v[i].t==T_WORD && v[i].s) kfree(v[i].s); kfree(v); }

// Forward declaration for script engine to call command executor
int exec_line(const char *line);

// -------- simple arithmetic parser for assignments (double) --------
static double osh_parse_expr(const char** ps);
static double osh_parse_number(const char** ps){
    double v=0.0;
    while (**ps==' '||**ps=='\t') (*ps)++;
    int neg = 0;
    if (**ps=='+' || **ps=='-') { if (**ps=='-') neg=1; (*ps)++; }
    // integer part
    while (**ps>='0'&&**ps<='9'){ v = v*10.0 + (double)(**ps - '0'); (*ps)++; }
    // fractional part
    if (**ps=='.'){ (*ps)++; double base = 0.1; while (**ps>='0'&&**ps<='9'){ v += base * (double)(**ps - '0'); base *= 0.1; (*ps)++; } }
    if (neg) v = -v;
    while (**ps==' '||**ps=='\t') (*ps)++;
    return v;
}
static double osh_parse_factor(const char** ps){
    while (**ps==' '||**ps=='\t') (*ps)++;
    if (**ps=='('){
        (*ps)++;
        double v=osh_parse_expr(ps);
        while (**ps==' '||**ps=='\t') (*ps)++;
        if (**ps==')') (*ps)++;
        while (**ps==' '||**ps=='\t') (*ps)++;
        return v;
    }
    return osh_parse_number(ps);
}
static double osh_parse_term(const char** ps){
    double v=osh_parse_factor(ps);
    for(;;){
        while (**ps==' '||**ps=='\t') (*ps)++;
        if (**ps=='*'){ (*ps)++; double r=osh_parse_factor(ps); v*=r; }
        else if (**ps=='/'){ (*ps)++; double r=osh_parse_factor(ps); if (r!=0.0) v/=r; }
        else break;
    }
    return v;
}
static double osh_parse_expr(const char** ps){
    double v=osh_parse_term(ps);
    for(;;){
        while (**ps==' '||**ps=='\t') (*ps)++;
        if (**ps=='+'){ (*ps)++; double r=osh_parse_term(ps); v+=r; }
        else if (**ps=='-'){ (*ps)++; double r=osh_parse_term(ps); v-=r; }
        else break;
    }
    return v;
}

static void osh_double_to_str(double val, char* out, size_t outsz){
    if (outsz==0) return;
    // handle NaN/Inf not expected; round to 6 decimals, trim trailing zeros
    double scaled = val * 1000000.0;
    long long int_scaled = (scaled >= 0.0)
        ? (long long)(scaled + 0.5)
        : (long long)(scaled - 0.5);
    double rounded = (double)int_scaled / 1000000.0;
    int neg = (rounded < 0.0);
    double abs_val = neg ? -rounded : rounded;
    long long ip = (long long)abs_val;
    double frac = abs_val - (double)ip;
    int fd = (int)(frac*1000000.0 + 0.5);
    if (fd >= 1000000) { fd -= 1000000; ip += 1; }

    // convert integer part
    char ibuf[64]; int in=0; long long t = ip;
    if (t==0){
        if (neg) ibuf[in++]='-';
        ibuf[in++]='0';
    } else {
        if (neg) ibuf[in++]='-';
        char tmp[32]; int k=0;
        while (t){
            tmp[k++] = (char)('0' + (t%10));
            t/=10;
        }
        for (int i=k-1;i>=0;i--) ibuf[in++]=tmp[i];
    }
    ibuf[in]='\0';
    // fractional with 6 digits
    char fbuf[16]; int fn=0;
    if (fd>0){
        // write 6 digits with leading zeros
        char tmp[8]; for (int i=5;i>=0;i--){ tmp[i] = (char)('0' + (fd%10)); fd/=10; }
        int end=5; while (end>=0 && tmp[end]=='0') end--;
        if (end>=0){
            fbuf[fn++]='.';
            for (int i=0;i<=end;i++) fbuf[fn++]=tmp[i];
        }
    }
    fbuf[fn]='\0';
    // combine
    size_t need = (size_t)in + (size_t)fn + 1;
    size_t pos=0;
    if (outsz>0){
        size_t ci = (size_t)in < outsz-1 ? (size_t)in : outsz-1; if (ci){ memcpy(out+pos, ibuf, ci); pos+=ci; }
        size_t cf = (size_t)fn < (outsz-1-pos) ? (size_t)fn : (outsz-1-pos); if (cf){ memcpy(out+pos, fbuf, cf); pos+=cf; }
        out[pos]='\0';
    }
}

// ---- Simple script engine for bi_osh ----
typedef struct { char name[32]; char *params[8]; int pc; int header; int start; int end; } osh_func_def;
typedef struct {
    char **lines;
    int nlines;
    osh_func_def *funcs;
    int nfuncs;
} osh_script_ctx;

typedef struct {
    char* cond;        // NULL indicates unconditional else branch
    int body_start;    // inclusive (valid when inline_cmd == NULL)
    int body_end;      // exclusive (line index of closing brace)
    char* inline_cmd;  // non-NULL for single-line bodies
} osh_if_branch;

static int g_script_depth = 0;

#define OSH_SCRIPT_OK 0
#define OSH_SCRIPT_EXIT 100
#define OSH_SCRIPT_ABORT 101
#define OSH_SCRIPT_RETURN 102

static osh_script_ctx* g_active_script_ctx = NULL;
static int g_script_return_pending = 0;
static char* g_script_return_value = NULL;

static int osh_find_func(osh_script_ctx* C, const char* nm) {
    for (int i=0;i<C->nfuncs;i++) if (strcmp(C->funcs[i].name, nm)==0) return i; return -1;
}

static int osh_eval_expr_to_string(const char* expr, char** out_value) {
    if (out_value) *out_value = NULL;
    size_t len = expr ? strlen(expr) : 0;
    char* tmp = (char*)kcalloc(len + 1, 1);
    if (!tmp) return 1;
    if (expr && len) memcpy(tmp, expr, len + 1);
    int rc = osh_eval_rhs(tmp, out_value);
    kfree(tmp);
    if (rc == OSH_SCRIPT_ABORT || rc == OSH_SCRIPT_EXIT || rc == OSH_SCRIPT_RETURN) {
        if (out_value && *out_value) { kfree(*out_value); *out_value = NULL; }
        return rc;
    }
    if (out_value && !*out_value) *out_value = (char*)kcalloc(1,1);
    return rc;
}

static int osh_eval_cond(const char* expr) {
    char *ex = expand_vars(expr);
    const char* e0 = ex ? ex : expr;
    char *ei = osh_expand_idents(e0);
    const char* e = ei ? ei : e0;

    int which = -1, pos = -1, oplen = 0;
    if (e) {
        for (int i = 0; e[i]; i++) {
            char c = e[i];
            char n = e[i+1];
            if (c=='=' && n=='=') { which = 0; pos = i; oplen = 2; break; }
            if (c=='!' && n=='=') { which = 1; pos = i; oplen = 2; break; }
            if (c=='<' && n=='=') { which = 2; pos = i; oplen = 2; break; }
            if (c=='>' && n=='=') { which = 3; pos = i; oplen = 2; break; }
            if (c=='<') { which = 4; pos = i; oplen = 1; break; }
            if (c=='>') { which = 5; pos = i; oplen = 1; break; }
        }
    }

    int res = 0;
    if (which >= 0) {
        char left[256], right[256];
        int ln = pos; if (ln > 255) ln = 255;
        memcpy(left, e, (size_t)ln); left[ln]='\0';
        const char* rp = e + pos + oplen;
        while (*rp==' '||*rp=='\t') rp++;
        strncpy(right, rp, sizeof(right)-1); right[sizeof(right)-1]='\0';
        trim_spaces(left);
        trim_spaces(right);

        char* left_val = NULL;
        char* right_val = NULL;
        int rc_left = osh_eval_expr_to_string(left, &left_val);
        int rc_right = osh_eval_expr_to_string(right, &right_val);
        if (rc_left == 0 && rc_right == 0) {
            if (!left_val) left_val = (char*)kcalloc(1,1);
            if (!right_val) right_val = (char*)kcalloc(1,1);
            double lv = 0.0, rv = 0.0;
            int left_is_num = osh_try_parse_number(left_val, &lv);
            int right_is_num = osh_try_parse_number(right_val, &rv);
            int both_numeric = left_is_num && right_is_num;

            if (which == 0 || which == 1) {
                if (both_numeric) {
                    double eps = 1e-9;
                    res = (which == 0)
                        ? ((lv - rv < eps) && (rv - lv < eps))
                        : !((lv - rv < eps) && (rv - lv < eps));
                } else {
                    strip_matching_quotes(left_val);
                    strip_matching_quotes(right_val);
                    int cmp = strcmp(left_val, right_val);
                    res = (which == 0) ? (cmp == 0) : (cmp != 0);
                }
            } else {
                if (both_numeric) {
                    double eps = 1e-9;
                    switch (which) {
                        case 2: res = (lv <= rv + eps); break;
                        case 3: res = (lv + eps >= rv); break;
                        case 4: res = (lv < rv - eps); break;
                        case 5: res = (lv > rv + eps); break;
                    }
                } else {
                    strip_matching_quotes(left_val);
                    strip_matching_quotes(right_val);
                    int cmp = strcmp(left_val, right_val);
                    switch (which) {
                        case 2: res = (cmp <= 0); break;
                        case 3: res = (cmp >= 0); break;
                        case 4: res = (cmp < 0); break;
                        case 5: res = (cmp > 0); break;
                    }
                }
            }
        }
        if (left_val) kfree(left_val);
        if (right_val) kfree(right_val);
    } else {
        char* val = NULL;
        if (osh_eval_expr_to_string(e, &val) == 0) {
            if (!val) val = (char*)kcalloc(1,1);
            double v = 0.0;
            if (osh_try_parse_number(val, &v)) {
                res = (v != 0.0);
            } else {
                strip_matching_quotes(val);
                res = (val[0] != '\0');
            }
        }
        if (val) kfree(val);
    }

    if (ei) kfree(ei);
    if (ex) kfree(ex);
    return res;
}

static int osh_exec_range(osh_script_ctx* C, int L, int R);

// -------- block parsing helpers (robust, single-pass) --------
static int osh_find_block(osh_script_ctx* C, int from_line, int *out_body_start, int *out_end_line) {
    if (!C || from_line < 0 || from_line >= C->nlines) return -1;
    int depth = 0;
    int saw_open = 0;
    int body_start = -1;
    for (int l = from_line; l < C->nlines; l++) {
        char *s = C->lines[l];
        if (!s) continue;
        for (char *p = s; *p; p++) {
            if (*p == '{') {
                depth++;
                if (!saw_open) {
                    saw_open = 1;
                    body_start = l + 1;
                }
            } else if (*p == '}') {
                if (depth > 0) depth--;
                if (saw_open && depth == 0) {
                    if (out_body_start) *out_body_start = body_start;
                    if (out_end_line) *out_end_line = l;
                    return 0;
                }
            }
        }
    }
    return -1; // not found
}

static void osh_extract_condition(const char* src, char* out, size_t cap) {
    if (!out || cap == 0) return;
    size_t idx = 0;
    if (src) {
        const char *p = src;
        while (*p==' '||*p=='\t') p++;
        while (*p && *p!='{' && idx + 1 < cap) {
            out[idx++] = *p++;
        }
    }
    out[idx] = '\0';
    while (idx>0 && (out[idx-1]==' '||out[idx-1]=='\t')) out[--idx]='\0';
}

static char* osh_extract_inline_cmd(const char* line) {
    if (!line) return (char*)kcalloc(1,1);
    const char *open = strchr(line, '{');
    const char *close = open ? strchr(open + 1, '}') : NULL;
    if (!open || !close || close <= open + 1) return (char*)kcalloc(1,1);
    size_t len = (size_t)(close - (open + 1));
    char *tmp = (char*)kcalloc(len + 1, 1);
    if (!tmp) return NULL;
    memcpy(tmp, open + 1, len);
    tmp[len] = '\0';
    char *trimmed = osh_dup_trim(tmp);
    kfree(tmp);
    if (!trimmed) trimmed = (char*)kcalloc(1,1);
    return trimmed;
}

static int osh_collect_if_branches(osh_script_ctx* C, int header_line, osh_if_branch* branches, int max_branches, int *out_next_line) {
    if (!C || !branches || max_branches <= 0) return 0;
    char cond_buf[256];
    const char *line = C->lines[header_line];
    const char *after_if = NULL;
    if (line) {
        const char *trim = line;
        while (*trim==' '||*trim=='\t') trim++;
        if (strncmp(trim, "if", 2) == 0) {
            after_if = trim + 2;
        }
    }
    osh_extract_condition(after_if, cond_buf, sizeof(cond_buf));
    char *cond_dup = osh_dup_trim(cond_buf);
    if (!cond_dup) cond_dup = (char*)kcalloc(1,1);

    int bstart=-1, bend=-1;
    if (osh_find_block(C, header_line, &bstart, &bend) != 0) {
        if (cond_dup) kfree(cond_dup);
        return 0;
    }

    int count = 0;
    char *inline_cmd = NULL;
    if (bstart > bend) inline_cmd = osh_extract_inline_cmd(C->lines[header_line]);
    branches[count++] = (osh_if_branch){cond_dup, bstart, bend, inline_cmd};

    int scan = bend + 1;
    while (scan < C->nlines && count < max_branches) {
        line = C->lines[scan];
        if (!line) { scan++; continue; }
        const char *trim = line;
        while (*trim==' '||*trim=='\t') trim++;
        // skip lines that are purely closing braces
        int only_closing = 1;
        for (const char *q=line; *q; q++) {
            if (*q!=' ' && *q!='\t' && *q!='}') { only_closing = 0; break; }
        }
        if (only_closing) { scan++; continue; }
        while (*trim=='}') trim++;
        while (*trim==' '||*trim=='\t') trim++;

        if (strncmp(trim, "else if", 7) == 0) {
            char cond_buf2[256];
            osh_extract_condition(trim + 7, cond_buf2, sizeof(cond_buf2));
            char *dup = osh_dup_trim(cond_buf2);
            if (!dup) dup = (char*)kcalloc(1,1);
            if (osh_find_block(C, scan, &bstart, &bend) != 0) { if (dup) kfree(dup); scan++; continue; }
            char *inline_if = NULL;
            if (bstart > bend) inline_if = osh_extract_inline_cmd(line);
            branches[count++] = (osh_if_branch){dup, bstart, bend, inline_if};
            scan = bend + 1;
            continue;
        } else if (strncmp(trim, "else", 4) == 0) {
            if (osh_find_block(C, scan, &bstart, &bend) != 0) { scan++; continue; }
            char *inline_else = NULL;
            if (bstart > bend) inline_else = osh_extract_inline_cmd(line);
            branches[count++] = (osh_if_branch){NULL, bstart, bend, inline_else};
            scan = bend + 1;
            break;
        } else {
            break;
        }
    }
    if (out_next_line) *out_next_line = scan;
    return count;
}
static int osh_call_func(osh_script_ctx* C, int fi, char** args, int ac, char** out_ret) {
    const int pc = C->funcs[fi].pc;
    const char* saved_names[8];
    char* saved_vals[8];
    for (int i=0;i<pc && i<8;i++){
        const char* pname = C->funcs[fi].params[i];
        saved_names[i] = pname;
        char* copy = NULL;
        const char* old = var_get(pname);
        if (old) {
            size_t len = strlen(old);
            copy = (char*)kcalloc(len+1,1);
            if (copy) memcpy(copy, old, len+1);
        }
        saved_vals[i] = copy;
        char* source = (i<ac && args[i]) ? args[i] : NULL;
        char* arg_copy = NULL;
        if (source) {
            size_t sl = strlen(source);
            arg_copy = (char*)kcalloc(sl+1,1);
            if (arg_copy) memcpy(arg_copy, source, sl+1);
        } else {
            arg_copy = (char*)kcalloc(1,1);
        }
        char* evaluated = NULL;
        int eval_rc = osh_eval_rhs(arg_copy ? arg_copy : "", &evaluated);
        if (arg_copy) kfree(arg_copy);
        if (eval_rc == OSH_SCRIPT_ABORT || eval_rc == OSH_SCRIPT_EXIT || eval_rc == OSH_SCRIPT_RETURN) {
            for (int j=0;j<=i;j++){
                if (saved_vals[j]) { var_set(saved_names[j], saved_vals[j]); kfree(saved_vals[j]); }
                else var_set(saved_names[j], "");
            }
            if (evaluated) kfree(evaluated);
            return eval_rc;
        }
        var_set(pname, evaluated ? evaluated : "");
        if (evaluated) kfree(evaluated);
    }
    osh_script_ctx* prev_ctx = g_active_script_ctx;
    int prev_flag = g_script_return_pending;
    char* prev_ret = g_script_return_value;
    g_active_script_ctx = C;
    g_script_return_pending = 0;
    g_script_return_value = NULL;

    int rc = osh_exec_range(C, C->funcs[fi].start, C->funcs[fi].end);

    char* func_ret = g_script_return_value;
    int has_ret = g_script_return_pending;

    g_active_script_ctx = prev_ctx;
    g_script_return_pending = prev_flag;
    g_script_return_value = prev_ret;

    for (int i=0;i<pc && i<8;i++){
        const char* pname = saved_names[i];
        if (saved_vals[i]) { var_set(pname, saved_vals[i]); kfree(saved_vals[i]); }
        else var_set(pname, "");
    }

    if (has_ret) {
        if (out_ret) *out_ret = func_ret ? func_ret : (char*)kcalloc(1,1);
        else if (func_ret) kfree(func_ret);
        return OSH_SCRIPT_OK;
    } else {
        if (func_ret) kfree(func_ret);
        if (out_ret) *out_ret = (char*)kcalloc(1,1);
    }
    return rc;
}

static int osh_exec_range(osh_script_ctx* C, int L, int R) {
    int li = L;
    while (li < R) {
        if (keyboard_ctrlc_pending()) {
            keyboard_consume_ctrlc();
            return OSH_SCRIPT_ABORT;
        }
        int prev_li = li;
        int skipped_def = 0;
        for (int fi=0; fi<C->nfuncs; fi++) {
            if (li == C->funcs[fi].header) {
                li = C->funcs[fi].end + 1;
                skipped_def = 1;
                break;
            }
        }
        if (skipped_def) continue;
        char *s0 = C->lines[li];
        while (*s0==' '||*s0=='\t') s0++;
        if (!*s0 || *s0=='#') { li++; continue; }
        if (line_is_brace_only(s0)) { li++; continue; }

        if (strncmp(s0, "if ", 3)==0) {
            osh_if_branch branches[16];
            int next_line = li + 1;
            int count = osh_collect_if_branches(C, li, branches, 16, &next_line);
            if (count <= 0) { li++; continue; }
            int exec_rc = OSH_SCRIPT_OK;
            for (int bi=0; bi<count; bi++) {
                int cond_true = (!branches[bi].cond) ? 1 : osh_eval_cond(branches[bi].cond);
                if (cond_true) {
                    if (branches[bi].inline_cmd && branches[bi].inline_cmd[0]) {
                        int rc_line = exec_line(branches[bi].inline_cmd);
                        if (rc_line == OSH_SCRIPT_EXIT) exec_rc = OSH_SCRIPT_EXIT;
                        else if (rc_line == 2) exec_rc = OSH_SCRIPT_EXIT;
                        else if (rc_line == OSH_SCRIPT_ABORT) exec_rc = OSH_SCRIPT_ABORT;
                        else if (rc_line == OSH_SCRIPT_RETURN) exec_rc = OSH_SCRIPT_RETURN;
                    } else if (!branches[bi].inline_cmd) {
                        exec_rc = osh_exec_range(C, branches[bi].body_start, branches[bi].body_end);
                    }
                    break;
                }
            }
            for (int bi=0; bi<count; bi++) {
                if (branches[bi].cond) kfree(branches[bi].cond);
                if (branches[bi].inline_cmd) kfree(branches[bi].inline_cmd);
            }
            li = next_line;
            if (exec_rc != OSH_SCRIPT_OK) return exec_rc;
            continue;
        }

        if (strncmp(s0, "while ", 6)==0) {
            char *cond = s0 + 6;
            char condw_buf[256]; int wi=0; char *pwc=cond;
            while (*pwc && *pwc!='{' && wi<255) { condw_buf[wi++]=*pwc++; }
            condw_buf[wi]='\0';
            int wl = (int)strlen(condw_buf);
            while (wl>0 && (condw_buf[wl-1]==' '||condw_buf[wl-1]=='\t')) condw_buf[--wl]='\0';
            int woff = 0; while (condw_buf[woff]==' '||condw_buf[woff]=='\t') woff++;
            char *openb = strchr(s0, '{');
            char *closeb = openb ? strchr(openb, '}') : NULL;
            if (openb && closeb && closeb > openb) {
                int guard = 0;
                while (osh_eval_cond(condw_buf + woff)) {
                    if (keyboard_ctrlc_pending()) {
                        keyboard_consume_ctrlc();
                        return OSH_SCRIPT_ABORT;
                    }
                    char inner[512];
                    int ilen = (int)(closeb - (openb + 1));
                    if (ilen >= (int)sizeof(inner)) ilen = (int)sizeof(inner) - 1;
                    if (ilen > 0) {
                        memcpy(inner, openb + 1, (size_t)ilen);
                        inner[ilen] = '\0';
                        int rc_line = exec_line(inner);
                        if (rc_line == OSH_SCRIPT_EXIT) return OSH_SCRIPT_EXIT;
                        if (rc_line == 2) return OSH_SCRIPT_EXIT;
                        if (rc_line == OSH_SCRIPT_ABORT) return OSH_SCRIPT_ABORT;
                        if (rc_line == OSH_SCRIPT_RETURN) return OSH_SCRIPT_RETURN;
                    }
                    if (++guard > 100000) break;
                }
                li++;
                continue;
            }
            int depth=0, bstart=-1, bend=-1, cur=li, started=0;
            for (; cur<R; cur++) {
                char *t = C->lines[cur]; while (*t==' '||*t=='\t') t++;
                for (char* q=t; *q; q++){
                    if(*q=='{'){
                        depth++;
                        if (!started) { started=1; bstart=cur+1; }
                    } else if(*q=='}'){
                        if (depth>0) {
                            depth--;
                            if (started && depth==0){ bend=cur; goto got_while_block; }
                        }
                    }
                }
            }
        got_while_block:
            if (bstart < 0 || bend < 0) { li++; continue; }
            int iter = 0;
            while (osh_eval_cond(condw_buf + woff)) {
                if (keyboard_ctrlc_pending()) {
                    keyboard_consume_ctrlc();
                    return OSH_SCRIPT_ABORT;
                }
                int sub = osh_exec_range(C, bstart, bend);
                if (sub != OSH_SCRIPT_OK) return sub;
                if (++iter > 100000) break;
            }
            li = bend + 1;
            continue;
        }

        if (strncmp(s0, "else if ", 8)==0) {
            char *cond = s0 + 8;
            int depth=0, bstart=-1, bend=-1, cur=li, started=0;
            for (; cur<R; cur++) {
                char *t = C->lines[cur]; while (*t==' '||*t=='\t') t++;
                for (char* q=t; *q; q++){
                    if(*q=='{'){ depth++; if (!started){ started=1; bstart=cur+1; } }
                    else if(*q=='}'){ if (depth>0){ depth--; if(started && depth==0){ bend=cur; goto got_else_if_block; } } }
                }
            }
        got_else_if_block:
            if (bstart >= 0 && bend >= 0) {
                if (osh_eval_cond(cond)) {
                    int sub = osh_exec_range(C, bstart, bend);
                    if (sub != OSH_SCRIPT_OK) return sub;
                }
                li = bend + 1;
                continue;
            } else {
                li++;
                continue;
            }
        }

        if (strncmp(s0, "else", 4)==0) {
            int depth=0, bstart=-1, bend=-1, cur=li, started=0;
            for (; cur<R; cur++) {
                char *t = C->lines[cur]; while (*t==' '||*t=='\t') t++;
                for (char* q=t; *q; q++){
                    if(*q=='{'){ depth++; if (!started){ started=1; bstart=cur+1; } }
                    else if(*q=='}'){ if (depth>0){ depth--; if(started && depth==0){ bend=cur; goto got_else_block; } } }
                }
            }
        got_else_block:
            if (bstart >= 0 && bend >= 0) {
                int sub = osh_exec_range(C, bstart, bend);
                if (sub != OSH_SCRIPT_OK) return sub;
                li = bend + 1;
                continue;
            } else {
                li++;
                continue;
            }
        }

        {
            char name[32]; int ni=0; const char* p=s0;
            while ((*p=='_'||(*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')) && ni<31) { name[ni++]=*p++; }
            name[ni]='\0';
            if (ni>0 && *p=='(') {
                int fi = osh_find_func(C, name);
                if (fi>=0) {
                    p++;
                    char *args[8]; int ac=0; char token[256]; int ti=0; int inq=0; int had_quote=0;
                    while (*p && *p != ')') {
                        if (!inq && (*p==',')) {
                            token[ti]='\0';
                            char *trimmed = osh_dup_trim(token);
                            if (trimmed) {
                                if ((trimmed[0] || had_quote || ti>0) && ac < 8) args[ac++] = trimmed; else kfree(trimmed);
                            }
                            had_quote = 0;
                            ti=0; p++; continue;
                        }
                        if (*p=='"'){ inq=!inq; had_quote=1; p++; continue; }
                        if (ti < (int)sizeof(token)-1) token[ti++]=*p++; else p++;
                    }
                    token[ti]='\0';
                    char *trimmed = osh_dup_trim(token);
                    if (trimmed) {
                        if ((trimmed[0] || had_quote || ti>0 || ac>0) && ac < 8) args[ac++] = trimmed; else kfree(trimmed);
                    }
                    char* ret_tmp = NULL;
                    int call_rc = osh_call_func(C, fi, args, ac, &ret_tmp);
                    for (int i2=0;i2<ac;i2++) if (args[i2]) kfree(args[i2]);
                    if (ret_tmp) kfree(ret_tmp);
                    if (call_rc != OSH_SCRIPT_OK) return call_rc;
                    li++; continue;
                }
            }
        }

        int rc = exec_line(s0);
        if (rc == OSH_SCRIPT_EXIT) return OSH_SCRIPT_EXIT;
        if (rc == 2) return 2;
        if (rc == OSH_SCRIPT_ABORT) return OSH_SCRIPT_ABORT;
        if (rc == OSH_SCRIPT_RETURN) return OSH_SCRIPT_RETURN;
        li++;
        if (li == prev_li) li++;
    }
    return OSH_SCRIPT_OK;
}

// -------- builtins --------
typedef struct { char **argv; int argc; const char *in; char **out; size_t *out_len; size_t *out_cap; } cmd_ctx;

// forward to allow builtins to execute lines
int exec_line(const char *line);

static int out_printf(cmd_ctx *c, const char *s) { osh_write(c->out, c->out_len, c->out_cap, s); return 0; }

static int bi_echo(cmd_ctx *c) {
    if (c->argc <= 1) { out_printf(c, "\n"); return 0; }
    for (int i=1;i<c->argc;i++) { out_printf(c, c->argv[i]); if (i+1<c->argc) out_printf(c, " "); }
    out_printf(c, "\n");
    return 0;
}

static int bi_pwd(cmd_ctx *c) { (void)c; char tmp[300]; strncpy(tmp, g_cwd, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0'; osh_write(c->out, c->out_len, c->out_cap, tmp); osh_write(c->out, c->out_len, c->out_cap, "\n"); return 0; }

static int bi_cd(cmd_ctx *c) {
    const char *arg = c->argc>1 ? c->argv[1] : "/";
    char path[256]; join_cwd(g_cwd, arg, path, sizeof(path));
    if (!is_dir_path(path)) {
        osh_write(c->out, c->out_len, c->out_cap, "cd: not a directory: ");
        osh_write(c->out, c->out_len, c->out_cap, path);
        osh_write(c->out, c->out_len, c->out_cap, "\n");
        return 1;
    }
    size_t l = strlen(path); if (l>1 && path[l-1]=='/') path[l-1]='\0'; strncpy(g_cwd, path, sizeof(g_cwd)-1); g_cwd[sizeof(g_cwd)-1]='\0'; return 0;
}

static int bi_cls(cmd_ctx *c) { (void)c; kclear(); return 0; }

static int bi_readline(cmd_ctx *c) {
    char prompt_buf[256];
    prompt_buf[0] = '\0';
    if (c->argc > 1) {
        size_t pos = 0;
        for (int i = 1; i < c->argc; i++) {
            const char* part = c->argv[i] ? c->argv[i] : "";
            size_t L = strlen(part);
            if (pos && pos < sizeof(prompt_buf) - 1) {
                prompt_buf[pos++] = ' ';
            }
            if (L > sizeof(prompt_buf) - 1 - pos) {
                L = sizeof(prompt_buf) - 1 - pos;
            }
            if (L > 0) {
                memcpy(prompt_buf + pos, part, L);
                pos += L;
            }
            if (pos >= sizeof(prompt_buf) - 1) break;
        }
        prompt_buf[pos] = '\0';
    }
    const char* prompt = prompt_buf;
    char cwd[256]; osh_get_cwd(cwd, sizeof(cwd));
    char linebuf[512];
    int n = osh_line_read(prompt, cwd, linebuf, (int)sizeof(linebuf));
    if (n < 0) {
        if (osh_line_was_ctrlc()) return OSH_SCRIPT_ABORT;
        linebuf[0] = '\0';
    } else {
        if (n >= (int)sizeof(linebuf)) n = (int)sizeof(linebuf) - 1;
        linebuf[n] = '\0';
    }
    osh_write(c->out, c->out_len, c->out_cap, linebuf);
    return 0;
}

static int bi_readkey(cmd_ctx *c) {
    (void)c;
    char ch = kgetc();
    if (ch == 3) {
        keyboard_consume_ctrlc();
        return OSH_SCRIPT_ABORT;
    }
    unsigned char uc = (unsigned char)ch;
    char outbuf[8];
    if (uc >= 32 && uc < 127) {
        outbuf[0] = (char)uc;
        outbuf[1] = '\0';
    } else {
        static const char hex_digits[] = "0123456789ABCDEF";
        outbuf[0] = '0';
        outbuf[1] = 'x';
        outbuf[2] = hex_digits[(uc >> 4) & 0xF];
        outbuf[3] = hex_digits[uc & 0xF];
        outbuf[4] = '\0';
    }
    osh_write(c->out, c->out_len, c->out_cap, outbuf);
    return 0;
}

static int bi_whoami(cmd_ctx *c) {
    (void)c;
    const char *name = user_get_current_name();
    if (!name) name = ROOT_USER_NAME;
    kprintf("%s\n", name);
    return 0;
}

static int bi_mkpasswd(cmd_ctx *c) {
    if (c->argc < 3) { kprintf("usage: mkpasswd <user> <password>\n"); return 1; }
    const char *name = c->argv[1];
    const char *pass = c->argv[2];
    struct user *u = user_find(name);
    if (!u) { kprintf("mkpasswd: user not found\n"); return 1; }
    if (user_set_password(name, pass) == 0) { kprintf("ok\n"); return 0; }
    kprintf("mkpasswd: failed\n");
    return 1;
}

static int bi_groups(cmd_ctx *c) {
    const char *name = NULL;
    if (c->argc >= 2) name = c->argv[1];
    else name = user_get_current_name();
    struct user *u = user_find(name);
    if (!u) { kprintf("groups: user not found\n"); return 1; }
    if (u->groups && u->groups[0]) kprintf("%s\n", u->groups);
    else kprintf("\n");
    return 0;
}

static int bi_passwd(cmd_ctx *c) {
    const char *name = NULL;
    if (c->argc >= 2) name = c->argv[1];
    else name = user_get_current_name();
    struct user *u = user_find(name);
    if (!u) { kprintf("passwd: user not found\n"); return 1; }
    char prompt[64];
    char passbuf[128];
    snprintf(prompt, sizeof(prompt), "New password for %s: ", name);
    if (read_password(prompt, passbuf, (int)sizeof(passbuf)) < 0) { kprintf("passwd: abort\n"); return 1; }
    if (user_set_password(name, passbuf) == 0) { kprintf("passwd: OK\n"); return 0; }
    kprintf("passwd: failed\n");
    return 1;
}

static int bi_su(cmd_ctx *c) {
    if (c->argc < 2) { kprintf("usage: su <user>\n"); return 1; }
    const char *name = c->argv[1];
    struct user *u = user_find(name);
    if (!u) { kprintf("su: user not found\n"); return 1; }
    char prompt[64]; char passbuf[128];
    snprintf(prompt, sizeof(prompt), "Password for %s: ", name);
    if (read_password(prompt, passbuf, (int)sizeof(passbuf)) < 0) { kprintf("su: abort\n"); return 1; }
    if (user_check_password(name, passbuf)) {
        user_set_current(name);
        /* set thread credentials so subsequent checks use per-thread euid/egid */
        thread_t* ct = thread_current();
        if (ct) { ct->euid = u->uid; ct->egid = u->gid; }
        kprintf("su: switched to %s\n", name);
        return 0;
    } else {
        kprintf("su: authentication failed\n");
        return 1;
    }
}

static int bi_useradd(cmd_ctx *c) {
    if (c->argc < 2) { kprintf("usage: useradd <user> [uid] [gid]\n"); return 1; }
    const char *name = c->argv[1];
    uid_t uid_val = 0;
    unsigned int gid_val = 1000;
    if (c->argc >= 3) uid_val = (uid_t)parse_uint(c->argv[2]);
    if (c->argc >= 4) gid_val = parse_uint(c->argv[3]);
    if (uid_val == 0) uid_val = user_get_next_uid();
    if (user_add(name, uid_val, gid_val, "") != 0) { kprintf("useradd: failed\n"); return 1; }
    /* regenerate /etc/passwd */
    char *buf = NULL; size_t bl = 0;
    if (user_export_passwd(&buf, &bl) == 0 && buf) {
        struct fs_file *f = fs_open("/etc/passwd");
        if (!f) f = fs_create_file("/etc/passwd");
        if (f) { fs_write(f, buf, bl, 0); fs_file_free(f); }
        kfree(buf);
    }
    kprintf("useradd: created %s\n", name);
    return 0;
}

static int bi_groupadd(cmd_ctx *c) {
    if (c->argc < 2) { kprintf("usage: groupadd <group> [gid]\n"); return 1; }
    const char *name = c->argv[1];
    unsigned int gid_val = 1000;
    if (c->argc >= 3) gid_val = parse_uint(c->argv[2]);
    char line[128];
    int n = snprintf(line, sizeof(line), "%s:x:%u:\n", name, gid_val);
    if (n <= 0) { kprintf("groupadd: failed\n"); return 1; }
    struct fs_file *f = fs_open("/etc/group");
    if (!f) f = fs_create_file("/etc/group");
    if (!f) { kprintf("groupadd: cannot open /etc/group\n"); return 1; }
    /* append at end */
    size_t off = f->size;
    fs_write(f, line, (size_t)n, off);
    fs_file_free(f);
    kprintf("groupadd: created %s\n", name);
    return 0;
}

/* Read password without echo into buf (NUL-terminated). Returns length or -1 on abort. */
static int read_password(const char *prompt, char *buf, int bufsize) {
    if (!buf || bufsize <= 1) return -1;
    kprintf("%s", prompt);
    int pos = 0;
    while (1) {
        char c = kgetc();
        if (c == 3) { keyboard_consume_ctrlc(); kprintf("\n"); return -1; } // Ctrl-C
        if (c == '\n' || c == '\r') { kprintf("\n"); break; }
        if (c == 8 || c == 127) { if (pos > 0) pos--; continue; }
        if (c >= 32 && c < 127) {
            if (pos + 1 < bufsize) {
                buf[pos++] = c;
            }
        }
    }
    buf[(pos < bufsize) ? pos : (bufsize-1)] = '\0';
    return pos;
}

static unsigned int parse_uint(const char *s) {
    unsigned int v = 0;
    if (!s) return 0;
    for (const char *p = s; *p; p++) {
        if (*p >= '0' && *p <= '9') v = v * 10 + (unsigned int)(*p - '0');
        else break;
    }
    return v;
}

static int bi_kprint(cmd_ctx *c) {
    if (c->argc <= 1) return 0;
    size_t alloc = 1;
    for (int i = 1; i < c->argc; i++) {
        if (c->argv[i]) alloc += strlen(c->argv[i]);
        if (i + 1 < c->argc) alloc++;
    }
    char *buf = (char*)kcalloc(alloc, 1);
    if (!buf) return 1;
    size_t pos = 0;
    for (int i = 1; i < c->argc; i++) {
        const char* s = c->argv[i] ? c->argv[i] : "";
        for (size_t j = 0; s[j]; j++) {
            if (pos + 1 >= alloc) break;
            char ch = s[j];
            if (ch == '\\' && s[j+1]) {
                j++;
                char esc = s[j];
                if (esc == 'n') { buf[pos++] = '\n'; }
                else if (esc == 't') { buf[pos++] = '\t'; }
                else if (esc == 'r') { buf[pos++] = '\r'; }
                else if (esc == '\\') { buf[pos++] = '\\'; }
                else if (esc == '"') { buf[pos++] = '"'; }
                else if (esc == 'x') {
                    int value = 0;
                    int consumed = 0;
                    while (consumed < 2 && s[j+1]) {
                        int hv = hex_value(s[j+1]);
                        if (hv < 0) break;
                        value = (value << 4) | hv;
                        j++;
                        consumed++;
                    }
                    buf[pos++] = (char)value;
                } else {
                    buf[pos++] = esc;
                }
            } else {
                buf[pos++] = ch;
            }
        }
        if (i + 1 < c->argc && pos + 1 < alloc) buf[pos++] = ' ';
    }
    buf[pos] = '\0';
    if (pos > 0) {
        buf[pos] = '\0';
        osh_write(c->out, c->out_len, c->out_cap, buf);
        osh_write(c->out, c->out_len, c->out_cap, "\n");
    }
    kfree(buf);
    return 0;
}

static int bi_ls(cmd_ctx *c) {
    char path[256]; if (c->argc<2) resolve_path(g_cwd, "", path, sizeof(path)); else resolve_path(g_cwd, c->argv[1], path, sizeof(path));
    struct fs_file *f = fs_open(path); if (!f) { osh_write(c->out, c->out_len, c->out_cap, "ls: cannot access\n"); return 1; }
    if (f->type != FS_TYPE_DIR) { osh_write(c->out, c->out_len, c->out_cap, c->argv[1] ? c->argv[1] : path); osh_write(c->out, c->out_len, c->out_cap, "\n"); fs_file_free(f); return 0; }
    size_t want = f->size ? f->size : 4096;
    void *buf = kmalloc(want+1);
    ssize_t r = buf ? fs_read(f, buf, want, 0) : 0;
    if (r > 0) {
        // Соберём все имена в список, сохраняя информацию о директориях
        int cap = 64, cnt = 0;
        char **names = (char**)kmalloc(sizeof(char*) * cap);
        int *is_dir = (int*)kmalloc(sizeof(int) * cap);
        uint32_t off = 0;
        while ((size_t)off < (size_t)r) {
            struct ext2_dir_entry *de = (struct ext2_dir_entry*)((uint8_t*)buf+off);
            if (de->inode==0 || de->rec_len==0) break;
            int nlen = de->name_len; if (nlen>255) nlen = 255;
            if (cnt >= cap) {
                int ncap = cap * 2;
                char **nn = (char**)kmalloc(sizeof(char*) * ncap);
                int *nd = (int*)kmalloc(sizeof(int) * ncap);
                for (int i=0;i<cnt;i++) { nn[i] = names[i]; nd[i] = is_dir[i]; }
                kfree(names); kfree(is_dir);
                names = nn; is_dir = nd; cap = ncap;
            }
            char *s = (char*)kmalloc(nlen + 2); // +1 for possible '/' +1 for '\0'
            if (!s) { off += de->rec_len; continue; }
            memcpy(s, (uint8_t*)buf+off+sizeof(*de), (size_t)nlen);
            s[nlen] = '\0';
            names[cnt] = s;
            is_dir[cnt] = (de->file_type == EXT2_FT_DIR) ? 1 : 0;
            cnt++;
            off += de->rec_len;
        }

        // Если нет элементов — ничего не делаем
        if (cnt == 0) {
            if (names) kfree(names);
            if (is_dir) kfree(is_dir);
        } else {
            // Вычислим ширину столбца
            int maxlen = 0;
            for (int i=0;i<cnt;i++) {
                int L = (int)strlen(names[i]) + (is_dir[i] ? 1 : 0);
                if (L > maxlen) maxlen = L;
            }
            int colw = maxlen + 2; if (colw < 8) colw = 8;
            int cols = MAX_COLS / colw; if (cols < 1) cols = 1;
            int rows = (cnt + cols - 1) / cols;

            // Формируем список с stat'ами и выводим в формате столбцов (права uid gid size name)
            typedef struct { char *name; int is_dir; struct stat st; } ent_t;
            ent_t *ents = (ent_t*)kmalloc(sizeof(ent_t) * cnt);
            int nents = 0;
            for (int i=0;i<cnt;i++) {
                if (strcmp(names[i], ".")==0 || strcmp(names[i],"..")==0) continue;
                ents[nents].name = names[i];
                ents[nents].is_dir = is_dir[i];
                char childpath[512];
                if (path[strlen(path)-1] == '/') {
                    snprintf(childpath, sizeof(childpath), "%s%s", path, names[i]);
                } else {
                    snprintf(childpath, sizeof(childpath), "%s/%s", path, names[i]);
                }
                if (vfs_stat(childpath, &ents[nents].st) != 0) {
                    memset(&ents[nents].st, 0, sizeof(ents[nents].st));
                }
                nents++;
            }
            // простой сортировщик (bubble) по имени
            for (int a = 0; a < nents; a++) {
                for (int b = a+1; b < nents; b++) {
                    if (strcmp(ents[a].name, ents[b].name) > 0) {
                        ent_t tmp = ents[a]; ents[a] = ents[b]; ents[b] = tmp;
                    }
                }
            }
            /* compute column widths for uid/gid/size to align like linux ls */
            int uid_w = 0, gid_w = 0, size_w = 0;
            for (int i = 0; i < nents; i++) {
                struct stat *s = &ents[i].st;
                unsigned long u = (unsigned long)s->st_uid;
                unsigned long g = (unsigned long)s->st_gid;
                unsigned long z = (unsigned long)s->st_size;
                int du = 1, dg = 1, dz = 1;
                unsigned long tmp;
                tmp = u; while (tmp >= 10) { du++; tmp /= 10; }
                tmp = g; while (tmp >= 10) { dg++; tmp /= 10; }
                tmp = z; while (tmp >= 10) { dz++; tmp /= 10; }
                if (du > uid_w) uid_w = du;
                if (dg > gid_w) gid_w = dg;
                if (dz > size_w) size_w = dz;
            }
            if (uid_w < 3) uid_w = 3;
            if (gid_w < 3) gid_w = 3;
            if (size_w < 4) size_w = 4;

            char line[512];
            for (int i = 0; i < nents; i++) {
                struct stat *s = &ents[i].st;
                char perms[11];
                perms[0] = (s->st_mode & S_IFDIR) ? 'd' : '-';
                perms[1] = (s->st_mode & 0400) ? 'r' : '-';
                perms[2] = (s->st_mode & 0200) ? 'w' : '-';
                perms[3] = (s->st_mode & 0100) ? 'x' : '-';
                perms[4] = (s->st_mode & 0040) ? 'r' : '-';
                perms[5] = (s->st_mode & 0020) ? 'w' : '-';
                perms[6] = (s->st_mode & 0010) ? 'x' : '-';
                perms[7] = (s->st_mode & 0004) ? 'r' : '-';
                perms[8] = (s->st_mode & 0002) ? 'w' : '-';
                perms[9] = (s->st_mode & 0001) ? 'x' : '-';
                perms[10] = '\0';
                int uid = (int)s->st_uid;
                int gid = (int)s->st_gid;
                long sizev = (long)s->st_size;
                int n = snprintf(line, sizeof(line), "%s %*d %*d %*ld %s%s\n",
                    perms, uid_w, uid, gid_w, gid, size_w, sizev, ents[i].name, ents[i].is_dir ? "/" : "");
                if (n > 0) osh_write(c->out, c->out_len, c->out_cap, line);
            }
            // свободим вспомогательные массивы (names элементы уже используются в ents)
            kfree(is_dir);
            kfree(ents);
            // освободим имена, так как они были kmalloc'ированы
            for (int i=0;i<cnt;i++) if (names[i]) kfree(names[i]);
            kfree(names);
        }
    }
    if (buf) kfree(buf); fs_file_free(f); return 0;
}

static int bi_cat(cmd_ctx *c) {
    if (c->argc <= 1) { if (c->in) { osh_write(c->out, c->out_len, c->out_cap, c->in); } return 0; }
    int rc = 0;
    for (int i=1;i<c->argc;i++) {
        char path[256]; join_cwd(g_cwd, c->argv[i], path, sizeof(path)); struct fs_file *f = fs_open(path);
        if (!f) { osh_write(c->out, c->out_len, c->out_cap, "cat: no such file\n"); rc=1; continue; }
        int is_tty = thread_fd_isatty(1);
        size_t bufsize = 4096;
        unsigned char *buf = (unsigned char*)kmalloc(bufsize);
        if (!buf) { fs_file_free(f); return 1; }
        size_t off = 0;
        while (1) {
            ssize_t r = fs_read(f, buf, bufsize, off);
            if (r < 0) break;
            if (r == 0) break;
            if (is_tty) {
                /* write directly to VGA/console to enable streaming */
                for (ssize_t bi = 0; bi < r; bi++) kputchar(buf[bi], GRAY_ON_BLACK);
            } else {
                /* append to pipeline output buffer */
                if (r > 0) {
                    /* ensure NUL-termination for osh_write usage */
                    char *tmp = (char*)kmalloc((size_t)r + 1);
                    if (tmp) {
                        memcpy(tmp, buf, (size_t)r);
                        tmp[r] = '\0';
                        osh_write(c->out, c->out_len, c->out_cap, tmp);
                        kfree(tmp);
                    }
                }
            }
            off += (size_t)r;
            /* if file is character device, continue indefinitely until Ctrl-C */
            if (f->size == 0) {
                if (keyboard_ctrlc_pending()) { keyboard_consume_ctrlc(); break; }
                continue;
            }
        }
        kfree(buf);
        fs_file_free(f);
    }
    return rc;
}

static int bi_mkdir(cmd_ctx *c) {
    if (c->argc<2) { osh_write(c->out, c->out_len, c->out_cap, "mkdir: missing operand\n"); return 1; }
    char arg[256]; size_t L = strlen(c->argv[1]); if (L >= sizeof(arg)) L = sizeof(arg)-1; memcpy(arg, c->argv[1], L); arg[L]='\0';
    strip_matching_quotes(arg);
    char path[256]; join_cwd(g_cwd, arg, path, sizeof(path));
    int r = fs_mkdir(path); return r==0?0:1;
}

static int bi_touch(cmd_ctx *c) {
    if (c->argc<2) { osh_write(c->out, c->out_len, c->out_cap, "touch: missing operand\n"); return 1; }
    char arg[256]; size_t L = strlen(c->argv[1]); if (L >= sizeof(arg)) L = sizeof(arg)-1; memcpy(arg, c->argv[1], L); arg[L]='\0';
    strip_matching_quotes(arg);
    char path[256]; join_cwd(g_cwd, arg, path, sizeof(path));
    struct fs_file *f = fs_create_file(path); if (!f) return 1; fs_file_free(f); return 0;
}

static int bi_rm(cmd_ctx *c) {
    if (c->argc<2) { osh_write(c->out, c->out_len, c->out_cap, "rm: missing operand\n"); return 1; }
    char arg[256]; size_t L = strlen(c->argv[1]); if (L >= sizeof(arg)) L = sizeof(arg)-1; memcpy(arg, c->argv[1], L); arg[L]='\0';
    strip_matching_quotes(arg);
    char path[256]; join_cwd(g_cwd, arg, path, sizeof(path));
    int r = ramfs_remove(path); return r==0?0:1;
}

#include "../inc/axonos.h"

static int bi_about(cmd_ctx *c) { 
    (void)c;
    kprintf("%s v%s\n", OS_NAME, OS_VERSION);
    kprintf("Copyright (c) 2025 %s Team\n", OS_AUTHORS);
    kprintf("fcexx, kotazz, neosporimy, dasteldi\n");
    kprintf("<(09)>The operating system is licensed under the MIT license.\n");
    kprintf("<(0f)>GitHub: <(0b)>https://github.com/fcexx/AxonOS\n");
    kprintf("<(0f)>Website: <(0b)>https://dasteldi.ru\n");
    return 0;
    }

    static int bi_time(cmd_ctx *c) { rtc_datetime_t dt; rtc_read_datetime(&dt); char out[16]; int pos=0;
        int hh=dt.hour, mm=dt.minute, ss=dt.second;
        out[pos++] = (char)('0' + (hh/10)); out[pos++] = (char)('0' + (hh%10)); out[pos++] = ':';
        out[pos++] = (char)('0' + (mm/10)); out[pos++] = (char)('0' + (mm%10)); out[pos++] = ':';
    out[pos++] = (char)('0' + (ss/10)); out[pos++] = (char)('0' + (ss%10)); out[pos]='\0';
    kprint((uint8_t*)out); return 0; }

        static int bi_date(cmd_ctx *c) { rtc_datetime_t dt; rtc_read_datetime(&dt); char out[64]; int pos=0; int d=dt.day,m=dt.month,y=dt.year; out[pos++]='0'+d/10; out[pos++]='0'+d%10; out[pos++]='/'; out[pos++]='0'+m/10; out[pos++]='0'+m%10; out[pos++]='/'; // year simplified
            // year 4 digits
            int yy = y; char tmp[8]; int n=0; if (yy==0){tmp[n++]='0';} else { int s[8],k=0; while(yy){ s[k++]=yy%10; yy/=10; } for(int i=k-1;i>=0;i--) tmp[n++]=(char)('0'+s[i]); }
    for (int i=0;i<n;i++) out[pos++]=tmp[i]; out[pos]='\0'; kprint((uint8_t*)out); return 0; }

static int bi_uptime(cmd_ctx *c) { uint64_t seconds = rtc_ticks / 2; uint64_t minutes = seconds / 60; uint64_t hours = minutes / 60; seconds%=60; minutes%=60; char out[64]; int pos=0; // Hh Mm Ss
    int h=(int)hours,m=(int)minutes,s=(int)seconds; char buf[32]; int n=0; // naive int to str
    int v=h; int st[16],k=0; if(v==0) buf[n++]='0'; else { while(v){ st[k++]=v%10; v/=10;} for(int i=k-1;i>=0;i--) buf[n++]=(char)('0'+st[i]); }
    memcpy(out+pos, buf, (size_t)n); pos+=n; out[pos++]='h'; out[pos++]=' ';
    n=0;k=0; v=m; if(v==0) buf[n++]='0'; else { while(v){ st[k++]=v%10; v/=10;} for(int i=k-1;i>=0;i--) buf[n++]=(char)('0'+st[i]); }
    memcpy(out+pos, buf, (size_t)n); pos+=n; out[pos++]='m'; out[pos++]=' ';
    n=0;k=0; v=s; if(v==0) buf[n++]='0'; else { while(v){ st[k++]=v%10; v/=10;} for(int i=k-1;i>=0;i--) buf[n++]=(char)('0'+st[i]); }
    memcpy(out+pos, buf, (size_t)n); pos+=n; out[pos++]='s'; out[pos++]='\n'; out[pos]='\0'; osh_write(c->out,c->out_len,c->out_cap,out); return 0; }

static int bi_edit(cmd_ctx *c) {
    char path[256];
    if (c->argc < 2) {
        join_cwd(g_cwd, "untitled", path, sizeof(path));
    } else {
        char arg[256];
        size_t L = strlen(c->argv[1]);
        if (L >= sizeof(arg)) L = sizeof(arg) - 1;
        memcpy(arg, c->argv[1], L);
        arg[L] = '\0';
        strip_matching_quotes(arg);
        join_cwd(g_cwd, arg, path, sizeof(path));
    }
    editor_run(path);
    return 0;
}
extern void reboot_system(); extern void shutdown_system();
static int bi_reboot(cmd_ctx *c){ (void)c; reboot_system(); return 0; }
static int bi_shutdown(cmd_ctx *c){ (void)c; shutdown_system(); return 0; }

static int bi_mem(cmd_ctx *c){
    (void)c;
    int ram = sysinfo_ram_mb();
    size_t htot = heap_total_bytes();
    size_t huse = heap_used_bytes();
    size_t hpeak = heap_peak_bytes();
    if (ram >= 0) kprintf("RAM total: %d MB\n", ram);
    else kprintf("RAM total: unknown\n");
    kprintf("Heap: used %u KB / total %u KB (peak %u KB)\n",
        (unsigned)(huse/1024u), (unsigned)(htot/1024u), (unsigned)(hpeak/1024u));
    return 0;
}

// Run script file: osh <script>
static int bi_osh(cmd_ctx *c) {
    if (c->argc < 2) { osh_run(); return 0; }
    // Use the same path join logic as cat/ls to avoid intermittent resolution issues
    char *path = kmalloc(256); if (path==0) return; join_cwd(g_cwd, c->argv[1], path, sizeof(path));
    struct fs_file *f = fs_open(path); if (!f) { osh_write(c->out, c->out_len, c->out_cap, "osh: cannot open script\n"); return 1; }
    size_t want = f->size ? f->size : 0; char *buf = (char*)kmalloc(want + 1);
    if (!buf) { fs_file_free(f); return 1; }
    ssize_t r = fs_read(f, buf, want, 0); fs_file_free(f);
    if (r < 0) { kfree(buf); osh_write(c->out, c->out_len, c->out_cap, "osh: read error\n"); return 1; }
    buf[r] = '\0';
    // strip UTF-8 BOM if present
    size_t start_off = 0;
    if ((size_t)r >= 3 && (unsigned char)buf[0]==0xEF && (unsigned char)buf[1]==0xBB && (unsigned char)buf[2]==0xBF) {
        start_off = 3;
    }
    // normalize patterns like "} else" to break onto new line to simplify parsing
    for (ssize_t idx = (ssize_t)start_off; idx < r - 4; idx++) {
        if (buf[idx] == '}') {
            ssize_t j = idx + 1;
            // skip single space/tabs; replace the first whitespace before 'else' with newline
            if (j < r && (buf[j] == ' ' || buf[j] == '\t')) {
                ssize_t k = j;
                while (k < r && (buf[k] == ' ' || buf[k] == '\t')) k++;
                if (k < r && strncmp(&buf[k], "else", 4) == 0) {
                    buf[j] = '\n';
                    for (ssize_t m = j + 1; m < k; m++) buf[m] = ' ';
                }
            }
        }
    }
    // split into lines
    int nlines = 0; for (ssize_t i=(ssize_t)start_off; i<r; i++) if (buf[i]=='\n') nlines++;
    nlines += 1;
    char **lines = (char**)kcalloc((size_t)nlines, sizeof(char*));
    int *line_len = (int*)kcalloc((size_t)nlines, sizeof(int));
    int idx = 0; char *line = buf + start_off; ssize_t i = (ssize_t)start_off;
    for (; i < r; i++) {
        if (buf[i] == '\r') { buf[i] = '\0'; }
        else if (buf[i] == '\n') { buf[i] = '\0'; lines[idx] = line; line_len[idx] = (int)strlen(line); idx++; line = buf + i + 1; }
    }
    if (*line) { lines[idx] = line; line_len[idx] = (int)strlen(line); idx++; }
    nlines = idx;

    // --- simple function table (pass 1) ---
    osh_func_def funcs[32]; int nfuncs = 0;
    for (int li=0; li<nlines; li++) {
        char *s = lines[li]; while (*s==' '||*s=='\t') s++;
        if (!*s || *s=='#') continue;
        // function header: name(arg1, arg2) {
        char name[32]; int ni=0;
        const char* p = s;
        while ((*p=='_'||(*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')) && ni<31) { name[ni++]=*p++; }
        name[ni]='\0';
        if (ni>0 && *p=='(') {
            p++;
            // parse params
            char *params[8]; int pc=0;
            char token[32]; int ti=0;
            int ok = 0;
            while (*p && *p != ')') {
                if (*p==' '||*p=='\t') { p++; continue; }
                if (*p==',') { p++; continue; }
                // ident
                ti=0;
                if ((*p=='_'||(*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z'))) {
                    while ((*p=='_'||(*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')) && ti<31) token[ti++]=*p++;
                    token[ti]='\0';
                    if (pc<8) { params[pc]=(char*)kcalloc(strlen(token)+1,1); memcpy(params[pc], token, strlen(token)+1); pc++; }
                } else { break; }
            }
            if (*p==')') { p++; while (*p==' '||*p=='\t') p++; if (*p=='{') { ok=1; } }
            if (ok) {
                // find matching }
                int depth = 0; int start = li+1; int end = nlines;
                for (int lj=li; lj<nlines; lj++) {
                    char *t = lines[lj]; while (*t==' '||*t=='\t') t++;
                    for (char *q=t; *q; q++) { if (*q=='{') depth++; else if (*q=='}') { depth--; if (depth==0) { end = lj; goto found_end; } } }
                }
            found_end:
                if (nfuncs < 32) {
                    strncpy(funcs[nfuncs].name, name, sizeof(funcs[nfuncs].name)-1);
                    funcs[nfuncs].pc = pc;
                    funcs[nfuncs].header = li;
                    for (int k=0;k<pc;k++) funcs[nfuncs].params[k]=params[k];
                    funcs[nfuncs].start = start;
                    funcs[nfuncs].end   = end;
                    nfuncs++;
                }
                li = end; // skip body
            }
        }
    }

    // Execute using top-level script engine
    osh_script_ctx CTX = { .lines = lines, .nlines = nlines, .funcs = funcs, .nfuncs = nfuncs };
    {
        osh_script_ctx* prev_ctx = g_active_script_ctx;
        g_active_script_ctx = &CTX;
        g_script_depth++;
        int status = osh_exec_range(&CTX, 0, nlines);
        g_script_depth--;
        g_active_script_ctx = prev_ctx;
        for (int j=0;j<nfuncs;j++){ for(int k=0;k<funcs[j].pc;k++) if(funcs[j].params[k]) kfree(funcs[j].params[k]); }
        kfree(lines); kfree(line_len); kfree(buf);
        if (status == OSH_SCRIPT_EXIT) status = 0;
        if (status == OSH_SCRIPT_ABORT) {
            status = 130;
        }
        if (status == OSH_SCRIPT_RETURN) status = 0;
        return status;
    }

#if 0
    // helpers
    auto int find_func(const char* nm) -> int {
        for (int i2=0;i2<nfuncs;i2++) if (strcmp(funcs[i2].name, nm)==0) return i2; return -1;
    }
    auto int exec_range(int L, int R) -> int; // fwd
    auto int eval_cond(const char* expr) -> int {
        // support: a op b, where op in == != <= >= < >
        // Expand vars in expr
        char *ex = expand_vars(expr);
        const char* e = ex ? ex : expr;
        const char* ops[] = {"==","!=", "<=", ">=", "<", ">"};
        int which = -1; int pos = -1;
        for (int k=0;k<6;k++) {
            const char* o = ops[k];
            const char* p = strstr(e, o);
            if (p) { which=k; pos=(int)(p - e); break; }
        }
        int res = 0;
        if (which >= 0) {
            char left[256], right[256];
            int ln = pos; if (ln>255) ln=255; memcpy(left, e, ln); left[ln]='\0';
            const char* rp = e + pos + (ops[which][1] ? 2 : 1);
            while (*rp==' ') rp++;
            strncpy(right, rp, sizeof(right)-1); right[sizeof(right)-1]='\0';
            // trim left trailing spaces
            int ll=(int)strlen(left); while (ll>0 && (left[ll-1]==' '||left[ll-1]=='\t')) left[--ll]='\0';
            // try numeric
            const char* pl = left; const char* pr = right;
            double lv = osh_parse_expr(&pl);
            double rv = osh_parse_expr(&pr);
            // If parsers consumed nothing, fallback to string
            int numeric = 1;
            // basic compare with tolerance
            double eps = 1e-9;
            switch (which) {
                case 0: res = (lv - rv < eps && rv - lv < eps); break; // ==
                case 1: res = ! (lv - rv < eps && rv - lv < eps); break; // !=
                case 2: res = (lv <= rv + eps); break; // <=
                case 3: res = (lv + eps >= rv); break; // >=
                case 4: res = (lv < rv - eps); break; // <
                case 5: res = (lv > rv + eps); break; // >
            }
        } else {
            // Non-empty after expansion -> true
            res = (e && *e);
        }
        if (ex) kfree(ex);
        return res;
    }
    auto void call_func(int fi, char** args, int ac) -> void {
        // save old values and set params
        const int pc = funcs[fi].pc;
        char* saved_names[8]; char* saved_vals[8];
        for (int i2=0;i2<pc && i2<8;i2++){
            const char* pname = funcs[fi].params[i2];
            // save
            saved_names[i2] = (char*)pname;
            const char* old = var_get(pname);
            saved_vals[i2] = old ? (char*)old : NULL;
            // set new
            var_set(pname, (i2<ac && args[i2]) ? args[i2] : "");
        }
        (void)exec_range(funcs[fi].start, funcs[fi].end);
        // restore: no need to free saved_vals (pointed to internal storage)
        for (int i2=0;i2<pc && i2<8;i2++){
            const char* pname = saved_names[i2];
            if (saved_vals[i2]) var_set(pname, saved_vals[i2]);
            else var_set(pname, "");
        }
    }
    auto int exec_range(int L, int R) -> int {
        int li=L;
        while (li<R) {
            char *s0 = lines[li]; while (*s0==' '||*s0=='\t') s0++;
            if (!*s0 || *s0=='#') { li++; continue; }
            // if / else-if / else chain
            if (strncmp(s0, "if ", 3)==0) {
                // expect {...}
                char *cond = s0 + 3;
                // find block
                int depth = 0; int bstart = -1; int bend = -1; int cur = li;
                for (; cur<R; cur++) {
                    char *t = lines[cur]; while (*t==' '||*t=='\t') t++;
                    for (char* q=t; *q; q++){ if (*q=='{'){ depth++; if (depth==1) bstart = cur+1; } else if(*q=='}'){ depth--; if(depth==0){ bend = cur; goto got_if_block; } } }
                }
            got_if_block:
                int taken = eval_cond(cond);
                int after = bend + 1;
                if (taken) { (void)exec_range(bstart, bend); }
                else {
                    // check else if / else
                    int consumed = 0;
                    while (after < R) {
                        char *t = lines[after]; while (*t==' '||*t=='\t') t++;
                        if (strncmp(t, "else if ", 8)==0) {
                            // parse its block
                            char *c2 = t + 8;
                            int d2=0, s2=-1, e2=-1, w=after;
                            for (; w<R; w++){ char *u=lines[w]; while(*u==' '||*u=='\t') u++; for(char* q=u;*q;q++){ if(*q=='{'){ d2++; if(d2==1) s2=w+1; } else if(*q=='}'){ d2--; if(d2==0){ e2=w; goto got_elseif; } } } }
                        got_elseif:
                            if (eval_cond(c2)) { (void)exec_range(s2, e2); consumed = e2 - li + 1; after = e2 + 1; break; }
                            else { after = e2 + 1; }
                        } else if (strncmp(t, "else", 4)==0) {
                            // expect { block }
                            int d3=0, s3=-1, e3=-1, w=after;
                            for (; w<R; w++){ char *u=lines[w]; while(*u==' '||*u=='\t') u++; for(char* q=u;*q;q++){ if(*q=='{'){ d3++; if(d3==1) s3=w+1; } else if(*q=='}'){ d3--; if(d3==0){ e3=w; goto got_else; } } } }
                        got_else:
                            (void)exec_range(s3, e3); consumed = e3 - li + 1; after = e3 + 1; break;
                        } else break;
                    }
                    if (!consumed) { /* nothing executed */ }
                }
                li = after;
                continue;
            }
            // while <cond> { ... }
            if (strncmp(s0, "while ", 6)==0) {
                char *cond = s0 + 6;
                int depth=0, bstart=-1, bend=-1, cur=li;
                for (; cur<R; cur++) {
                    char *t = lines[cur]; while (*t==' '||*t=='\t') t++;
                    for (char* q=t; *q; q++){ if(*q=='{'){ depth++; if(depth==1) bstart=cur+1; } else if(*q=='}'){ depth--; if(depth==0){ bend=cur; goto got_while; } } }
                }
            got_while:
                // naive loop guard to avoid hanging
                int iter = 0;
                while (eval_cond(cond)) {
                    (void)exec_range(bstart, bend);
                    if (++iter > 100000) break;
                }
                li = bend + 1;
                continue;
            }
            // function call: name(arg,...)
            {
                char name[32]; int ni2=0; const char* p2=s0;
                while ((*p2=='_'||(*p2>='a'&&*p2<='z')||(*p2>='A'&&*p2<='Z')) && ni2<31) { name[ni2++]=*p2++; }
                name[ni2]='\0';
                if (ni2>0 && *p2=='(') {
                    int fi = find_func(name);
                    if (fi >= 0) {
                        p2++;
                        char *args[8]; int ac=0;
                        char token[256]; int ti=0; int inq=0;
                        while (*p2 && *p2 != ')') {
                            if (!inq && (*p2==',')) {
                                token[ti]='\0'; args[ac]=(char*)kcalloc(strlen(token)+1,1); memcpy(args[ac], token, strlen(token)+1); ac++; ti=0; p2++; continue;
                            }
                            if (*p2=='"') { inq = !inq; p2++; continue; }
                            if (ti < (int)sizeof(token)-1) token[ti++]=*p2++;
                            else p2++;
                        }
                        token[ti]='\0'; if (ti||ac) { args[ac]=(char*)kcalloc(strlen(token)+1,1); memcpy(args[ac], token, strlen(token)+1); ac++; }
                        call_func(fi, args, ac);
                        for (int i3=0;i3<ac;i3++) if (args[i3]) kfree(args[i3]);
                        li++; continue;
                    }
                }
            }
            // plain command
            int rc = exec_line(s0);
            if (rc == 2) { /* exit shell */ for (int j=0;j<nfuncs;j++){ for(int k=0;k<funcs[j].pc;k++) if(funcs[j].params[k]) kfree(funcs[j].params[k]); } kfree(lines); kfree(line_len); kfree(buf); return 0; }
            li++;
        }
        return 0;
    }
    int status = exec_range(0, nlines);
    for (int j=0;j<nfuncs;j++){ for(int k=0;k<funcs[j].pc;k++) if(funcs[j].params[k]) kfree(funcs[j].params[k]); }
    kfree(lines); kfree(line_len); kfree(buf);
    return status;
#endif
}
static int bi_pause(cmd_ctx *c){ (void)c; kprintf("Press any key to continue...\n"); kgetc(); return 0;}
static int bi_chipset(cmd_ctx *c) {
    if (c->argc < 2) {
        kprintf("usage: chipset <command>\n");
        kprintf("commands:\n");
        kprintf("  info - print chipset information\n");
        kprintf("  reset - reset chipset\n");
        return 1;
    }
    if (strcmp(c->argv[1], "info") == 0) {
        intel_print_chipset_info();
    } else if (strcmp(c->argv[1], "reset") == 0) {
        intel_chipset_reset();
    } else {
        kprintf("<(0c)>chipset: unknown command: %s\n", c->argv[1]);
        return 1;
    }
    return 0;
}

static int bi_help(cmd_ctx *c) {
    (void)c;
    kprint((uint8_t*)"OSH v0.2 (axosh)\n");
    kprint((uint8_t*)"Available commands:\n");
    kprint((uint8_t*)"help - show available commands\n");
    kprint((uint8_t*)"clear, cls - clear the screen\n");
    kprint((uint8_t*)"kprint <text> - print raw text without auto-newline\n");
    kprint((uint8_t*)"readline [prompt] - read a line from the user\n");
    kprint((uint8_t*)"readkey - read a single keypress (hex for non-printable)\n");
    kprint((uint8_t*)"reboot - reboot the system\n");
    kprint((uint8_t*)"shutdown - shutdown the system\n");
    kprint((uint8_t*)"echo <text> - print text\n");
    kprint((uint8_t*)"time - show current time from RTC\n");
    kprint((uint8_t*)"date - show current date from RTC\n");
    kprint((uint8_t*)"uptime - show system uptime based on RTC ticks\n");
    kprint((uint8_t*)"about - show information about authors and system\n");
    kprint((uint8_t*)"ls - list directory contents\n");
    kprint((uint8_t*)"cat - print file contents\n");
    kprint((uint8_t*)"mkdir - create a directory\n");
    kprint((uint8_t*)"touch - create an empty file\n");
    kprint((uint8_t*)"rm - remove a file\n");
    kprint((uint8_t*)"edit - edit a file\n");
    kprint((uint8_t*)"pause - pause the shell and wait for a key press\n");
    kprint((uint8_t*)"chipset info - print chipset information\n");
    kprint((uint8_t*)"chipset reset - reset chipset\n");
    kprint((uint8_t*)"osh - run a script file\n");
    kprint((uint8_t*)"art - show ASCII art\n");
    kprint((uint8_t*)"exit - exit the shell\n");
    return 0;
}

extern void ascii_art(void);
static int bi_art(cmd_ctx *c){ (void)c; ascii_art(); return 0; }
typedef int (*builtin_fn)(cmd_ctx*);
typedef struct { const char* name; builtin_fn fn; } builtin;
/* forward declaration for chmod builtin */
static int bi_chmod(cmd_ctx *c);
/* forward declaration for chvt builtin */
static int bi_chvt(cmd_ctx *c);
/* fd builtins */
static int bi_open(cmd_ctx *c);
static int bi_close(cmd_ctx *c);
static int bi_dup(cmd_ctx *c);
static int bi_dup2(cmd_ctx *c);
static int bi_isatty(cmd_ctx *c);
/* xxd builtin forward declaration */
static int bi_xxd(cmd_ctx *c);
static int bi_mount(cmd_ctx *c);
static int bi_umount(cmd_ctx *c);
static int bi_exec(cmd_ctx *c);

static const builtin builtin_table[] = {
    {"echo", bi_echo}, {"kprint", bi_kprint}, {"readline", bi_readline}, {"readkey", bi_readkey},
    {"pwd", bi_pwd}, {"cd", bi_cd}, {"clear", bi_cls}, {"cls", bi_cls},
    {"ls", bi_ls}, {"cat", bi_cat}, {"mkdir", bi_mkdir}, {"touch", bi_touch}, {"rm", bi_rm},
    {"about", bi_about}, {"time", bi_time}, {"date", bi_date}, {"uptime", bi_uptime},
    {"edit", bi_edit}, {"reboot", bi_reboot}, {"shutdown", bi_shutdown}, {"mem", bi_mem},
    {"osh", bi_osh}, {"art", bi_art}, {"pause", bi_pause}, {"chipset", bi_chipset}, {"help", bi_help},
    {"passwd", bi_passwd}, {"su", bi_su}, {"whoami", bi_whoami}, {"mkpasswd", bi_mkpasswd}, {"groups", bi_groups},
    {"useradd", bi_useradd}, {"groupadd", bi_groupadd}, {"chmod", bi_chmod}, {"chvt", bi_chvt},
    {"open", bi_open}, {"close", bi_close}, {"dup", bi_dup}, {"dup2", bi_dup2}, {"isatty", bi_isatty}, {"xxd", bi_xxd}, {"mount", bi_mount}, {"umount", bi_umount}, {"exec", bi_exec}
};
static int bi_chmod(cmd_ctx *c) {
    if (c->argc < 3) { kprintf("usage: chmod <mode> <path>\n"); return 1; }
    const char *mode_s = c->argv[1];
    const char *path = c->argv[2];
    char fullpath[512];
    join_cwd(g_cwd, path, fullpath, sizeof(fullpath));
    /* use fullpath for operations from here */
    /* If symbolic mode like +x or -x — handle simple case for execute bits */
    mode_t newmode = 0;
    struct stat st;
    if (vfs_stat(fullpath, &st) != 0) { kprintf("chmod: cannot stat %s\n", path); return 1; }
    uid_t cur = user_get_current_uid();
    /* permission check: only root or owner can chmod */
    if (cur != 0 && cur != st.st_uid) { kprintf("chmod: permission denied\n"); return 1; }

    if (mode_s[0] == '+' || mode_s[0] == '-') {
        /* support +x and -x (all users) */
        int add = (mode_s[0] == '+');
        int want_x = 0;
        for (const char *p = mode_s+1; *p; p++) if (*p == 'x') want_x = 1;
        if (!want_x) { kprintf("chmod: invalid mode\n"); return 1; }
        if (add) newmode = (mode_t)(st.st_mode | 0111);
        else newmode = (mode_t)(st.st_mode & ~0111);
    } else {
        /* parse octal mode */
        mode_t mode = 0;
        const char *p = mode_s;
        if (!p || !(*p >= '0' && *p <= '7')) { kprintf("chmod: invalid mode\n"); return 1; }
        for (; *p; p++) {
            if (*p >= '0' && *p <= '7') { mode = (mode << 3) + (mode_t)(*p - '0'); }
            else { kprintf("chmod: invalid mode\n"); return 1; }
        }
        newmode = mode;
    }
    if (fs_chmod(fullpath, newmode) == 0) { kprintf("ok\n"); return 0; }
    kprintf("chmod: failed\n");
    return 1;
}

static int bi_chvt(cmd_ctx *c) {
    if (c->argc < 2) { kprintf("usage: chvt <n>\n"); return 1; }
    int n = parse_uint(c->argv[1]);
    if (n < 0) { kprintf("chvt: invalid number\n"); return 1; }
    extern void devfs_switch_tty(int index);
    devfs_switch_tty(n);
    return 0;
}

/* exec builtin: replace current shell with given executable */
static int bi_exec(cmd_ctx *c) {
    if (c->argc < 2) { kprintf("usage: exec <path> [args...]\n"); return 1; }
    char fullpath[512];
    join_cwd(g_cwd, c->argv[1], fullpath, sizeof(fullpath));
    /* build argv array for kernel_execve (argv[0] should be program name) */
    int argcount = c->argc - 1;
    const char **kargv = (const char **)kmalloc(sizeof(char*) * (size_t)(argcount + 1));
    if (!kargv) { kprintf("exec: allocation failed\n"); return 1; }
    for (int i = 0; i < argcount; i++) kargv[i] = c->argv[i+1];
    kargv[argcount] = NULL;
    /* call kernel execve; on success this will not return */
    int r = kernel_execve_from_path(fullpath, kargv, NULL);
    kfree(kargv);
    if (r != 0) {
        kprintf("exec: failed to run %s (rc=%d)\n", fullpath, r);
        return 1;
    }
    return 0; /* not reached on success */
}

static int bi_open(cmd_ctx *c) {
    if (c->argc < 2) { kprintf("usage: open <path>\n"); return 1; }
    const char *path = c->argv[1];
    struct fs_file *f = fs_open(path);
    if (!f) { kprintf("open: failed\n"); return 1; }
    int fd = thread_fd_alloc(f);
    if (fd < 0) { fs_file_free(f); kprintf("open: no fds\n"); return 1; }
    kprintf("%d\n", fd);
    return 0;
}

static int bi_mount(cmd_ctx *c) {
    if (c->argc < 3) {
        kprintf("usage: mount [-t type] <device> <mountpoint>\n");
        return 1;
    }
    const char *fstype = NULL;
    const char *devpath = NULL;
    const char *mntpath = NULL;
    int i = 1;
    while (i < c->argc) {
        if (strcmp(c->argv[i], "-t") == 0 && i + 1 < c->argc) {
            fstype = c->argv[i+1];
            i += 2;
            continue;
        }
        if (!devpath) { devpath = c->argv[i++]; continue; }
        if (!mntpath) { mntpath = c->argv[i++]; continue; }
        i++;
    }
    if (!devpath || !mntpath) {
        kprintf("mount: missing device or mountpoint\n");
        return 1;
    }
    char full_dev[256]; char full_mnt[256];
    join_cwd(g_cwd, devpath, full_dev, sizeof(full_dev));
    join_cwd(g_cwd, mntpath, full_mnt, sizeof(full_mnt));
    int dev_index = devfs_find_block_by_path(full_dev);
    if (dev_index < 0) { kprintf("mount: device not found: %s\n", full_dev); return 1; }
    int device_id = devfs_get_device_id(full_dev);
    if (device_id < 0) { kprintf("mount: cannot resolve device id for %s\n", full_dev); return 1; }
    struct fs_driver *drv = NULL;
    if (!fstype || strcmp(fstype, "auto") == 0 || strcmp(fstype, "fat32") == 0) {
        /* try fat32 on the underlying device id */
        if (fat32_probe_and_mount(device_id) == 0) {
            drv = fat32_get_driver();
        }
    }
    if (!drv) { kprintf("mount: filesystem not recognized or not supported\n"); return 1; }
    /* ensure mountpoint exists in ramfs */
    ramfs_mkdir(full_mnt);
    if (fs_mount(full_mnt, drv) == 0) {
        kprintf("mount: mounted %s at %s\n", full_dev, full_mnt);
        return 0;
    } else {
        kprintf("mount: failed to mount %s at %s\n", full_dev, full_mnt);
        return 1;
    }
}

static int bi_umount(cmd_ctx *c) {
    if (c->argc < 2) {
        kprintf("usage: umount <mountpoint>\n");
        return 1;
    }
    char full_mnt[512];
    join_cwd(g_cwd, c->argv[1], full_mnt, sizeof(full_mnt));
    struct fs_driver *mount_drv = fs_get_mount_driver(full_mnt);
    if (fs_unmount(full_mnt) == 0) {
        kprintf("umount: %s unmounted\n", full_mnt);
        if (mount_drv && mount_drv->ops && mount_drv->ops->name && strcmp(mount_drv->ops->name, "fat32") == 0) {
            extern void fat32_unmount_cleanup(void);
            fat32_unmount_cleanup();
        }
        return 0;
    } else {
        kprintf("umount: failed to unmount %s\n", full_mnt);
        return 1;
    }
}

static int bi_close(cmd_ctx *c) {
    if (c->argc < 2) { kprintf("usage: close <fd>\n"); return 1; }
    int fd = parse_uint(c->argv[1]);
    if (fd < 0) { kprintf("close: invalid fd\n"); return 1; }
    if (thread_fd_close(fd) == 0) return 0;
    kprintf("close: failed\n");
    return 1;
}

static int bi_dup(cmd_ctx *c) {
    if (c->argc < 2) { kprintf("usage: dup <oldfd>\n"); return 1; }
    int oldfd = parse_uint(c->argv[1]);
    int nfd = thread_fd_dup(oldfd);
    if (nfd < 0) { kprintf("dup: failed\n"); return 1; }
    kprintf("%d\n", nfd);
    return 0;
}

static int bi_dup2(cmd_ctx *c) {
    if (c->argc < 3) { kprintf("usage: dup2 <oldfd> <newfd>\n"); return 1; }
    int oldfd = parse_uint(c->argv[1]);
    int newfd = parse_uint(c->argv[2]);
    int r = thread_fd_dup2(oldfd, newfd);
    if (r < 0) { kprintf("dup2: failed\n"); return 1; }
    return 0;
}

static int bi_isatty(cmd_ctx *c) {
    if (c->argc < 2) { kprintf("usage: isatty <fd>\n"); return 1; }
    int fd = parse_uint(c->argv[1]);
    int r = thread_fd_isatty(fd);
    kprintf("%d\n", r ? 1 : 0);
    return 0;
}

/* xxd: simple hex dump utility
   usage: xxd <path> [offset] [length]
*/
static int bi_xxd(cmd_ctx *c) {
    /* Parse args: support optional flag -l <length> (anywhere) and a path.
       Positional offset/length after path are still supported if -l not provided. */
    size_t specified_len = 0;
    int has_len_flag = 0;
    const char *path_arg = NULL;
    for (int i = 1; i < c->argc; i++) {
        if (c->argv[i] && strcmp(c->argv[i], "-l") == 0 && i + 1 < c->argc) {
            specified_len = (size_t)parse_uint(c->argv[i + 1]);
            has_len_flag = 1;
            i++; /* skip length token */
        } else if (!path_arg) {
            path_arg = c->argv[i];
        } else {
            /* ignore extra tokens here; positional parsing happens below */
        }
    }
    if (!path_arg) {
        osh_write(c->out, c->out_len, c->out_cap, "usage: xxd [-l length] <path> [offset] [length]\n");
        return 1;
    }
    char path[256];
    join_cwd(g_cwd, path_arg, path, sizeof(path));
    struct fs_file *f = fs_open(path);
    if (!f) {
        osh_write(c->out, c->out_len, c->out_cap, "xxd: cannot open file\n");
        return 1;
    }
    size_t fsize = f->size ? f->size : 0;
    size_t start = 0;
    size_t length = fsize;
    /* If user provided positional offset/length after the path, parse them (only used when -l not present). */
    if (!has_len_flag) {
        /* find index of path_arg to read following tokens */
        int path_idx = -1;
        for (int i = 1; i < c->argc; i++) {
            if (c->argv[i] && strcmp(c->argv[i], path_arg) == 0) { path_idx = i; break; }
        }
        if (path_idx >= 0) {
            if (path_idx + 1 < c->argc) start = (size_t)parse_uint(c->argv[path_idx + 1]);
            if (path_idx + 2 < c->argc) {
                size_t L = (size_t)parse_uint(c->argv[path_idx + 2]);
                if (L < length) length = L;
            }
        }
    } else {
        /* flag -l overrides positional length */
        length = specified_len;
    }
    /* If file reports size 0 (character device), and no length explicitly provided,
       we will treat length==0 as 'infinite' (handled below). */
    if (start > fsize) {
        fs_file_free(f);
        osh_write(c->out, c->out_len, c->out_cap, "xxd: offset beyond EOF\n");
        return 1;
    }
    int infinite = 0;
    if (fsize == 0 && !has_len_flag && length == 0) {
        /* character device and no explicit length: generate indefinitely until Ctrl-C */
        infinite = 1;
    }
    size_t remaining;
    if (fsize == 0) {
        /* character device: use requested length (may be 0 if infinite) */
        remaining = length;
    } else {
        remaining = (start + length <= fsize) ? length : (fsize - start);
    }
    kprintf("xxd: open='%s' fsize=%u start=%u length=%u remaining=%u\n", path, (unsigned)fsize, (unsigned)start, (unsigned)length, (unsigned)remaining);
    unsigned char buf[16];
    size_t pos = 0;
    while ((infinite) || (remaining > 0)) {
        if (keyboard_ctrlc_pending()) { keyboard_consume_ctrlc(); break; }
        size_t want;
        if (infinite) want = sizeof(buf);
        else want = remaining >= sizeof(buf) ? sizeof(buf) : remaining;
        ssize_t r = fs_read(f, buf, want, start + pos);
        //kprintf("xxd: fs_read want=%u r=%d\n", (unsigned)want, (int)r);
        if (r <= 0) {
            if (infinite) {
                /* fallback: generate bytes locally if device read blocks */
                for (size_t gi = 0; gi < want; gi++) {
                    /* simple xorshift32 */
                    static uint32_t xrand = 0x12345677;
                    xrand ^= xrand << 13;
                    xrand ^= xrand >> 17;
                    xrand ^= xrand << 5;
                    buf[gi] = (unsigned char)(xrand & 0xFF);
                }
                r = (ssize_t)want;
            } else break;
        }
        char line[128];
        char hexbuf[64];
        const char hexdigits[] = "0123456789abcdef";
        int hp = 0;
        for (int i = 0; i < 16; i++) {
            if (i > 0) {
                if (i == 8) { hexbuf[hp++] = ' '; hexbuf[hp++] = ' '; }
                else { hexbuf[hp++] = ' '; }
            }
            if (i < r) {
                unsigned char b = buf[i];
                if (hp + 2 < (int)sizeof(hexbuf)) {
                    hexbuf[hp++] = hexdigits[(b >> 4) & 0xF];
                    hexbuf[hp++] = hexdigits[b & 0xF];
                }
            } else {
                /* two spaces to preserve width for missing byte */
                if (hp + 2 < (int)sizeof(hexbuf)) { hexbuf[hp++] = ' '; hexbuf[hp++] = ' '; }
            }
        }
        if (hp >= (int)sizeof(hexbuf)) hp = (int)sizeof(hexbuf) - 1;
        hexbuf[hp] = '\0';
        /* address + hex area, then two spaces, then ASCII for available bytes */
        /* format 4-digit hex offset manually to avoid depending on snprintf %zx support */
        char addrbuf[8 + 1];
        //const char hexdigits[] = "0123456789abcdef";
        unsigned long addr_val = (unsigned long)(start + pos);
        for (int i = 0; i < 4; i++) {
            int shift = (3 - i) * 4;
            int nibble = (int)((addr_val >> shift) & 0xF);
            addrbuf[i] = hexdigits[nibble];
        }
        addrbuf[4] = '\0';
        int lp = snprintf(line, sizeof(line), "%s: %s  ", addrbuf, hexbuf);
        for (int i = 0; i < r; i++) {
            unsigned char ch = buf[i];
            line[lp++] = (ch >= 32 && ch < 127) ? (char)ch : '.';
            if (lp >= (int)sizeof(line) - 2) break;
        }
        /* terminate and add newline */
        if (lp < (int)sizeof(line) - 1) line[lp++] = '\n';
        if (lp >= (int)sizeof(line)) lp = (int)sizeof(line) - 1;
        line[lp] = '\0';
        // If stdout is a tty for current thread, print directly to screen to enable streaming.
        if (thread_fd_isatty(1)) {
            // direct kernel print (avoid buffered osh_write so output appears immediately)
            // ensure 0-termination
            line[lp] = '\0';
            kprint((uint8_t*)line);
        } else {
            osh_write(c->out, c->out_len, c->out_cap, line);
        }
        pos += (size_t)r;
        if (!infinite) remaining -= (size_t)r;
    }
    fs_file_free(f);
    return 0;
}

static builtin_fn find_builtin(const char* name) {
    for (size_t i=0;i<sizeof(builtin_table)/sizeof(builtin_table[0]);i++) if (strcmp(builtin_table[i].name, name)==0) return builtin_table[i].fn;
    return NULL;
}

// export builtin names for completion
int osh_get_builtin_names(const char*** out_names) {
    static const char* names[64];
    size_t n = sizeof(builtin_table)/sizeof(builtin_table[0]);
    for (size_t i=0;i<n && i<64;i++) names[i] = builtin_table[i].name;
    *out_names = names;
    return (int)n;
}

static int osh_assign_value(const char* name, char* rhs) {
    if (!name || !rhs) return 1;
    char* value = NULL;
    int rc = osh_eval_rhs(rhs, &value);
    if (rc == OSH_SCRIPT_ABORT || rc == OSH_SCRIPT_EXIT || rc == OSH_SCRIPT_RETURN) {
        if (value) kfree(value);
        return rc;
    }
    if (!value) value = (char*)kcalloc(1,1);
    var_set(name, value);
    kfree(value);
    return 0;
}

// -------- executor --------
static int exec_simple(char **argv, int argc, const char *in, char **out, size_t *out_len, size_t *out_cap) {
    if (argc==0) return 0;
    // handle assignment: name = rhs ...  OR  name=rhs (single word)
    if (argc >= 3 && strcmp(argv[1], "=") == 0 && is_valid_varname(argv[0])) {
        // join rhs with spaces
        char rhs[512]; size_t pos=0; rhs[0]='\0';
        for (int i=2;i<argc;i++) {
            size_t L = strlen(argv[i]); if (pos + L + 2 >= sizeof(rhs)) break;
            if (i>2) rhs[pos++] = ' ';
            memcpy(rhs+pos, argv[i], L); pos += L; rhs[pos]='\0';
        }
        return osh_assign_value(argv[0], rhs);
    } else if (argc >= 1) {
        // compact form: name=rhs (possibly with extra tokens on RHS)
        char* eq = NULL;
        for (char* p=argv[0]; *p; p++) if (*p=='='){ eq=p; break; }
        if (eq) {
            *eq = '\0';
            const char* name = argv[0];
            const char* first_rhs = eq + 1;
            if (is_valid_varname(name)) {
                char rhs_buf[512]; size_t pos = 0;
                if (first_rhs && *first_rhs) {
                    size_t L = strlen(first_rhs);
                    if (L > sizeof(rhs_buf) - 1) L = sizeof(rhs_buf) - 1;
                    memcpy(rhs_buf, first_rhs, L);
                    pos = L;
                }
                for (int i = 1; i < argc && pos < sizeof(rhs_buf) - 1; i++) {
                    const char* tok = argv[i];
                    if (!tok || !*tok) continue;
                    if (pos > 0 && pos < sizeof(rhs_buf) - 1) rhs_buf[pos++] = ' ';
                    size_t L = strlen(tok);
                    if (L > sizeof(rhs_buf) - 1 - pos) L = sizeof(rhs_buf) - 1 - pos;
                    if (L > 0) { memcpy(rhs_buf + pos, tok, L); pos += L; }
                }
                rhs_buf[pos] = '\0';
                int rc = osh_assign_value(name, rhs_buf);
                *eq = '=';
                return rc;
            }
            *eq = '='; // restore and fallthrough to normal exec
        }
    }
    if (strcmp(argv[0], "exit") == 0) {
        if (g_script_depth > 0) return OSH_SCRIPT_EXIT;
        return 2; // exit interactive shell
    }
    builtin_fn fn = find_builtin(argv[0]);
    if (!fn) { kprintf("<(0c)>osh: %s: command not found\n", argv[0]); return 1; }
    cmd_ctx c = { .argv=argv, .argc=argc, .in=in, .out=out, .out_len=out_len, .out_cap=out_cap };
    return fn(&c);
}

static int exec_pipeline(token *toks, int l, int r, const char *stdin_data, char **out_buf, size_t *out_len, size_t *out_cap) {
    // collect redirections > and < at end or anywhere: last > wins, single < for first stage
    char *redir_out = NULL; char *redir_in = NULL; int last_pipe = -1; int bg = 0;
    // find & at end
    if (r>l && toks[r-1].t==T_BG) { bg = 1; r--; }
    // scan for redirs and pipes
    int parts_idx[16]; int parts_count=0; int i=l; int start=l;
    while (i<r) {
        if (toks[i].t==T_PIPE) { parts_idx[parts_count++] = start; parts_idx[parts_count++] = i; start = i+1; }
        else if (toks[i].t==T_GT) { if (i+1<r && toks[i+1].t==T_WORD) { redir_out = toks[i+1].s; } i+=1; }
        else if (toks[i].t==T_LT) { if (!redir_in && i+1<r && toks[i+1].t==T_WORD) { redir_in = toks[i+1].s; } i+=1; }
        i++;
    }
    parts_idx[parts_count++] = start; parts_idx[parts_count++] = r;
    // initial stdin
    char *stage_in = NULL; size_t stage_in_len = 0;
    if (redir_in) {
        char path[256]; resolve_path(g_cwd, redir_in, path, sizeof(path)); struct fs_file *f = fs_open(path);
        if (f) { size_t want = f->size ? f->size : 0; stage_in = (char*)kmalloc(want+1); if (stage_in) { ssize_t rd = fs_read(f, stage_in, want, 0); if (rd>0){ stage_in[rd]='\0'; stage_in_len=(size_t)rd;} else { stage_in[0]='\0'; stage_in_len=0; } } fs_file_free(f); }
    } else if (stdin_data) {
        size_t n = strlen(stdin_data); stage_in = (char*)kmalloc(n+1); if (stage_in){ memcpy(stage_in, stdin_data, n+1); stage_in_len=n; }
    }
    // Execute stages left-to-right
    char *cur_out = NULL; size_t cur_len=0, cur_cap=0;
    for (int pi=0; pi<parts_count; pi+=2) {
        int pl = parts_idx[pi], pr = parts_idx[pi+1];
        // build argv from [pl,pr)
        char *argv[32]; int argc=0;
        for (int j = pl; j < pr; j++) {
            if (toks[j].t == T_GT || toks[j].t == T_LT) break; /* stop at redirection for this stage */
            if (toks[j].t == T_WORD) {
                argv[argc++] = toks[j].s;
                if (argc >= 31) break;
            }
        }
        argv[argc] = NULL;
        // prepare output buffer for this stage
        char *stage_out = NULL; size_t stage_out_len=0, stage_out_cap=0;
        const char *use_in = stage_in ? stage_in : NULL;
        int rc = exec_simple(argv, argc, use_in, &stage_out, &stage_out_len, &stage_out_cap);
        if (stage_in) { kfree(stage_in); stage_in=NULL; }
        if (rc == 2) { // exit shell
            if (stage_out) kfree(stage_out);
            if (cur_out) kfree(cur_out);
            return 2;
        }
        if (rc == OSH_SCRIPT_EXIT) {
            if (stage_out) kfree(stage_out);
            if (cur_out) kfree(cur_out);
            return OSH_SCRIPT_EXIT;
        }
        if (rc == OSH_SCRIPT_ABORT) {
            if (stage_out) kfree(stage_out);
            if (cur_out) kfree(cur_out);
            return OSH_SCRIPT_ABORT;
        }
        if (rc == OSH_SCRIPT_RETURN) {
            if (stage_out) kfree(stage_out);
            if (cur_out) kfree(cur_out);
            return OSH_SCRIPT_RETURN;
        }
        // Next stage input becomes this output
        stage_in = stage_out; stage_in_len = stage_out_len;
        if (pi+2 >= parts_count) { cur_out = stage_out; cur_len = stage_out_len; cur_cap = stage_out_cap; }
    }
    /* color tags removed — do not special-case output here; return to caller for printing */

    // output redirection or return text
    if (redir_out) {
        char path[256]; resolve_path(g_cwd, redir_out, path, sizeof(path)); struct fs_file *f = fs_open(path); if (!f) f = fs_create_file(path);
        if (f) { if (cur_out) fs_write(f, cur_out, cur_len, 0); fs_file_free(f); }
        if (cur_out) { kfree(cur_out); cur_out=NULL; cur_len=0; cur_cap=0; }
    } else {
        // pass back to caller
        *out_buf = cur_out; *out_len = cur_len; *out_cap = cur_cap; cur_out=NULL;
    }
    return 0;
}

static int osh_exec_subcommand(const char* line, char **out_value) {
    if (out_value) *out_value = NULL;
    if (!line) {
        if (out_value) {
            char* empty = (char*)kcalloc(1,1);
            if (!empty) return 1;
            *out_value = empty;
        }
        return 0;
    }
    int tn = 0;
    token *t = lex(line, &tn);
    if (!t) return 1;
    if (tn == 0) {
        free_tokens(t, tn);
        if (out_value) {
            char* empty = (char*)kcalloc(1,1);
            if (!empty) *out_value = empty; else return 1;
        }
        return 0;
    }
    char *out = NULL; size_t out_len = 0, out_cap = 0;
    int rc = exec_pipeline(t, 0, tn, NULL, &out, &out_len, &out_cap);
    free_tokens(t, tn);
    if (rc == 2 || rc == OSH_SCRIPT_EXIT || rc == OSH_SCRIPT_ABORT || rc == OSH_SCRIPT_RETURN) {
        if (out) kfree(out);
        return rc;
    }
    if (out_value) {
        if (out) {
            size_t len = strlen(out);
            while (len > 0 && (out[len-1] == '\n' || out[len-1] == '\r')) out[--len] = '\0';
            *out_value = out;
            out = NULL;
        } else {
            char* empty = (char*)kcalloc(1,1);
            if (!empty) *out_value = empty; else return rc ? rc : 1;
        }
    }
    if (out) kfree(out);
    return rc;
}

static int osh_eval_command_subst(char* expr_buf, int* handled, char** out_value) {
    if (handled) *handled = 0;
    if (out_value) *out_value = NULL;
    if (!expr_buf) return 0;
    trim_spaces(expr_buf);
    size_t len = strlen(expr_buf);
    if (len < 3 || expr_buf[0] != '%' || expr_buf[1] != '(' || expr_buf[len-1] != ')') {
        return 0;
    }
    expr_buf[len-1] = '\0';
    char* inner = expr_buf + 2;
    trim_spaces(inner);
    if (handled) *handled = 1;
    char *subst_val = NULL;
    int rc = osh_exec_subcommand(inner, &subst_val);
    if (rc == OSH_SCRIPT_ABORT || rc == OSH_SCRIPT_EXIT || rc == OSH_SCRIPT_RETURN) {
        if (subst_val) kfree(subst_val);
        return rc;
    }
    if (!subst_val) subst_val = (char*)kcalloc(1,1);
    if (out_value) *out_value = subst_val;
    else if (subst_val) kfree(subst_val);
    return rc;
}

static int osh_eval_function_call(char* expr_buf, int* handled, char** out_value) {
    if (keyboard_ctrlc_pending()) { keyboard_consume_ctrlc(); return OSH_SCRIPT_ABORT; }
    if (handled) *handled = 0;
    if (out_value) *out_value = NULL;
    if (!expr_buf || !g_active_script_ctx) return 0;
    trim_spaces(expr_buf);
    if (!*expr_buf) return 0;
    char *p = expr_buf;
    char fname[32]; int ni = 0;
    if (!is_var_name_char1(*p)) return 0;
    while (*p && is_var_name_char(*p) && ni < (int)sizeof(fname)-1) {
        fname[ni++] = *p++;
    }
    fname[ni] = '\0';
    if (ni == 0) return 0;
    while (*p==' '||*p=='\t') p++;
    if (*p != '(') return 0;
    p++; // skip '('
    char* args[8] = {0}; int ac = 0;
    char* token_buf = (char*)kcalloc(1, 512);
    if (!token_buf) return 0;
    int ti = 0;
    int depth = 1;
    int inq = 0;
    char quote = 0;
    while (*p && depth > 0) {
        char ch = *p;
        if (inq) {
            if (ch == quote) inq = 0;
        } else {
            if (ch == '"' || ch=='\'') { inq = 1; quote = ch; }
            else if (ch == '(') { depth++; }
            else if (ch == ')') {
                depth--;
                if (depth == 0) {
                    token_buf[ti] = '\0';
                    char* trimmed = osh_dup_trim(token_buf);
                    if (!trimmed) trimmed = (char*)kcalloc(1,1);
                    if (ac < 8) args[ac++] = trimmed; else kfree(trimmed);
                    ti = 0;
                    break;
                }
            } else if (ch == ',' && depth == 1) {
                token_buf[ti] = '\0';
                char* trimmed = osh_dup_trim(token_buf);
                if (!trimmed) trimmed = (char*)kcalloc(1,1);
                if (ac < 8) args[ac++] = trimmed; else kfree(trimmed);
                ti = 0;
                p++;
                continue;
            }
        }
        if (depth > 0) {
            if (ti < 511) token_buf[ti++] = ch;
        }
        p++;
    }
    kfree(token_buf);
    if (depth != 0) {
        for (int i=0;i<ac;i++) if (args[i]) kfree(args[i]);
        return 0;
    }
    while (*p==' '||*p=='\t') p++;
    if (*p != '\0') {
        for (int i=0;i<ac;i++) if (args[i]) kfree(args[i]);
        return 0;
    }
    int fi = osh_find_func(g_active_script_ctx, fname);
    if (fi < 0) {
        for (int i=0;i<ac;i++) if (args[i]) kfree(args[i]);
        return 0;
    }
    char* ret_val = NULL;
    if (handled) *handled = 1;
    int rc = osh_call_func(g_active_script_ctx, fi, args, ac, &ret_val);
    for (int i=0;i<ac;i++) if (args[i]) kfree(args[i]);
    if (rc == OSH_SCRIPT_ABORT || rc == OSH_SCRIPT_EXIT) {
        if (ret_val) kfree(ret_val);
        return rc;
    }
    if (!ret_val) ret_val = (char*)kcalloc(1,1);
    if (out_value) *out_value = ret_val;
    else if (ret_val) kfree(ret_val);
    return rc;
}

static int osh_eval_rhs(char* rhs, char** out_value) {
    if (out_value) *out_value = NULL;
    if (!rhs) return 1;
    trim_spaces(rhs);
    if (!*rhs) {
        if (out_value) *out_value = (char*)kcalloc(1,1);
        return 0;
    }
    if (keyboard_ctrlc_pending()) { keyboard_consume_ctrlc(); return OSH_SCRIPT_ABORT; }
    int handled = 0;
    char* val = NULL;
    int rc = osh_eval_command_subst(rhs, &handled, &val);
    if (handled) {
        if (out_value) *out_value = val;
        else if (val) kfree(val);
        return rc;
    }
    handled = 0;
    rc = osh_eval_function_call(rhs, &handled, &val);
    if (handled) {
        if (out_value) *out_value = val;
        else if (val) kfree(val);
        return rc;
    }
    // Replace any inline function calls within arithmetic expressions
    // Example: "fib(10) + fib(9)" -> evaluate sub-calls to numbers first
    if (g_active_script_ctx) {
        // Try at most 64 substitutions to avoid infinite loops
        for (int pass = 0; pass < 64; pass++) {
            if (keyboard_ctrlc_pending()) { keyboard_consume_ctrlc(); return OSH_SCRIPT_ABORT; }
            const char* p = rhs;
            // find identifier followed by '(' and matching ')'
            int found = 0;
            const char* start = NULL;
            const char* end = NULL;
            // scan for name(
            for (; *p; p++) {
                if (is_var_name_char1(*p)) {
                    const char* q = p + 1;
                    while (*q && is_var_name_char(*q)) q++;
                    while (*q==' '||*q=='\t') q++;
                    if (*q == '(') {
                        // find matching ')'
                        int depth = 1; const char* r = q + 1;
                        int inq = 0; char quote = 0;
                        while (*r) {
                            char ch = *r;
                            if (inq) { if (ch == quote) inq = 0; r++; continue; }
                            if (ch=='"' || ch=='\'') { inq=1; quote=ch; r++; continue; }
                            if (ch=='(') depth++;
                            else if (ch==')') { depth--; if (depth==0) { end = r; break; } }
                            r++;
                        }
                        if (end) { start = p; found = 1; break; }
                    }
                }
            }
            if (!found) break;
            // build substring [start, end] inclusive, then evaluate as a single call
            size_t sub_len = (size_t)(end - start + 1);
            char* sub = (char*)kcalloc(sub_len + 1, 1);
            if (!sub) break;
            memcpy(sub, start, sub_len); sub[sub_len] = '\0';
            int h = 0; char* sub_val = NULL;
            int rc2 = osh_eval_function_call(sub, &h, &sub_val);
            kfree(sub);
            if (rc2 == OSH_SCRIPT_ABORT || rc2 == OSH_SCRIPT_EXIT || rc2 == OSH_SCRIPT_RETURN) {
                if (sub_val) kfree(sub_val);
                return rc2;
            }
            if (!h) { if (sub_val) kfree(sub_val); break; }
            if (!sub_val) sub_val = (char*)kcalloc(1,1);
            // splice back: prefix + sub_val + suffix into a new rhs buffer
            size_t prefix_len = (size_t)(start - rhs);
            size_t suffix_len = strlen(end + 1);
            size_t sv_len = strlen(sub_val);
            size_t ncap = prefix_len + sv_len + suffix_len + 1;
            char* nb = (char*)kcalloc(ncap, 1);
            if (!nb) { kfree(sub_val); break; }
            if (prefix_len) memcpy(nb, rhs, prefix_len);
            if (sv_len) memcpy(nb + prefix_len, sub_val, sv_len);
            if (suffix_len) memcpy(nb + prefix_len + sv_len, end + 1, suffix_len);
            nb[prefix_len + sv_len + suffix_len] = '\0';
            kfree(sub_val);
            // replace rhs contents in-place (caller provided modifiable buffer)
            size_t nb_len = strlen(nb);
            size_t rhs_cap = strlen(rhs); // best effort: assume buffer is large; if not, reallocate
            // safer: reallocate
            char* repl = (char*)kcalloc(nb_len + 1, 1);
            if (repl) {
                memcpy(repl, nb, nb_len + 1);
                // swap pointers
                // free old rhs only if it was heap-allocated by us; we cannot know, so copy back
                // to existing buffer up to its size; since osh_eval_rhs callers pass local arrays
                // sized reasonably (512), this copy is safe within their limits.
                // Copy back with truncation protection
                size_t maxcpy = nb_len;
                // assume rhs buffer is at least 512; keep conservative 511
                if (maxcpy > 511) maxcpy = 511;
                memcpy(rhs, repl, maxcpy);
                rhs[maxcpy] = '\0';
                kfree(repl);
            } else {
                // fallback: copy into rhs directly
                size_t maxcpy = nb_len;
                if (maxcpy > 511) maxcpy = 511;
                memcpy(rhs, nb, maxcpy);
                rhs[maxcpy] = '\0';
            }
            kfree(nb);
        }
    }
    char *rhs_exp = expand_vars(rhs);
    const char* R0 = rhs_exp ? rhs_exp : rhs;
    char *rhs_ident = osh_expand_idents(R0);
    const char* R = rhs_ident ? rhs_ident : R0;
    int arith = 1;
    int has_op = 0;
    for (const char* q = R; *q; q++) {
        char c = *q;
        if (c=='+'||c=='-'||c=='*'||c=='/'||c=='('||c==')') has_op = 1;
        if (!(c==' '||c=='\t'||c=='+'||c=='-'||c=='*'||c=='/'||c=='('||c==')'||c=='.'||(c>='0'&&c<='9'))) {
            arith = 0;
            break;
        }
    }
    if (!has_op) arith = 0;
    if (arith && *R) {
        const char* s = R;
        double valnum = osh_parse_expr(&s);
        char buf[64];
        osh_double_to_str(valnum, buf, sizeof(buf));
        size_t blen = strlen(buf);
        char* out = (char*)kcalloc(blen + 1, 1);
        if (out) memcpy(out, buf, blen + 1);
        if (out_value) *out_value = out;
        if (rhs_ident) kfree(rhs_ident);
        if (rhs_exp) kfree(rhs_exp);
        return 0;
    }
    const char* final_src = rhs_ident ? rhs_ident : R0;
    size_t flen = strlen(final_src);
    char* out = (char*)kcalloc(flen + 1, 1);
    if (out && flen) memcpy(out, final_src, flen + 1);
    if (!out) out = (char*)kcalloc(1,1);
    strip_matching_quotes(out);
    if (out_value) *out_value = out;
    if (rhs_ident) kfree(rhs_ident);
    if (rhs_exp) kfree(rhs_exp);
    return 0;
}

int exec_line(const char *line) {
    if (!line) return 0;
    const char* lp = line;
    while (*lp==' '||*lp=='\t') lp++;
    if (g_script_depth > 0 && strncmp(lp, "return", 6) == 0 && (lp[6]==' '||lp[6]=='\t'||lp[6]=='\0')) {
        lp += 6;
        while (*lp==' '||*lp=='\t') lp++;
        char* expr = osh_dup_trim(lp);
        if (!expr) expr = (char*)kcalloc(1,1);
        char* value = NULL;
        int rc_eval = osh_eval_rhs(expr, &value);
        if (expr) kfree(expr);
        if (rc_eval == OSH_SCRIPT_ABORT || rc_eval == OSH_SCRIPT_EXIT) {
            if (value) kfree(value);
            return rc_eval;
        }
        if (!value) value = (char*)kcalloc(1,1);
        if (g_script_return_value) { kfree(g_script_return_value); g_script_return_value = NULL; }
        g_script_return_value = value;
        g_script_return_pending = 1;
        return OSH_SCRIPT_RETURN;
    }
    int tn=0; token *t = lex(line, &tn); if (tn==0) { if (t) kfree(t); return 0; }
    int i=0; int status=0; // 0 success, non-zero fail; exit=2
    while (i < tn) {
        int j = i;
        while (j < tn && t[j].t != T_AND && t[j].t != T_OR) j++;
        // execute segment [i,j)
        char *out=NULL; size_t out_len=0,out_cap=0;
        int rc = exec_pipeline(t, i, j, NULL, &out, &out_len, &out_cap);
        if (rc == 2) { free_tokens(t, tn); if (out) kfree(out); return 2; }
        if (rc == OSH_SCRIPT_EXIT) { free_tokens(t, tn); if (out) kfree(out); return OSH_SCRIPT_EXIT; }
        if (rc == OSH_SCRIPT_ABORT) { free_tokens(t, tn); if (out) kfree(out); return OSH_SCRIPT_ABORT; }
        if (rc == OSH_SCRIPT_RETURN) { free_tokens(t, tn); if (out) kfree(out); return OSH_SCRIPT_RETURN; }
        status = rc;
        // print to screen if there is output (and not redirected)
        if (out && out_len > 0) {
            // ensure 0-termination using a small temporary buffer to avoid heap resizing stalls
            char *plain_tmp = (char*)kmalloc(out_len + 1);
            if (plain_tmp) { memcpy(plain_tmp, out, out_len); plain_tmp[out_len] = '\0'; }
            // Print output plainly (color tags are not interpreted)
            if (plain_tmp) { kprint((uint8_t*)plain_tmp); if (plain_tmp[out_len-1] != '\n') kprint((uint8_t*)"\n"); }
            if (plain_tmp) kfree(plain_tmp);
            kfree(out); out=NULL;
        }
        if (j == tn) break;
        if (t[j].t == T_AND) { if (status != 0) { // skip next until next AND/OR
                i = j + 1; // move over operator; but still execute next; AND means execute only if success; we already failed => skip one segment?
                // Skip one segment
                int k = j+1; while (k<tn && t[k].t != T_AND && t[k].t != T_OR) k++; i = k; continue; } }
        else if (t[j].t == T_OR) { if (status == 0) { int k = j+1; while (k<tn && t[k].t != T_AND && t[k].t != T_OR) k++; i = k; continue; } }
        i = j + 1;
    }
    free_tokens(t, tn);
    return status;
}

// -------- background jobs (minimal) --------
typedef struct job { char *line; struct job *next; } job;
static job *jobs_head = NULL;
static void job_push(const char *line) { job *j=(job*)kmalloc(sizeof(job)); size_t n=strlen(line); j->line=(char*)kmalloc(n+1); memcpy(j->line,line,n+1); j->next=jobs_head; jobs_head=j; }
static job* job_pop(void) { job *j=jobs_head; if (j) jobs_head=j->next; return j; }

static void bg_thread_entry(void) {
    job *j = job_pop(); if (!j) return; (void)exec_line(j->line); kfree(j->line); kfree(j);
}

// -------- public loop --------
static void build_prompt(char* out, size_t outsz) {
    if (!out || outsz == 0) return;
    out[0] = '\0';
    const char* ps1 = var_get("PS1");
    if (ps1 && ps1[0]) {
        char* exp = expand_vars(ps1);
        const char* s = exp ? exp : ps1;
        size_t pos = 0;
        for (const char* p = s; *p && pos < outsz - 1; p++) {
            if (*p == '\\') {
                p++;
                if (!*p) break;
                char c = *p;
                if (c == 'n') { out[pos++] = '\n'; }
                else if (c == 'w') {
                    size_t L = strlen(g_cwd);
                    if (L > outsz - 1 - pos) L = outsz - 1 - pos;
                    if (L) { memcpy(out + pos, g_cwd, L); pos += L; }
                } else if (c == 'W') {
                    const char* base = g_cwd;
                    const char* last = NULL;
                    for (const char* q = g_cwd; *q; q++) if (*q == '/') last = q;
                    if (last) base = (*(last+1)) ? (last+1) : last;
                    size_t L = strlen(base);
                    if (L > outsz - 1 - pos) L = outsz - 1 - pos;
                    if (L) { memcpy(out + pos, base, L); pos += L; }
                } else if (c == '\\') { out[pos++] = '\\'; }
                else if (c == '$') { out[pos++] = '$'; }
                else { out[pos++] = c; }
            } else {
                out[pos++] = *p;
            }
        }
        out[pos] = '\0';
        if (exp) kfree(exp);
        if (out[0]) return;
    }
    // default prompt: "<cwd> > "
    strncpy(out, g_cwd, outsz > 3 ? outsz - 3 : outsz - 1);
    out[outsz - 1] = '\0';
    size_t cur = strlen(out);
    if (cur + 2 < outsz) { out[cur++] = '>'; out[cur++] = ' '; out[cur] = '\0'; }
}

void osh_run(void) {
    kprintf("%s v%s (%s)\n", OSH_NAME, OSH_VERSION, OSH_FULL_NAME);
    static char buf[512];
    osh_history_init();
    for (;;) {
        /* приглашение osh + строковый редактор */
        char prompt[128]; build_prompt(prompt, sizeof(prompt));
        int n = osh_line_read(prompt, g_cwd, buf, (int)sizeof(buf));
        if (n < 0) continue;
        char *line = buf;
        // Detect trailing background '&' at top level quickly; if present -> spawn job thread
        int tn=0; token *t = lex(line, &tn); if (tn==0) { if (t) kfree(t); continue; }
        int bg = (t[tn-1].t == T_BG);
        free_tokens(t, tn);
        if (!bg) osh_history_add(line);
        if (bg) { job_push(line); thread_create(bg_thread_entry, "bg"); continue; }
        int rc = exec_line(line); if (rc == 2) break; // exit
    }
}

// ---- small helpers for other subsystems ----
void osh_get_cwd(char* out, unsigned long outlen) {
    if (!out || outlen==0) return; if (outlen<2) { out[0]='\0'; return; }
    strncpy(out, g_cwd, (size_t)outlen-1); out[outlen-1] = '\0';
}

void osh_resolve_path(const char* base, const char* arg, char* out, unsigned long outlen) {
    if (!out || outlen==0) return; if (!arg) { out[0]='\0'; return; }
    if (arg[0]=='/') { strncpy(out, arg, (size_t)outlen-1); out[outlen-1]='\0'; return; }
    const char* b = base ? base : g_cwd; resolve_path(b, arg, out, (size_t)outlen);
}


