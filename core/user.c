#include "../inc/user.h"
#include "../inc/heap.h"
#include <string.h>
#include "../inc/thread.h"

/* avoid including host stdlib headers in kernel code */

/* Simple in-memory user database, no persistence */
#define MAX_USERS 64
static struct user g_users[MAX_USERS];
static int g_user_count = 0;
static uid_t g_current_uid = ROOT_UID;

/* djb2-like simple hash, not for real security */
static unsigned long simple_hash(const char *s) {
    unsigned long h = 5381;
    while (*s) { h = ((h << 5) + h) + (unsigned char)(*s++); }
    return h;
}

static char* strdup_k(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *p = (char*)kmalloc(n+1);
    if (!p) return NULL;
    memcpy(p, s, n+1);
    return p;
}

int user_add(const char *name, uid_t uid, gid_t gid, const char *groups) {
    if (!name) return -1;
    if (g_user_count >= MAX_USERS) return -1;
    for (int i=0;i<g_user_count;i++) if (strcmp(g_users[i].name, name)==0) return -2;
    struct user *u = &g_users[g_user_count++];
    strncpy(u->name, name, sizeof(u->name)-1); u->name[sizeof(u->name)-1] = '\0';
    u->uid = uid; u->gid = gid;
    u->passwd_hash = NULL;
    if (groups && groups[0]) u->groups = strdup_k(groups);
    else u->groups = strdup_k(name); /* default primary group = username */
    return 0;
}

struct user* user_find(const char *name) {
    if (!name) return NULL;
    for (int i=0;i<g_user_count;i++) if (strcmp(g_users[i].name, name)==0) return &g_users[i];
    return NULL;
}

int user_set_password(const char *name, const char *password) {
    struct user *u = user_find(name);
    if (!u) return -1;
    if (u->passwd_hash) kfree(u->passwd_hash);
    unsigned long h = simple_hash(password ? password : "");
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%lu", h);
    u->passwd_hash = (char*)kmalloc((size_t)n + 1);
    if (!u->passwd_hash) return -1;
    memcpy(u->passwd_hash, buf, (size_t)n + 1);
    return 0;
}

int user_check_password(const char *name, const char *password) {
    struct user *u = user_find(name);
    if (!u) return 0;
    if (!u->passwd_hash) return 0;
    unsigned long h = simple_hash(password ? password : "");
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%lu", h);
    return (strcmp(u->passwd_hash, buf) == 0) ? 1 : 0;
}

int user_set_current(const char *name) {
    struct user *u = user_find(name);
    if (!u) return -1;
    g_current_uid = u->uid;
    return 0;
}

/* user_get_current_name / user_get_current_uid implemented later using thread credentials */

int user_init(void) {
    /* create root user */
    g_user_count = 0;
    user_add(ROOT_USER_NAME, ROOT_UID, ROOT_GID, "root");
    /* no password by default */
    user_set_current(ROOT_USER_NAME);
    return 0;
}

int user_export_passwd(char **out, size_t *out_len) {
    if (!out || !out_len) return -1;
    /* estimate size */
    size_t cap = (size_t)g_user_count * 64 + 16;
    char *buf = (char*)kmalloc(cap);
    if (!buf) return -1;
    size_t pos = 0;
    for (int i=0;i<g_user_count;i++) {
        struct user *u = &g_users[i];
        /* format: name:x:uid:gid::\n */
        int n = snprintf(buf + pos, (pos < cap) ? cap - pos : 0, "%s:x:%u:%u::\n", u->name, u->uid, u->gid);
        if (n <= 0) break;
        pos += (size_t)n;
        if (pos + 128 > cap) {
            size_t ncap = cap * 2;
            char *nb = (char*)krealloc(buf, ncap);
            if (!nb) break;
            buf = nb; cap = ncap;
        }
    }
    *out = buf; *out_len = pos;
    return 0;
}

uid_t user_get_next_uid(void) {
    uid_t max = 1000;
    for (int i=0;i<g_user_count;i++) if (g_users[i].uid >= max) max = g_users[i].uid;
    return max + 1;
}

const char* user_get_current_name(void) {
    /* prefer thread-local credentials if available */
    thread_t* t = thread_current();
    uid_t uid = (t) ? t->euid : g_current_uid;
    for (int i=0;i<g_user_count;i++) if (g_users[i].uid == uid) return g_users[i].name;
    return ROOT_USER_NAME;
}

uid_t user_get_current_uid(void) {
    thread_t* t = thread_current();
    return (t) ? t->euid : g_current_uid;
}


