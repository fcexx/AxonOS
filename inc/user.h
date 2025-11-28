#ifndef INC_USER_H
#define INC_USER_H

#include <stddef.h>
#include "stdint.h"

typedef unsigned int uid_t;
typedef unsigned int gid_t;

#define ROOT_USER_NAME "root"
#define ROOT_UID 0
#define ROOT_GID 0

struct user {
    char name[32];
    uid_t uid;
    gid_t gid;
    char *passwd_hash; /* simple hash stored as string (not cryptographically secure) */
    char *groups; /* comma-separated group names */
};

/* Initialize user subsystem and create default root user */
int user_init(void);

/* Get current user name (returns pointer to internal string) */
const char* user_get_current_name(void);
uid_t user_get_current_uid(void);

/* Set current user by name; returns 0 on success */
int user_set_current(const char *name);

/* Add or update user */
int user_add(const char *name, uid_t uid, gid_t gid, const char *groups);

/* Set password for user (stores hashed) */
int user_set_password(const char *name, const char *password);

/* Check password; returns 1 if ok, 0 otherwise */
int user_check_password(const char *name, const char *password);

/* Find user by name; returns pointer or NULL */
struct user* user_find(const char *name);

/* Export /etc/passwd content into newly allocated buffer (kmalloc). 
   Caller must kfree(*out). Returns 0 on success. */
int user_export_passwd(char **out, size_t *out_len);

/* Get next unused uid (simple: max existing + 1) */
uid_t user_get_next_uid(void);

#endif


