#pragma once

#include <stddef.h>
#include <stdint.h>

typedef unsigned long ino_t;
typedef unsigned int mode_t;
typedef unsigned int nlink_t;
typedef long off_t;
typedef long time_t;

struct stat {
    ino_t st_ino;
    mode_t st_mode;
    nlink_t st_nlink;
    unsigned int st_uid;
    unsigned int st_gid;
    off_t st_size;
    time_t st_atime;
    time_t st_mtime;
    time_t st_ctime;
};

/* File type macros */
#ifndef S_IFDIR
#define S_IFDIR 0040000
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif



