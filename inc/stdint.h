#pragma once
/* If a system stdint already provided limits, skip redefinition to avoid conflicts */
#ifndef UINT64_MAX

/* Most commonly used types */
#ifndef NULL
#define NULL ((void *)0)
#endif
#ifndef bool
#define bool int
#endif
#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif

#define UINT32_MAX 0xFFFFFFFF
#define UINT64_MAX 0xFFFFFFFFFFFFFFFF

/* stdint types */
typedef unsigned char       uint8_t;
typedef   signed char        int8_t;
typedef unsigned short     uint16_t;
typedef   signed short      int16_t;
typedef unsigned int       uint32_t;
typedef   signed int        int32_t;
typedef unsigned long uint64_t;
typedef   signed long  int64_t;
typedef unsigned long     uintptr_t;
typedef   signed long      intptr_t;

/* those are commonly provided by sys/types.h */
typedef unsigned long         ino_t;
typedef unsigned int         mode_t;
typedef   signed int          pid_t;
typedef unsigned int          uid_t;
typedef unsigned int          gid_t;
typedef   signed long         off_t;
typedef   signed long     blksize_t;
typedef   signed long      blkcnt_t;
typedef   signed long        time_t;

#endif /* UINT64_MAX */