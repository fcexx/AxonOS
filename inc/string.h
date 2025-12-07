#ifndef STRING_H
#define STRING_H

#include <stdint.h>
#include <stddef.h>

// functions for working with strings
size_t strlen(const char* str);
char* strcpy(char* dest, const char* src);
char* strncpy(char* dest, const char* src, size_t n);
int strcmp(const char* str1, const char* str2);
int strncmp(const char* str1, const char* str2, size_t n);
char* strcat(char* dest, const char* src);
char* strncat(char* dest, const char* src, size_t n);
char* strchr(const char* str, int c);
char* strrchr(const char* str, int c);
char* strstr(const char* haystack, const char* needle);
char* strtok(char* str, const char* delim);
int trim(char* str);
// split string by any delimiters in delim; returns NULL-terminated array of tokens
// writes number of tokens to *n if n != NULL
char** split(const char* str, char* delim, int* n);

// functions for working with memory
void* memcpy(void* dest, const void* src, size_t n);
void* memmove(void* dest, const void* src, size_t n);
void* memset(void* ptr, int value, size_t n);
int memcmp(const void* ptr1, const void* ptr2, size_t n);

// additional functions
void itoa(int value, char* str, int base);
void utoa(uint32_t value, char* str, int base);
int atoi(const char* str);
void reverse(char* str, size_t length);
size_t strnlen(const char* s, size_t maxlen);

uint32_t simple_hex_to_u32(const char* str);
uint32_t simple_dec_to_u32(const char* str);
char* strdup(const char* str);
int isxdigit(int c);
int isspace(int c);
int strcasecmp(const char* s1, const char* s2);
char* strpbrk(const char* s, const char* accept);

#endif // STRING_H