#include <string.h>
#include <heap.h>

// Простое преобразование hex строки в число (без 0x префикса)
uint32_t simple_hex_to_u32(const char* str) {
    uint32_t result = 0;
    
    if (!str) return 0;
    
    // Пропускаем пробелы
    while (*str == ' ' || *str == '\t') str++;
    
    // Пропускаем "0x" если есть
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        str += 2;
    }
    
    while (*str) {
        char c = *str;
        uint8_t digit;
        
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            digit = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            digit = c - 'A' + 10;
        } else {
            break;
        }
        
        result = (result << 4) | digit;
        str++;
    }
    
    return result;
}

// Простое преобразование dec строки в число  
uint32_t simple_dec_to_u32(const char* str) {
    uint32_t result = 0;
    
    if (!str) return 0;
    
    // Пропускаем пробелы
    while (*str == ' ' || *str == '\t') str++;
    
    while (*str >= '0' && *str <= '9') {
        result = result * 10 + (*str - '0');
        str++;
    }
    
    return result;
}

// Копирование строки с выделением памяти
char* strdup(const char* str) {
    if (!str) return NULL;
    
    size_t len = strlen(str) + 1;
    char* copy = kmalloc(len);
    if (copy) {
        memcpy(copy, str, len);
    }
    return copy;
}

// Проверка символа на hex цифру
int isxdigit(int c) {
    return (c >= '0' && c <= '9') || 
           (c >= 'a' && c <= 'f') || 
           (c >= 'A' && c <= 'F');
}

// Проверка символа на пробел (табуляция и т.д.)
int isspace(int c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

// Проверка символа на цифру
int isdigit(int c) {
    return (c >= '0' && c <= '9');
}

// Сравнение строк без учета регистра
int strcasecmp(const char* s1, const char* s2) {
    if (!s1 || !s2) {
        if (!s1 && !s2) return 0;
        return s1 ? 1 : -1;
    }
    
    while (*s1 && *s2) {
        char c1 = *s1, c2 = *s2;
        
        // Приводим к нижнему регистру
        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        
        if (c1 != c2) return (int)(unsigned char)c1 - (int)(unsigned char)c2;
        s1++;
        s2++;
    }
    
    return (int)(unsigned char)*s1 - (int)(unsigned char)*s2;
}

// Поиск символа в строке (для разделителей)
char* strpbrk(const char* s, const char* accept) {
    if (!s || !accept) return NULL;
    
    while (*s) {
        const char* a = accept;
        while (*a) {
            if (*s == *a) return (char*)s;
            a++;
        }
        s++;
    }
    return NULL;
}

// Поиск последнего вхождения любого символа из accept
char* strrpbrk(const char* s, const char* accept) {
    if (!s || !accept) return NULL;
    
    char* last = NULL;
    while (*s) {
        const char* a = accept;
        while (*a) {
            if (*s == *a) {
                last = (char*)s;
                break;
            }
            a++;
        }
        s++;
    }
    return last;
}

// Преобразует hex строку в число (с поддержкой 0x)
uint32_t hex_str_to_u32(const char* str) {
    return simple_hex_to_u32(str);
}

// Преобразует dec строку в число
uint32_t dec_str_to_u32(const char* str) {
    return simple_dec_to_u32(str);
}

// Функция для быстрого парсинга чисел из строк (десятичных или шестнадцатеричных)
int parse_number(const char* str, uint32_t* result) {
    if (!str || !result) return -1;
    
    // Пропускаем пробелы
    while (isspace(*str)) str++;
    
    if (*str == '\0') return -1;
    
    // Проверяем формат
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        *result = hex_str_to_u32(str);
    } else {
        *result = dec_str_to_u32(str);
    }
    
    return 0;
}

// Вычисляет длину строки
size_t strlen(const char* str) {
        size_t len = 0;
        while (str[len] != '\0') {
                len++;
        }
        return len;
}

// Копирует строку
char* strcpy(char* dest, const char* src) {
        char* ptr = dest;
        while (*src != '\0') {
                *ptr = *src;
                ptr++;
                src++;
        }
        *ptr = '\0';
        return dest;
}

// Копирует n символов строки
char* strncpy(char* dest, const char* src, size_t n) {
        char* ptr = dest;
        size_t i = 0;
        
        while (i < n && *src != '\0') {
                *ptr = *src;
                ptr++;
                src++;
                i++;
        }
        
        while (i < n) {
                *ptr = '\0';
                ptr++;
                i++;
        }
        
        return dest;
}

// Сравнивает две строки
int strcmp(const char* str1, const char* str2) {
        while (*str1 != '\0' && *str2 != '\0') {
                if (*str1 != *str2) {
                        return (*str1 < *str2) ? -1 : 1;
                }
                str1++;
                str2++;
        }
        
        if (*str1 == '\0' && *str2 == '\0') {
                return 0;
        }
        
        return (*str1 == '\0') ? -1 : 1;
}

// Сравнивает n символов двух строк
int strncmp(const char* str1, const char* str2, size_t n) {
        size_t i = 0;
        
        while (i < n && *str1 != '\0' && *str2 != '\0') {
                if (*str1 != *str2) {
                        return (*str1 < *str2) ? -1 : 1;
                }
                str1++;
                str2++;
                i++;
        }
        
        if (i == n) {
                return 0;
        }
        
        if (*str1 == '\0' && *str2 == '\0') {
                return 0;
        }
        
        return (*str1 == '\0') ? -1 : 1;
}

// Объединяет две строки
char* strcat(char* dest, const char* src) {
        char* ptr = dest + strlen(dest);
        
        while (*src != '\0') {
                *ptr = *src;
                ptr++;
                src++;
        }
        
        *ptr = '\0';
        return dest;
}

// Объединяет n символов строки
char* strncat(char* dest, const char* src, size_t n) {
        char* ptr = dest + strlen(dest);
        size_t i = 0;
        
        while (i < n && *src != '\0') {
                *ptr = *src;
                ptr++;
                src++;
                i++;
        }
        
        *ptr = '\0';
        return dest;
}

// Находит первое вхождение символа в строке
char* strchr(const char* str, int c) {
        while (*str != '\0') {
                if (*str == (char)c) {
                        return (char*)str;
                }
                str++;
        }
        
        if (c == '\0') {
                return (char*)str;
        }
        
        return NULL;
}

// Находит последнее вхождение символа в строке
char* strrchr(const char* str, int c) {
        char* last = NULL;
        
        while (*str != '\0') {
                if (*str == (char)c) {
                        last = (char*)str;
                }
                str++;
        }
        
        if (c == '\0') {
                return (char*)str;
        }
        
        return last;
}

// Находит подстроку в строке
char* strstr(const char* haystack, const char* needle) {
        if (*needle == '\0') {
                return (char*)haystack;
        }
        
        while (*haystack != '\0') {
                const char* h = haystack;
                const char* n = needle;
                
                while (*h != '\0' && *n != '\0' && *h == *n) {
                        h++;
                        n++;
                }
                
                if (*n == '\0') {
                        return (char*)haystack;
                }
                
                haystack++;
        }
        
        return NULL;
}

// Копирует память
void* memcpy(void* dest, const void* src, size_t n) {
        uint8_t* d = (uint8_t*)dest;
        const uint8_t* s = (const uint8_t*)src;
        
        for (size_t i = 0; i < n; i++) {
                d[i] = s[i];
        }
        
        return dest;
}

// Перемещает память (с учетом перекрытия)
void* memmove(void* dest, const void* src, size_t n) {
        uint8_t* d = (uint8_t*)dest;
        const uint8_t* s = (const uint8_t*)src;
        
        if (d < s) {
                // Копируем вперед
                for (size_t i = 0; i < n; i++) {
                        d[i] = s[i];
                }
        } else if (d > s) {
                // Копируем назад
                for (size_t i = n; i > 0; i--) {
                        d[i-1] = s[i-1];
                }
        }
        
        return dest;
}

// Заполняет память значением
void* memset(void* ptr, int value, size_t n) {
        uint8_t* p = (uint8_t*)ptr;
        
        for (size_t i = 0; i < n; i++) {
                p[i] = (uint8_t)value;
        }
        
        return ptr;
}

// Сравнивает память
int memcmp(const void* ptr1, const void* ptr2, size_t n) {
        const uint8_t* p1 = (const uint8_t*)ptr1;
        const uint8_t* p2 = (const uint8_t*)ptr2;
        
        for (size_t i = 0; i < n; i++) {
                if (p1[i] != p2[i]) {
                        return (p1[i] < p2[i]) ? -1 : 1;
                }
        }
        
        return 0;
}

// Переворачивает строку
void reverse(char* str, size_t length) {
        size_t start = 0;
        size_t end = length - 1;
        
        while (start < end) {
                char temp = str[start];
                str[start] = str[end];
                str[end] = temp;
                start++;
                end--;
        }
}

// Преобразует целое число в строку
void itoa(int value, char* str, int base) {
        int i = 0;
        bool isNegative = false;
        
        // Обрабатываем 0 отдельно
        if (value == 0) {
                str[i++] = '0';
                str[i] = '\0';
                return;
        }
        
        // Обрабатываем отрицательные числа только для десятичной системы
        if (value < 0 && base == 10) {
                isNegative = true;
                value = -value;
        }
        
        // Преобразуем число в строку
        while (value != 0) {
                int rem = value % base;
                str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
                value = value / base;
        }
        
        // Добавляем знак минус для отрицательных чисел
        if (isNegative) {
                str[i++] = '-';
        }
        
        str[i] = '\0';
        
        // Переворачиваем строку
        reverse(str, i);
}

// Преобразует беззнаковое целое число в строку
void utoa(uint32_t value, char* str, int base) {
        int i = 0;
        
        // Обрабатываем 0 отдельно
        if (value == 0) {
                str[i++] = '0';
                str[i] = '\0';
                return;
        }
        
        // Преобразуем число в строку
        while (value != 0) {
                uint32_t rem = value % base;
                str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
                value = value / base;
        }
        
        str[i] = '\0';
        
        // Переворачиваем строку
        reverse(str, i);
}

// Преобразует строку в целое число
int atoi(const char* str) {
        int result = 0;
        int sign = 1;
        int i = 0;
        
        // Пропускаем пробелы
        while (str[i] == ' ' || str[i] == '\t' || str[i] == '\n') {
                i++;
        }
        
        // Обрабатываем знак
        if (str[i] == '-' || str[i] == '+') {
                sign = (str[i] == '-') ? -1 : 1;
                i++;
        }
        
        // Преобразуем цифры
        while (str[i] >= '0' && str[i] <= '9') {
                result = result * 10 + (str[i] - '0');
                i++;
        }
        
        return sign * result;
} 

int trim(char* str) {
        if (!str) return 0;
        
        // Удаляем пробелы в начале
        while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r') {
                str++;
        }
        
        if (*str == '\0') {
                return 0;
        }
        
        // Удаляем пробелы в конце
        char* end = str + strlen(str) - 1;
        while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
                end--;
        }
        
        *(end + 1) = '\0';
        return 1;
}

// Реализация strtok
static char* strtok_save = NULL;

char* strtok(char* str, const char* delim) {
        if (!str && !strtok_save) {
                return NULL;
        }
        
        if (str) {
                strtok_save = str;
        }
        
        if (!strtok_save) {
                return NULL;
        }
        
        // Пропускаем разделители в начале
        while (*strtok_save && strchr(delim, *strtok_save)) {
                strtok_save++;
        }
        
        if (*strtok_save == '\0') {
                strtok_save = NULL;
                return NULL;
        }
        
        char* token_start = strtok_save;
        
        // Ищем следующий разделитель
        while (*strtok_save && !strchr(delim, *strtok_save)) {
                strtok_save++;
        }
        
        if (*strtok_save) {
                *strtok_save = '\0';
                strtok_save++;
        } else {
                strtok_save = NULL;
        }
        
        return token_start;
}

size_t strnlen(const char* s, size_t maxlen) {
        size_t i = 0;
        if (!s) return 0;
        while (i < maxlen && s[i] != '\0') {
                i++;
        }
        return i;
}

static int is_delim(char c, const char* delim) {
        for (const char* d = delim; *d; ++d) if (c == *d) return 1;
        return 0;
}

char** split(const char* str, char* delim, int* n) {
        if (!str || !delim) {
                char** empty = (char**)kmalloc(sizeof(char*));
                if (empty) empty[0] = NULL;
                if (n) *n = 0;
                return empty;
        }

        // First pass: count tokens
        size_t count = 0;
        const char* p = str;
        while (*p) {
                while (*p && is_delim(*p, delim)) p++;
                if (!*p) break;
                count++;
                while (*p && !is_delim(*p, delim)) p++;
        }

        // Allocate array (NULL-terminated)
        char** out = (char**)kmalloc((count + 1) * sizeof(char*));
        if (!out) return NULL;
        out[count] = NULL;
        if (n) *n = (int)count;

        // Second pass: copy tokens
        p = str;
        size_t idx = 0;
        while (*p) {
                while (*p && is_delim(*p, delim)) p++;
                if (!*p) break;
                const char* start = p;
                while (*p && !is_delim(*p, delim)) p++;
                size_t len = (size_t)(p - start);
                char* token = (char*)kmalloc(len + 1);
                if (!token) { out[idx] = NULL; return out; }
                for (size_t i = 0; i < len; i++) token[i] = start[i];
                token[len] = '\0';
                out[idx++] = token;
        }
        return out;
}