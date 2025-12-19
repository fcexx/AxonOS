#ifndef AXONOS_AXOSH_H
#define AXONOS_AXOSH_H

#ifdef __cplusplus
extern "C" {
#endif

#define OSH_NAME "osh"
#define OSH_VERSION "0.2"
#define OSH_FULL_NAME "axonsh"

// Запуск командного интерпретатора osh (bash-подобный)
void osh_run(void);

// Получить текущий рабочий каталог shell в out
void osh_get_cwd(char* out, unsigned long outlen);

// Разрешить относительный путь относительно base в out
void osh_resolve_path(const char* base, const char* arg, char* out, unsigned long outlen);

// Экспорт списка builtin-команд для подсказок
int osh_get_builtin_names(const char*** out_names);

/* Execute a single shell line (used by kernelcore at boot to run /start). */
int exec_line(const char *line);

#ifdef __cplusplus
}
#endif

#endif /* AXONOS_AXOSH_H */
