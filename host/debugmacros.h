#ifndef DEBUG_MACROS_H
#define DEBUG_MACROS_H

#define INFO(fmt, ...)                                                         \
    fprintf(stderr, "[+] %s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define WARN(fmt, ...)                                                         \
    fprintf(stderr, "[!] %s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define DEBG(fmt, ...)                                                         \
    fprintf(stderr, "[*] %s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define ERRO(fmt, ...)                                                         \
    fprintf(stderr, "[[-!-]] %s:%d " fmt "\n", __func__, __LINE__,             \
            ##__VA_ARGS__)

#endif // !DEBUG_MACROS_H
