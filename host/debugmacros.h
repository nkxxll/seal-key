#ifndef DEBUG_MACROS_H
#define DEBUG_MACROS_H

#define INFO(fmt, ...)                                                         \
    printf("[+] %s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define WARN(fmt, ...)                                                         \
    printf("[!] %s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define DEBG(fmt, ...)                                                         \
    printf("[*] %s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define ERRO(fmt, ...)                                                         \
    printf("[[-!-]] %s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#endif // !DEBUG_MACROS_H
