#ifndef CONSTANTS_H
#define CONSTANTS_H
#include <stdlib.h>

const size_t MAX_KEY_LEN = 1024;
#define PREFIX "key#"
#define SUBCOMMAND_GET_KEY 1
#define SUBCOMMAND_SET_KEY 2
#define SUBCOMMAND_DEL_KEY 3
#define SUBCOMMAND_ENCRYPT_SEAL 4
#define SUBCOMMAND_DECRYPT_UNSEAL 5

#endif // !CONSTANTS_H
