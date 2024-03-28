#include "commandline.h"
#include "constants.h"
#include "debugmacros.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief usage of the app
 *
 * this function is called when the app is called with wrong parameters
 * it shows how to use the app in the console using Linux style
 */
void usage(const char *prog_name) {
    printf("Usage: %s [SUBCOMMAND] <name> [OPTION] ...\n", prog_name);
    printf("The size of the key is 32 bytes by default and can be changed via "
           "the environment variable KEY_SIZE\n");
    printf("SUBCOMMANDS:\n");
    printf(
        "g, get-key\tget the key from the secure storage by its storage id\n");
    printf("s, set-key\tset the key in the secure storage by its storage id\n");
    printf("d, del-key\tdelete the key from the secure storage by its storage "
           "id\n");
    printf("e, encrypt-seal\tencrypt the key before sealing it with the optee "
           "storage utilities\n");
    printf("ds, decrypt-unseal\tdecrypt the key and unseal it with the optee "
           "storage utilities\n");
    printf("-h, --help\tshow this help message\n");
}

void usage_get_key() {
    printf("Usage: get-key [OPTION] ...\n");
    printf("OPTIONS:\n");
}

void usage_set_key() {
    printf("Usage: set-key [OPTION] ...\n");
    printf("OPTIONS:\n");
    printf("-k\tthe key to set in the secure storage\n");
    printf("-f\tthe file to read the key from\n");
}

void usage_encrypt_seal() {
    printf("Usage: encrypt-seal [OPTION] ...\n");
    printf("TODO...\n");
}

void usage_decrypt_unseal() {
    printf("Usage: decrypt-unseal [OPTION] ...\n");
    printf("TODO...\n");
}

void parse_args(int argc, char *argv[], options_t *options) {
    if (argc < 2) {
        usage(argv[0]);
        exit(1);
    }
    if (strcmp(argv[1], "get-key") == 0 || strcmp(argv[1], "g") == 0) {
        options->subcommand = SUBCOMMAND_GET_KEY;
        // options->name = argv[2];
    } else if (strcmp(argv[1], "set-key") == 0 || strcmp(argv[1], "s") == 0) {
        options->subcommand = SUBCOMMAND_SET_KEY;
        // options->name = argv[2];
        if (argc < 3) {
            usage_set_key();
        } else if (argc == 5) {
            if (strcmp(argv[3], "-f") == 0) {
                options->file = argv[4];
            } else if (strcmp(argv[3], "-k") == 0) {
                // subtract the \0
                options->key_len = strlen(argv[4]);
                if (options->key_len > MAX_KEY_LEN) {
                    ERRO("Warning: key length is to big max is: %d bytes\n",
                         MAX_KEY_LEN);
                    exit(1);
                }
                char *buf = malloc(options->key_len * sizeof(char));
                options->key = buf;
                // this cuts of the \0 bytes but this is ok
                strncpy(options->key, argv[4], options->key_len);
            } else {
                usage_set_key();
            }
        }
    } else if (strcmp(argv[1], "del-key") == 0 || strcmp(argv[1], "d") == 0) {
        options->subcommand = SUBCOMMAND_DEL_KEY;
        // options->name = argv[2];
    } else if (strcmp(argv[1], "encrypt-seal") == 0 ||
               strcmp(argv[1], "e") == 0) {
        options->subcommand = SUBCOMMAND_ENCRYPT_SEAL;
        // options->name = argv[2];
        usage_encrypt_seal();
    } else if (strcmp(argv[1], "decrypt-unseal") == 0 ||
               strcmp(argv[1], "ds") == 0) {
        options->subcommand = SUBCOMMAND_DECRYPT_UNSEAL;
        // options->name = argv[2];
        usage_decrypt_unseal();
    } else {
        usage(argv[0]);
        exit(1);
    }
}
long get_file_size(char *file) {
    FILE *f;
    f = fopen(file, "rb");
    if (f == NULL) {
        printf("Error opening file %s\n", file);
        exit(1);
    }
    if (fseek(f, 0, SEEK_END) < 0) {
        fclose(f);
        ERRO("Failed to get the size of %s", file);
        exit(1);
    }
    // todo: is this save from an integer overflow?
    long size = ftell(f);
    if (size < 0) {
        fclose(f);
        ERRO("Failed to get the size of %s", file);
        exit(1);
    }
    rewind(f);
    fclose(f);
    return size;
}

void read_key_file(options_t *opts) {
    FILE *f;
    f = fopen(opts->file, "rb");
    int res = fread(opts->key, 1, opts->key_len, f);
    if (res != opts->key_len) {
        printf("Error reading file %s is the key as long as you say it is?\n",
               opts->file);
        exit(1);
    }
    int fcres = fclose(f);
    if (fcres != 0) {
        printf("Error closing file %s\n", opts->file);
        exit(1);
    }
}
