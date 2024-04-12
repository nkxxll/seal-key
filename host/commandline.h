#ifndef COMMANDLINE_H
#define COMMANDLINE_H

#include <err.h>
#include <fcntl.h>
#include <stdlib.h>

typedef struct options {
    int subcommand;
    char *name;
    char *key;
    char *file;
    size_t key_len;
} options_t;

void usage(const char *prog_name);
void usage_get_key();
void usage_encrypt_seal();
void usage_decrypt_unseal();
void parse_args(int argc, char *argv[], options_t *options);
long get_file_size(char *file);
void read_key_file(options_t *opts);
void parse_get_key(int argc, char *argv[], options_t *options);
void parse_set_key(int argc, char *argv[], options_t *options);

#endif // !COMMANDLINE_H
