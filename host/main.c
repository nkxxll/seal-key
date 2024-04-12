/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "commandline.h"
#include "constants.h"
#include "debugmacros.h"
#include "storage.h"

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TA API: UUID and command IDs */
#include <seal-key_ta.h>

// storage.c
void prepare_tee_session(struct test_ctx *ctx) {
    TEEC_UUID uuid = TA_SEAL_KEY_UUID;
    uint32_t origin;
    TEEC_Result res;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx->ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    /* Open a session with the TA */
    res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid, TEEC_LOGIN_PUBLIC,
                           NULL, NULL, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res,
             origin);
}

void terminate_tee_session(struct test_ctx *ctx) {
    TEEC_CloseSession(&ctx->sess);
    TEEC_FinalizeContext(&ctx->ctx);
}

// todo: this is a function we can use our object here is the key in this case
// of a seal key application
TEEC_Result read_secure_object(struct test_ctx *ctx, char *id, char *data,
                               size_t *data_len) {
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    size_t id_len = strlen(id);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = id_len;

    op.params[1].tmpref.buffer = data;
    op.params[1].tmpref.size = *data_len;

    res =
        TEEC_InvokeCommand(&ctx->sess, TA_SEAL_KEY_CMD_READ_RAW, &op, &origin);
    switch (res) {
    case TEEC_SUCCESS:
        *data_len = op.params[1].tmpref.size;
        break;
    case TEEC_ERROR_SHORT_BUFFER:
        printf("Buffer too short\n");
    case TEEC_ERROR_ITEM_NOT_FOUND:
        printf("Item not found\n");
        break;
    default:
        printf("Command READ_RAW failed: 0x%x / %u\n", res, origin);
    }

    return res;
}

// here we write the key to the optee secure storage
// it gets sealed from the optee and stored securely
// todo: ?do we trust this or do we want to encrypt it before sending it to
// the optee?
TEEC_Result write_secure_object(struct test_ctx *ctx, char *id, char *data,
                                size_t data_len) {
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    size_t id_len = strlen(id);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = id_len;

    op.params[1].tmpref.buffer = data;
    op.params[1].tmpref.size = data_len;

    res =
        TEEC_InvokeCommand(&ctx->sess, TA_SEAL_KEY_CMD_WRITE_RAW, &op, &origin);
    if (res != TEEC_SUCCESS)
        printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);

    switch (res) {
    case TEEC_SUCCESS:
        break;
    default:
        printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);
    }

    return res;
}

TEEC_Result delete_secure_object(struct test_ctx *ctx, char *id) {
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    size_t id_len = strlen(id);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = id_len;

    res = TEEC_InvokeCommand(&ctx->sess, TA_SEAL_KEY_CMD_DELETE, &op, &origin);

    switch (res) {
    case TEEC_SUCCESS:
        break;
    case TEEC_ERROR_ITEM_NOT_FOUND:
        printf("Command DELETE failed: 0x%x / %u\n", res, origin);
        break;
    default:
        printf("Command DELETE failed: 0x%x / %u\n", res, origin);
    }

    return res;
}

// commandline.c
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
    printf("-s\tsize of the key\n");
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

void set_name(char *name, options_t *options) {
    char buf[8];
    snprintf(buf, sizeof(buf), "%s%d", PREFIX, atoi(name));
    strncpy(options->name, buf, sizeof(buf));
}

void parse_get_key(int argc, char *argv[], options_t *options) {
    if (argc < 3) {
        usage_get_key();
        exit(1);
    }
}
void parse_set_key(int argc, char *argv[], options_t *options) {
    if (argc < 3) {
        usage_set_key();
        exit(1);
    } else if (argc == 5) {
        if (strcmp(argv[3], "-f") == 0) {
            options->file = argv[4];

            options->key_len = get_file_size(options->file);
            if (options->key_len < 0) {
                ERRO("Failed to get the size of %s", options->file);
                exit(1);
            }
            if (options->key_len > MAX_KEY_LEN) {
                ERRO("The file contents are too long");
                exit(1);
            }
            // cut the \0
            options->key_len--;
            char *buf;
            buf = malloc(options->key_len * sizeof(char));
            if (buf == NULL) {
                errx(1, "error allocating memory on the heap");
            }
            options->key = buf;
            read_key_file(options);
        } else if (strcmp(argv[3], "-k") == 0) {
            options->key_len = strlen(argv[4]);
            if (options->key_len > MAX_KEY_LEN) {
                ERRO("Warning: key length is to big max is: %zu bytes\n",
                     MAX_KEY_LEN);
                exit(1);
            }
            char *buf = malloc(options->key_len * sizeof(char));
            if (buf == NULL) {
                errx(1, "there was an error allocating memory for the key");
            }
            options->key = buf;
            // this cuts of the \0 bytes but this is ok
            strncpy(options->key, argv[4], options->key_len);
        }
    } else if (argc == 4 && (strcmp(argv[3], "-k") == 0)) {
        // ask for stdin
        printf("Enter the key (the key is cut at %zu):\n", MAX_KEY_LEN);
        char buf[MAX_KEY_LEN];
        // Read at most n bytes
        // again the need to use base64 this was very stupid
        char *res = fgets(buf, MAX_KEY_LEN, stdin);
        size_t len = strlen(buf);
        // ditch the \0 byte
        len--;
        if (res != NULL) {
            printf("Read %zu bytes\n", len);
            options->key_len = len;
            options->key = malloc(options->key_len * sizeof(char));
            if (options->key == NULL) {
                errx(1, "error allocating memory on the heap");
            }
            strncpy(options->key, buf, options->key_len);
        } else {
            printf("Error reading input\n");
        }
    } else {
        usage_set_key();
        exit(1);
    }
}

void parse_args(int argc, char *argv[], options_t *options) {
    if (argc < 2) {
        usage(argv[0]);
        exit(1);
    }
    if (strcmp(argv[1], "get-key") == 0 || strcmp(argv[1], "g") == 0) {
        options->subcommand = SUBCOMMAND_GET_KEY;
        set_name(argv[2], options);
        parse_get_key(argc, argv, options);
    } else if (strcmp(argv[1], "set-key") == 0 || strcmp(argv[1], "s") == 0) {
        options->subcommand = SUBCOMMAND_SET_KEY;
        set_name(argv[2], options);
        parse_set_key(argc, argv, options);
    } else if (strcmp(argv[1], "del-key") == 0 || strcmp(argv[1], "d") == 0) {
        options->subcommand = SUBCOMMAND_DEL_KEY;
        set_name(argv[2], options);
    } else if (strcmp(argv[1], "encrypt-seal") == 0 ||
               strcmp(argv[1], "e") == 0) {
        options->subcommand = SUBCOMMAND_ENCRYPT_SEAL;
        set_name(argv[2], options);
        usage_encrypt_seal();
    } else if (strcmp(argv[1], "decrypt-unseal") == 0 ||
               strcmp(argv[1], "ds") == 0) {
        options->subcommand = SUBCOMMAND_DECRYPT_UNSEAL;
        set_name(argv[2], options);
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

int check_name(char *name) {
    if (strlen(name) > sizeof(name)) {
        ERRO("The name is too long");
        return 1;
    }
    for (int i = 0; i < strlen(name); i++) {
        if (name[i] < '0' || name[i] > '9') {
            ERRO("The name contains invalid characters");
            return 1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    struct test_ctx ctx;
    struct options o;
    char buf[8];
    o.subcommand = 0;
    o.name = buf;
    o.key = NULL;
    o.file = NULL;
    o.key_len = 0;

    parse_args(argc, argv, &o);

    TEEC_Result res = TEEC_SUCCESS;
    prepare_tee_session(&ctx);

    DEBG("len: %zu", o.key_len);

    char key_data[o.key_len];
    // save printing of the key
    char read_data[MAX_KEY_LEN];
    size_t read_data_len = MAX_KEY_LEN;
    // test this after
    switch (o.subcommand) {
    case SUBCOMMAND_SET_KEY:
        INFO("Set key from the secure storage\n");
        // the input should be base64 encoded
        if (o.name == NULL) {
            errx(1, "No key name provided");
        }
        INFO("- Create and load key in the TA secure storage\n");

        strncpy(key_data, o.key, o.key_len);
        DEBG("key before write %s len: %zu", key_data, o.key_len);
        res = write_secure_object(&ctx, o.name, key_data, sizeof(key_data));
        if (res != TEEC_SUCCESS) {
            errx(1, "Failed to create an object in the secure storage");
            goto cleanup;
        }
        res = read_secure_object(&ctx, o.name, read_data, &read_data_len);
        if (res != TEEC_SUCCESS)
            errx(1, "Failed to read an object from the secure storage");
        break;
    case SUBCOMMAND_GET_KEY:
        INFO("Get key from the secure storage\n");
        if (o.name == NULL) {
            errx(1, "No key name provided");
        }
        DEBG("Read back the object - len, %zu\n", o.key_len);

        res = read_secure_object(&ctx, o.name, read_data, &read_data_len);
        if (res != TEEC_SUCCESS)
            errx(1, "Failed to read an object from the secure storage");

        break;
    case SUBCOMMAND_DEL_KEY:
        INFO("Delete key from the secure storage\n");
        if (o.name == NULL) {
            errx(1, "No key name provided");
        }
        INFO("- Delete the key\n");
        res = delete_secure_object(&ctx, o.name);
        if (res != TEEC_SUCCESS)
            errx(1, "Failed to delete the object: 0x%x", res);

        break;
    default:
        WARN("Subcommand not implemented!\n");
        exit(1);
        goto cleanup;
        break;
    }

    if (o.subcommand == SUBCOMMAND_SET_KEY) {
        char read_buf[read_data_len + 1];
        read_buf[read_data_len] = '\0';
        memcpy(read_buf, read_data, read_data_len);
        // this should be base64
        DEBG("test read :: key after read: %s", read_buf);
    }
    if (o.subcommand == SUBCOMMAND_GET_KEY) {
        char read_buf[read_data_len + 1];
        read_buf[read_data_len] = '\0';
        memcpy(read_buf, read_data, read_data_len);
        // this should be base64
        DEBG("key after read: %s", read_buf);
        printf("%s\n", read_buf);
    }

cleanup:
    INFO("\nWe're done, close and release TEE resources\n");
    terminate_tee_session(&ctx);
    return 0;
}
