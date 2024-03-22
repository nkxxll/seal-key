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

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TA API: UUID and command IDs */
#include <seal-key_ta.h>

#define DEFAULT_KEY_SIZE 32
#define INFO(fmt, ...)                                                         \
    printf("[+] %s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define WARN(fmt, ...)                                                         \
    printf("[!] %s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define DEBG(fmt, ...)                                                         \
    printf("[*] %s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define ERRO(fmt, ...)                                                         \
    printf("[[-!-]] %s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#define SUBCOMMAND_GET_KEY 1
#define SUBCOMMAND_SET_KEY 2
#define SUBCOMMAND_DEL_KEY 3
#define SUBCOMMAND_ENCRYPT_SEAL 4
#define SUBCOMMAND_DECRYPT_UNSEAL 5

/* TEE resources */
struct test_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
};

typedef struct options {
    int subcommand;
    char *name;
    char *key;
    char *file;
    size_t key_len;
} options_t;
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
                // only copy key len to the key and warn if the key is shorter
                // or longer
                if (strlen(argv[4]) != options->key_len) {
                    printf("Warning: key length is not %zd bytes\n",
                           options->key_len);
                }
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

void read_key_file(char *file, char *key, size_t key_len) {
    FILE *f;
    f = fopen(file, "r");
    if (f == NULL) {
        printf("Error opening file %s\n", file);
        exit(1);
    }
    int res = fread(key, 1, key_len, f);
    if (res != key_len) {
        printf("Error reading file %s is the key as long as you say it is?\n",
               file);
        exit(1);
    }
    int fcres = fclose(f);
    if (fcres != 0) {
        printf("Error closing file %s\n", file);
        exit(1);
    }
}

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
                               size_t data_len) {
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
    op.params[1].tmpref.size = data_len;

    res =
        TEEC_InvokeCommand(&ctx->sess, TA_SEAL_KEY_CMD_READ_RAW, &op, &origin);
    switch (res) {
    case TEEC_SUCCESS:
    case TEEC_ERROR_SHORT_BUFFER:
    case TEEC_ERROR_ITEM_NOT_FOUND:
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
    case TEEC_ERROR_ITEM_NOT_FOUND:
        break;
    default:
        printf("Command DELETE failed: 0x%x / %u\n", res, origin);
    }

    return res;
}

int main(int argc, char *argv[]) {
    // char *keysize_str = getenv("SK_KEY_SIZE");
    int key_len = DEFAULT_KEY_SIZE;
    // if (keysize_str == NULL) {
    //     key_len = DEFAULT_KEY_SIZE;
    // } else {
    //     key_len = atoi(keysize_str);
    // }
    char key_data[key_len];
    struct test_ctx ctx;
    struct options o;
    o.subcommand = 0;
    o.name = "key#1";
    o.key = key_data;
    o.file = NULL;
    o.key_len = key_len;

    parse_args(argc, argv, &o);

    TEEC_Result res;

    DEBG("key: %s, file %s", o.key, o.file);

    // test this after
    switch (o.subcommand) {
    case SUBCOMMAND_SET_KEY:
        INFO("Set key from the secure storage\n");
        if (o.name == NULL) {
            errx(1, "No key name provided");
        }
        if (o.file != NULL) {
            read_key_file(o.file, o.key, key_len);
        }
        break;
    default:
        WARN("Subcommand not implemented!\n");
        break;
    }

    INFO("Prepare session with the TA\n");
    prepare_tee_session(&ctx);

    INFO("- Create and load key in the TA secure storage\n");

    // INFO("this still only 0xA1 here update that\n");
    // memset(key_data, 0xA1, sizeof(key_data));

    res = write_secure_object(&ctx, o.name, o.key, sizeof(key_data));
    if (res != TEEC_SUCCESS)
        errx(1, "Failed to create an object in the secure storage");

    INFO("- Read back the object\n");

    char read_data[key_len];
    res = read_secure_object(&ctx, o.name, read_data, sizeof(read_data));
    if (res != TEEC_SUCCESS)
        errx(1, "Failed to read an object from the secure storage");
    if (memcmp(key_data, read_data, sizeof(key_data)))
        errx(1, "Unexpected content found in secure storage");

    // still for testing i think
    INFO("- Delete the key after reading it\n");
    res = delete_secure_object(&ctx, o.name);
    if (res != TEEC_SUCCESS)
        errx(1, "Failed to delete the object: 0x%x", res);

    INFO("\nWe're done, close and release TEE resources\n");
    terminate_tee_session(&ctx);
    return 0;
}
