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

/* TEE resources */
struct test_ctx {
  TEEC_Context ctx;
  TEEC_Session sess;
};

/**
 * @brief usage of the app
 *
 * this function is called when the app is called with wrong parameters
 * it shows how to use the app in the console using Linux style
 */
void usage(const char *prog_name) {
  printf("Usage: %s [OPTION]... [KEY|KEY_FILE] [SIZE]\n", prog_name);
  printf("Concatenate KEY(s) to standard output.\n");
  printf("If no KEY is given, or if KEY is '-', read standard input.\n\n");
  printf("Flags:\n");
  printf("\t-h, --help\tDisplay this help message and exit\n");
  printf("\t-f, --file <file>\tUse the key from the file\n");
  printf("\t-k, --key <key>\tUse the key from the command line directly\n");
  printf("SIZE\tSize of key in bytes (optional)\n");
}

void parse_args(int argc, char *argv[], int *size, int *file, int *key) {
  // max 3 args name, option, key/file
  if (argc > 4) {
    usage(argv);
    exit(1);
  }
  if (argc == 2 &&
      (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
    usage(argv);
    exit(0);
  } else if (argc == 2 &&
             (strcmp(argv[1], "--key") == 0 || strcmp(argv[1], "-k") == 0)) {
    *key = 1;
    return;
  }
  if (argc >= 3) {
    if (strcmp(argv[1], "--file") == 0 || strcmp(argv[1], "-f") == 0) {
      *file = 1;
      if (argc == 4) {
        *size = atoi(argv[3]);
      }
      return;
    } else if (strcmp(argv[1], "--key") == 0 || strcmp(argv[1], "-k") == 0) {
      *key = 1;
      if (argc == 4) {
        *size = atoi(argv[3]);
      }
      return;
    } else if (strcmp(argv[1], "--size") == 0 || strcmp(argv[1], "-s") == 0) {
      *size = 1;
      if (argc == 4) {
        *size = atoi(argv[3]);
      }
      return;
    }
  }
  usage(argv[0]);
  exit(1);
}

void read_key_file(char *file, char *key, size_t key_len) {
  FILE *f;
  f = fopen(file, "r");
  if (f == NULL) {
    printf("Error opening file %s\n", file);
    exit(1);
  }
  char *res = fgets(key, key_len, f);
  if (res == NULL) {
    printf("Error reading file %s\n", file);
    exit(1);
  }
  int fcres = fclose(f);
  if (fcres != 0) {
    printf("Error closing file %s\n", file);
    exit(1);
  }
}

void read_key(int argc, char *argv[], char *key, size_t key_len) {
  if (argc == 2) {
    printf("Enter the key: ");
    char *res = fgets(key, key_len, stdin);
    if (res == NULL) {
      puts("Error reading file stdin\n");
      exit(1);
    }
  }
  // else it is parsed via the command line in the 3 position
  char *res = strncpy(key, argv[2], key_len);
  if (res == NULL) {
    puts("Error copying file contents\n");
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
  res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
                         NULL, &origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, origin);
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

  res = TEEC_InvokeCommand(&ctx->sess, TA_SEAL_KEY_CMD_READ_RAW, &op, &origin);
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
// todo: ?do we trust this or do we want to encrypt it before sending it to the
// optee?
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

  res = TEEC_InvokeCommand(&ctx->sess, TA_SEAL_KEY_CMD_WRITE_RAW, &op, &origin);
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
  op.paramTypes =
      TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

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
  size_t key_len = DEFAULT_KEY_SIZE;
  struct test_ctx ctx;
  // todo: do we want to be able to add an identifier to the key?
  int bool_key = 0;
  int bool_file = 0;
  char key[] = "key#1"; /* string identification for the object */

  parse_args(argc, argv, &key_len, &bool_file, &bool_key);

  char key_data[key_len];
  char read_data[key_len];
  TEEC_Result res;

  DEBG("key: %d, file %d", bool_key, bool_file);

  // test this after
  if (bool_key == 1) {
    read_key(argc, argv, key_data, sizeof(key_data));
    DEBG("%s", key_data);
  } else if (bool_file == 1) {
    read_key_file(argv[2], key_data, sizeof(key_data));
    DEBG("%s", key_data);
  } else {
    // that is a safety net haha ;D
    usage(argv);
    exit(1);
  }

  INFO("Prepare session with the TA\n");
  prepare_tee_session(&ctx);

  INFO("- Create and load key in the TA secure storage\n");

  // INFO("this still only 0xA1 here update that\n");
  // memset(key_data, 0xA1, sizeof(key_data));

  res = write_secure_object(&ctx, key, key_data, sizeof(key_data));
  if (res != TEEC_SUCCESS)
    errx(1, "Failed to create an object in the secure storage");

  INFO("- Read back the object\n");

  res = read_secure_object(&ctx, key, read_data, sizeof(read_data));
  if (res != TEEC_SUCCESS)
    errx(1, "Failed to read an object from the secure storage");
  if (memcmp(key_data, read_data, sizeof(key_data)))
    errx(1, "Unexpected content found in secure storage");

  // still for testing i think
  INFO("- Delete the key after reading it\n");
  res = delete_secure_object(&ctx, key);
  if (res != TEEC_SUCCESS)
    errx(1, "Failed to delete the object: 0x%x", res);

  INFO("\nWe're done, close and release TEE resources\n");
  terminate_tee_session(&ctx);
  return 0;
}
