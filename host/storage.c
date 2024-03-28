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
