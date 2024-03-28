#ifndef STORAGE_H
#define STORAGE_H

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <tee_client_api.h>

/* TEE resources */
struct test_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx);
void terminate_tee_session(struct test_ctx *ctx);
TEEC_Result read_secure_object(struct test_ctx *ctx, char *id, char *data,
                               size_t data_len);
TEEC_Result write_secure_object(struct test_ctx *ctx, char *id, char *data,
                                size_t data_len);
TEEC_Result delete_secure_object(struct test_ctx *ctx, char *id);

#endif // !STORAGE_H
