/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Infineon Technologies AG
 * All rights reserved.
 */

#include <stdbool.h>
#include <stdio.h>
#include <tss2/tss2_tcti_tbs.h>

#include "src/util/tss2_endian.h"

#if !defined(__FILE_NAME__)
#define __FILE_NAME__ "tpm2_send_tbs.c"
#endif

#define LOG_ERR(m,...) fprintf(stderr, "ERROR:%s:%i:%s: " m "\n", __FILE_NAME__, __LINE__, __func__, ## __VA_ARGS__)

#define LOG_DBG(m,...) if (verbose) fprintf(stderr, "debug:%s:%i:%s: " m "\n", __FILE_NAME__, __LINE__, __func__, ## __VA_ARGS__)
#define DBG(x) if (verbose) {x}

#define check_rc(x,y) if (x != TSS2_RC_SUCCESS) { \
            LOG_ERR("Error"); \
            y; \
        }

#define TPM2_HEADER_SIZE 10

bool verbose = false;

FILE* input;
FILE* output;

void get_opts(int argc, char** argv) {
    bool inputset = false;
    bool outputset = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "/?") || !strcmp(argv[i], "/h") || !strcmp(argv[i], "/help") || !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("Usage %s [<inputfile> <outputfile>]", argv[0]);
            exit(0);
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
            verbose = true;
            continue;
        } else if (!inputset) {
            input = fopen(argv[i], "r");
            inputset = true;
            if (!input) {
                LOG_ERR("Cannot open input file: %s", strerror(errno));
                exit(1);
            }
            continue;
        } else if (!outputset) {
            output = fopen(argv[i], "wc");
            outputset = true;
            if (!input) {
                LOG_ERR("Cannot open output file: %s", strerror(errno));
                exit(1);
            }
            continue;
        }
        else {
            fprintf(stderr, "Usage %s [<inputfile> <outputfile>]", argv[0]);
            exit(1);
        }
    }
}

int main(int argc, char **argv)
{
    size_t ctx_size;
    TSS2_TCTI_CONTEXT* ctx;
    TSS2_RC rc;

    uint8_t buffer[TPM2_MAX_COMMAND_SIZE];
    size_t buffer_size = sizeof(buffer);
    size_t buffer_offset = 0;

    uint32_t size_from_header;
    size_t body_size;

    input = stdin;
    output = stdout;

    get_opts(argc, argv);

    rc = Tss2_Tcti_Tbs_Init(NULL, &ctx_size, NULL);
    check_rc(rc, return 1);
    ctx = malloc(ctx_size);
    if (!ctx) {
        LOG_ERR("OOM");
        return 1;
    }
    rc = Tss2_Tcti_Tbs_Init(ctx, &ctx_size, NULL);
    check_rc(rc, return 1);

    while (1) {
        LOG_DBG("Attempting to read 10 bytes of input header.");
        fread(&buffer[0], TPM2_HEADER_SIZE, 1, input);
        if ((ferror(input) && errno != EINTR)) {
            LOG_ERR("Failed to read command header of 10 bytes: %s", strerror(errno));
            return -1;
        }
        if (feof(input) || ferror(input)) {
            LOG_DBG("End of input reached");
            rc = 0; goto out;
        }
        buffer_size = TPM2_HEADER_SIZE;

        LOG_DBG("Received CommandHeader: 0x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
            buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5],
            buffer[6], buffer[7], buffer[8], buffer[9]);

        memcpy(&size_from_header, &buffer[2], sizeof(size_from_header));
        size_from_header = BE_TO_HOST_32(size_from_header);

        if (sizeof(buffer) <= size_from_header) {
            LOG_ERR("Input command size too long: %i", size_from_header);
            rc = 1; goto out;
        }

        body_size = size_from_header - buffer_size;

        LOG_DBG("Attempting to read %zi bytes of input command body", body_size);
        fread(&buffer[buffer_size], body_size, 1, input);
        if (ferror(input)) {
            LOG_ERR("Failed to read command body of %zi bytes: %s", body_size, strerror(errno));
            rc = 1; goto out;
        }
        if (feof(input)) {
            LOG_ERR("Failed to read command body of %zi bytes: EOF reached.", body_size);
            rc = 1; goto out;
        }
        buffer_size += body_size;

        if (size_from_header != buffer_size) {
            LOG_ERR("Command_size does not match header_size: %zi vs %i", buffer_size, size_from_header);
            rc = 1; goto out;
        }

        DBG(
            fprintf(stderr, "Sending Command: ");
            for (size_t i = 0; i < buffer_size; i++) {
                fprintf(stderr, "%02x", buffer[i]);
            }
            fprintf(stderr, "\n");
        )

        rc = Tss2_Tcti_Transmit(ctx, buffer_size, &buffer[0]);
        check_rc(rc, goto out);

        LOG_DBG("Command trasmitted, awaiting response.");

        buffer_size = sizeof(buffer);
        rc = Tss2_Tcti_Receive(ctx, &buffer_size, &buffer[0], TSS2_TCTI_TIMEOUT_BLOCK);
        check_rc(rc, goto out);

        if (buffer_size < 10) {
            LOG_ERR("Response buffer too short: %zi", buffer_size);
            rc = 1; goto out;
        }

        LOG_DBG("Received %zi bytes of total response.", buffer_size);

        LOG_DBG("Received CommandHeader: 0x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
            buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5],
            buffer[6], buffer[7], buffer[8], buffer[9]);

        DBG(
            fprintf(stderr, "Received Response: ");
            for (size_t i = 0; i < buffer_size; i++) {
                fprintf(stderr, "%02x", buffer[i]);
            }
            fprintf(stderr, "\n");
        )


        memcpy(&size_from_header, &buffer[2], sizeof(size_from_header));
        size_from_header = BE_TO_HOST_32(size_from_header);

        if (size_from_header != buffer_size) {
            LOG_ERR("Response_size does not match header_size: %zi vs %i", buffer_size, size_from_header);
            rc = 1; goto out;
        }

        fwrite(&buffer[0], 1, buffer_size, output);
        if (ferror(output) && errno != EINTR) {
            LOG_ERR("Failed to write response: %s", strerror(errno));
            return -1;
        }
        fflush(output);
    }

out:
    Tss2_Tcti_Finalize(ctx);

    if (input != stdin) {
        fclose(input);
    }
    if (output != stdout) {
        fclose(output);
    }

    return (rc != TSS2_RC_SUCCESS);
}