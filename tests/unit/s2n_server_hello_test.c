/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <s2n.h>

#include "tls/s2n_tls.h"

#include "utils/s2n_safety.h"

const uint8_t EXTENSION_LEN = 2;

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test basic Server Hello Send */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
        uint32_t last_write_cursor;
        RECORD_WRITE_CURSOR(hello_stuffer, last_write_cursor);

        /* Test s2n_server_hello_send */
        {
            const uint32_t total = S2N_TLS_PROTOCOL_VERSION_LEN
                + S2N_TLS_RANDOM_DATA_LEN
                + 1 // session_id
                + conn->session_id_len
                + S2N_TLS_CIPHER_SUITE_LEN
                + 1; // compression method

            EXPECT_SUCCESS(s2n_server_hello_send(conn));
            EXPECT_STUFFER_BYTES_WRITTEN(hello_stuffer, total, last_write_cursor);
        }

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test basic Server Hello Recv */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
        uint32_t last_write_cursor;
        RECORD_WRITE_CURSOR(hello_stuffer, last_write_cursor);

        /* Test s2n_server_hello_send */
        {
            const uint32_t total = S2N_TLS_PROTOCOL_VERSION_LEN
                + S2N_TLS_RANDOM_DATA_LEN
                + 1 // session_id
                + conn->session_id_len
                + S2N_TLS_CIPHER_SUITE_LEN
                + 1; // compression method

            EXPECT_SUCCESS(s2n_server_hello_send(conn));
            EXPECT_STUFFER_BYTES_WRITTEN(hello_stuffer, total, last_write_cursor);
        }

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }
    END_TEST();
    return 0;
}

