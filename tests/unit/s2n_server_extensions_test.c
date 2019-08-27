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
#include "tls/extensions/s2n_server_key_share.h"

#include "utils/s2n_safety.h"

const uint8_t EXTENSION_LEN = 2;

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_server_extensions_send */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

        uint32_t last_write_cursor;
        RECORD_WRITE_CURSOR(hello_stuffer, last_write_cursor);

        /* Test Server Extensions Send - No extensions */
        {
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));

            EXPECT_STUFFER_BYTES_WRITTEN(hello_stuffer, 0, last_write_cursor);
        }

        /* Test Server Extensions Send - Server Name */
        {
            conn->server_name_used = 1;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));

            EXPECT_STUFFER_BYTES_WRITTEN(hello_stuffer, 4 + EXTENSION_LEN, last_write_cursor);

            conn->server_name_used = 0;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            EXPECT_STUFFER_BYTES_WRITTEN(hello_stuffer, 0, last_write_cursor);
        }

        /* Test Server Extensions Send - Application Protocol */
        {
            strcpy(conn->application_protocol, "h2");
            const uint8_t application_protocol_len = strlen(conn->application_protocol);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));

            const uint8_t ALPN_LEN = 7 + application_protocol_len;
            EXPECT_STUFFER_BYTES_WRITTEN(hello_stuffer, ALPN_LEN + EXTENSION_LEN, last_write_cursor);

            strcpy(conn->application_protocol, "");
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            EXPECT_STUFFER_BYTES_WRITTEN(hello_stuffer, 0, last_write_cursor);
        }

        /* Test Server Extensions Send - Secure Negotiation */
        {
            conn->secure_renegotiation = 1;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            const uint8_t SECURE_RENEGOTIATION_SIZE = 5;
            EXPECT_STUFFER_BYTES_WRITTEN(hello_stuffer, SECURE_RENEGOTIATION_SIZE + EXTENSION_LEN, last_write_cursor);

            conn->secure_renegotiation = 0;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            EXPECT_STUFFER_BYTES_WRITTEN(hello_stuffer, 0, last_write_cursor);
        }

        /* Test TLS13 Extensions */
        {
            conn->secure.server_ecc_params.negotiated_curve = &s2n_ecc_supported_curves[0];

            conn->actual_protocol_version = S2N_TLS13;

            uint8_t size = s2n_extensions_server_key_share_send_size(conn);
            s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            EXPECT_STUFFER_BYTES_WRITTEN(hello_stuffer, size + EXTENSION_LEN, last_write_cursor);

            conn->actual_protocol_version = S2N_TLS12;

            s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            EXPECT_STUFFER_BYTES_WRITTEN(hello_stuffer, 0, last_write_cursor);
        }

        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
    return 0;
}
