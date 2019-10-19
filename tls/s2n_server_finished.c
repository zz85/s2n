/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdint.h>

#include "error/s2n_errno.h"


#include "tls/s2n_connection.h"
#include "tls/s2n_resume.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

#include "crypto/s2n_tls13_keys.h"

int s2n_tls13_server_finished_recv(struct s2n_connection *conn) {
    PRINT0("TLS 13 server finish\n");

    /* conn->handshake.server_finished differs from the way we do it in tls 1.2 where
    conn->handshake.server_finished keeps the finish key secret (not the expected value).

    we then run HMAC with the server finish as a key with the transcribe hash, then verify 
    the results */

    // verify it is expected hash size!
    // This is the server finish!

    struct s2n_tls13_keys keys = {0};

    s2n_tls13_keys_init(&keys, conn->secure.cipher_suite->tls12_prf_alg);

    server_finish_verify(conn, &keys);

    PRINT0("Wire Verify\n");
    // debug_stuffer(&conn->handshake.io);

    uint8_t length = s2n_stuffer_data_available(&conn->handshake.io);
    struct s2n_blob wire_server_finished_verify = {
        .data = s2n_stuffer_raw_read(&conn->handshake.io, length),
        .size = length
    };

    print_hex_blob(wire_server_finished_verify);

    return 0;
}

int s2n_server_finished_recv(struct s2n_connection *conn)
{
    if (conn->actual_protocol_version == S2N_TLS13) {
        return s2n_tls13_server_finished_recv(conn);
    }

    uint8_t *our_version;
    int length = S2N_TLS_FINISHED_LEN;
    our_version = conn->handshake.server_finished;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        length = S2N_SSL_FINISHED_LEN;
    }

    uint8_t *their_version = s2n_stuffer_raw_read(&conn->handshake.io, length);
    notnull_check(their_version);

    S2N_ERROR_IF(!s2n_constant_time_equals(our_version, their_version, length), S2N_ERR_BAD_MESSAGE);

    return 0;
}

int s2n_server_finished_send(struct s2n_connection *conn)
{
    uint8_t *our_version;
    int length = S2N_TLS_FINISHED_LEN;

    /* Compute the finished message */
    GUARD(s2n_prf_server_finished(conn));

    our_version = conn->handshake.server_finished;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        length = S2N_SSL_FINISHED_LEN;
    }

    GUARD(s2n_stuffer_write_bytes(&conn->handshake.io, our_version, length));

    /* Zero the sequence number */
    struct s2n_blob seq = {.data = conn->secure.server_sequence_number,.size = S2N_TLS_SEQUENCE_NUM_LEN };
    GUARD(s2n_blob_zero(&seq));

    /* Update the secure state to active, and point the client at the active state */
    conn->server = &conn->secure;

    if (IS_RESUMPTION_HANDSHAKE(conn->handshake.handshake_type)) {
        GUARD(s2n_prf_key_expansion(conn));
    }

    return 0;
}
