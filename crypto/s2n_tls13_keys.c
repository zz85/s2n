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

#include <stdio.h>

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hmac.h"
#include "crypto/s2n_hkdf.h"
#include "crypto/s2n_tls13_keys.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

#include "utils/s2n_safety.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"

/*
 * There are 9 keys that can be generated by the end of a TLS 1.3 handshake.
 * We currently support the following, more will be supported
 * when the relevant TLS 1.3 features are worked on.
 *
 * [ ] binder_key
 * [ ] client_early_traffic_secret
 * [ ] early_exporter_master_secret
 * [x] client_handshake_traffic_secret
 * [x] server_handshake_traffic_secret
 * [x] client_application_traffic_secret_0
 * [x] server_application_traffic_secret_0
 * [ ] exporter_master_secret
 * [ ] resumption_master_secret
 *
 * The TLS 1.3 key generation can be divided into 3 phases
 * 1. early secrets
 * 2. handshake secrets
 * 3. master secrets
 *
 * In each phase, secrets are first extracted with HKDF-Extract that takes in
 * both an ikm (input keying material) and a salt. Some keys can be derived/expanded
 * from the extract before a "tls13 derived" Derive-Secret is used to
 * derive the input salt for the next phase.
 */

/*
 * Define TLS 1.3 HKDF labels as specified in
 * https://tools.ietf.org/html/rfc8446#section-7.1
 */

S2N_BLOB_LABEL(s2n_tls13_label_derived_secret, "derived")

S2N_BLOB_LABEL(s2n_tls13_label_external_psk_binder_key, "ext binder")
S2N_BLOB_LABEL(s2n_tls13_label_resumption_psk_binder_key, "res binder")

S2N_BLOB_LABEL(s2n_tls13_label_client_early_traffic_secret, "c e traffic")
S2N_BLOB_LABEL(s2n_tls13_label_early_exporter_master_secret, "e exp master")

S2N_BLOB_LABEL(s2n_tls13_label_client_handshake_traffic_secret, "c hs traffic")
S2N_BLOB_LABEL(s2n_tls13_label_server_handshake_traffic_secret, "s hs traffic")

S2N_BLOB_LABEL(s2n_tls13_label_client_application_traffic_secret, "c ap traffic")
S2N_BLOB_LABEL(s2n_tls13_label_server_application_traffic_secret, "s ap traffic")

S2N_BLOB_LABEL(s2n_tls13_label_exporter_master_secret, "exp master")
S2N_BLOB_LABEL(s2n_tls13_label_resumption_master_secret, "res master")

/*
 * Traffic secret labels
 */

S2N_BLOB_LABEL(s2n_tls13_label_traffic_secret_key, "key")
S2N_BLOB_LABEL(s2n_tls13_label_traffic_secret_iv, "iv")

static const struct s2n_blob zero_length_blob = { .data = NULL, .size = 0 };

int s2n_handle_tls13_secrets_update(struct s2n_connection *conn) {
    struct s2n_blob client_shared_secret = { 0 };

    conn->secure.server_ecc_params.negotiated_curve = conn->secure.client_ecc_params[0].negotiated_curve;

    GUARD(s2n_ecc_compute_shared_secret_from_params(
        &conn->secure.client_ecc_params[0],
        &conn->secure.server_ecc_params,
        &client_shared_secret));

    printf("[handshake] === Computed shared secret ===\n");
    print_hex_blob(client_shared_secret);

    // ---------- set up -------------
    struct s2n_tls13_keys secrets = {0};

    printf("HMAC algo %d\n", conn->secure.cipher_suite->tls12_prf_alg);

    s2n_tls13_keys_init(&secrets, 
        conn->secure.cipher_suite->tls12_prf_alg
        // S2N_HMAC_SHA384
        // S2N_HMAC_SHA256
    );

    printf("Secrets size %d\n", secrets.size);

    s2n_tls13_derive_early_secrets(&secrets);

    s2n_stack_blob(client_hs_secret, secrets.size, SHA384_DIGEST_LENGTH);
    s2n_stack_blob(server_hs_secret, secrets.size, SHA384_DIGEST_LENGTH);

    // conn->server->server_implicit_iv
    // conn->server->server_key

    struct s2n_hash_state hash_state = {0};
    GUARD(s2n_handshake_get_hash_state(conn,
        // chosen_hash_alg,
        secrets.hash_algorithm,
        &hash_state));


    s2n_tls13_derive_handshake_secrets(&secrets, &client_shared_secret,
        // &conn->handshake.sha256, // FIXME stub this!
        &hash_state,
        &client_hs_secret, &server_hs_secret);

    printf("%s", KYEL);

    printf("\n");
    printf("[handshake] === client_handshake_traffic_secret ===\n");
    print_hex(client_hs_secret.data, client_hs_secret.size);

    printf("\n");
    printf("[handshake] === server_handshake_traffic_secret ===\n");
    print_hex(server_hs_secret.data, server_hs_secret.size);
    printf("\n");
    printf("%s", KNRM);

    // conn->secure.cipher_suite->record_alg->cipher->key_material_size

    printf("Key Material size: %d\n", conn->secure.cipher_suite->record_alg->cipher->key_material_size);


    s2n_tls13_key_blob(s_hs_key,
        conn->secure.cipher_suite->record_alg->cipher->key_material_size
        // 16
        );

    struct s2n_blob s_hs_iv = {
        .data = conn->server->server_implicit_iv,
        .size = 12
    };

    s2n_blob_init(&s_hs_iv, conn->server->server_implicit_iv, 12);

    GUARD(s2n_tls13_derive_traffic_keys(&secrets, &server_hs_secret, &s_hs_key, &s_hs_iv));
    printf("--- HS IV --\n");
    print_hex(s_hs_iv.data, s_hs_iv.size);

    printf("--- HS key --\n");
    print_hex(s_hs_key.data, s_hs_key.size);

    // conn->server->server_implicit_iv[8] = 99;
    // conn->server->server_implicit_iv[9] = 99;
    // conn->server->server_implicit_iv[10] = 99;
    // conn->server->server_implicit_iv[11] = 99;

    // struct s2n_session_key session_key = { 0 };
    // EXPECT_SUCCESS(s2n_session_key_alloc(&session_key));


    // GUARD(s2n_session_key_alloc(&conn->server->server_key));
    // GUARD(s2n_aead_cipher_aes128_gcm_set_decryption_key(&conn->server->server_key, &s_hs_key));
    PRINT0("Cipher Init\n");
    printf("%d\n", conn->secure.cipher_suite->record_alg->cipher->type);
    GUARD(conn->secure.cipher_suite->record_alg->cipher->init(&conn->server->server_key));
    GUARD(conn->secure.cipher_suite->record_alg->cipher->set_decryption_key(&conn->server->server_key, &s_hs_key));

    return 0;
}

/* Message transcript hash based on selected HMAC algorithm */
static int s2n_tls13_transcript_message_hash(struct s2n_tls13_keys *keys, const struct s2n_blob *message, struct s2n_blob *message_digest)
{
    notnull_check(keys);
    notnull_check(message);
    notnull_check(message_digest);

    struct s2n_hash_state hash_state;
    GUARD(s2n_hash_new(&hash_state));
    GUARD(s2n_hash_init(&hash_state, keys->hash_algorithm));
    GUARD(s2n_hash_update(&hash_state, message->data, message->size));
    GUARD(s2n_hash_digest(&hash_state, message_digest->data, message_digest->size));
    GUARD(s2n_hash_free(&hash_state));

    return 0;
}

/*
 * Initalizes the tls13_keys struct
 */
int s2n_tls13_keys_init(struct s2n_tls13_keys *handshake, s2n_hmac_algorithm alg)
{
    notnull_check(handshake);

    handshake->hmac_algorithm = alg;
    GUARD(s2n_hmac_hash_alg(alg, &handshake->hash_algorithm));
    GUARD(s2n_hash_digest_size(handshake->hash_algorithm, &handshake->size));
    GUARD(s2n_blob_init(&handshake->extract_secret, handshake->extract_secret_bytes, handshake->size));
    GUARD(s2n_blob_init(&handshake->derive_secret, handshake->derive_secret_bytes, handshake->size));
    GUARD(s2n_hmac_new(&handshake->hmac));

    return 0;
}

/*
 * Derives early secrets
 */
int s2n_tls13_derive_early_secrets(struct s2n_tls13_keys *keys)
{
    notnull_check(keys);

    s2n_tls13_key_blob(psk_ikm, keys->size); /* in 1-RTT, PSK is 0-filled of key length */

    /* Early Secret */
    GUARD(s2n_hkdf_extract(&keys->hmac, keys->hmac_algorithm, &zero_length_blob, &psk_ikm, &keys->extract_secret));

    /* binder, client_early_traffic_secret, early_exporter_master_secret can be derived here */

    /* derive next secret */
    s2n_tls13_key_blob(message_digest, keys->size);
    GUARD(s2n_tls13_transcript_message_hash(keys, &zero_length_blob, &message_digest));
    GUARD(s2n_hkdf_expand_label(&keys->hmac, keys->hmac_algorithm, &keys->extract_secret,
        &s2n_tls13_label_derived_secret, &message_digest, &keys->derive_secret));

    return 0;
}

/*
 * Derives handshake secrets
 */
int s2n_tls13_derive_handshake_secrets(struct s2n_tls13_keys *keys,
                                        const struct s2n_blob *ecdhe,
                                        struct s2n_hash_state *client_server_hello_hash,
                                        struct s2n_blob *client_secret,
                                        struct s2n_blob *server_secret)
{
    notnull_check(keys);
    notnull_check(ecdhe);
    notnull_check(client_server_hello_hash);
    notnull_check(client_secret);
    notnull_check(server_secret);

    /* Handshake Secret */
    GUARD(s2n_hkdf_extract(&keys->hmac, keys->hmac_algorithm, &keys->derive_secret, ecdhe, &keys->extract_secret));

    s2n_tls13_key_blob(message_digest, keys->size);

    /* copy the hash */
    struct s2n_hash_state hkdf_hash_copy;
    GUARD(s2n_hash_new(&hkdf_hash_copy));
    GUARD(s2n_hash_copy(&hkdf_hash_copy, client_server_hello_hash));
    s2n_hash_digest(&hkdf_hash_copy, message_digest.data, message_digest.size);
    s2n_hash_free(&hkdf_hash_copy);

    /* produce client + server traffic secrets */
    GUARD(s2n_hkdf_expand_label(&keys->hmac, keys->hmac_algorithm, &keys->extract_secret,
        &s2n_tls13_label_client_handshake_traffic_secret, &message_digest, client_secret));
    GUARD(s2n_hkdf_expand_label(&keys->hmac, keys->hmac_algorithm, &keys->extract_secret,
        &s2n_tls13_label_server_handshake_traffic_secret, &message_digest, server_secret));

    /* derive next secret */
    GUARD(s2n_tls13_transcript_message_hash(keys, &zero_length_blob, &message_digest));
    GUARD(s2n_hkdf_expand_label(&keys->hmac, keys->hmac_algorithm, &keys->extract_secret,
        &s2n_tls13_label_derived_secret, &message_digest, &keys->derive_secret));

    return 0;
}

/*
 * Derives application/master secrets
 */
int s2n_tls13_derive_application_secrets(struct s2n_tls13_keys *keys, struct s2n_hash_state *hashes, struct s2n_blob *client_secret, struct s2n_blob *server_secret)
{
    notnull_check(keys);
    notnull_check(hashes);
    notnull_check(client_secret);
    notnull_check(server_secret);

    s2n_tls13_key_blob(empty_key, keys->size);
    GUARD(s2n_hkdf_extract(&keys->hmac, keys->hmac_algorithm, &keys->derive_secret, &empty_key, &keys->extract_secret));

    s2n_tls13_key_blob(message_digest, keys->size);

    /* copy the hash */
    struct s2n_hash_state hkdf_hash_copy;
    GUARD(s2n_hash_new(&hkdf_hash_copy));
    GUARD(s2n_hash_copy(&hkdf_hash_copy, hashes));
    GUARD(s2n_hash_digest(&hkdf_hash_copy, message_digest.data, message_digest.size));

    GUARD(s2n_hash_free(&hkdf_hash_copy));

    /* produce client + server traffic secrets */
    GUARD(s2n_hkdf_expand_label(&keys->hmac, keys->hmac_algorithm, &keys->extract_secret,
        &s2n_tls13_label_client_application_traffic_secret, &message_digest, client_secret));
    GUARD(s2n_hkdf_expand_label(&keys->hmac, keys->hmac_algorithm, &keys->extract_secret,
        &s2n_tls13_label_server_application_traffic_secret, &message_digest, server_secret));

    /* exporter and resumption master secrets can be derived here */

    return 0;
}

/*
 * Derive Traffic Key and IV based on input secret
 */
int s2n_tls13_derive_traffic_keys(struct s2n_tls13_keys *keys, struct s2n_blob *secret, struct s2n_blob *key, struct s2n_blob *iv)
{
    notnull_check(keys);
    notnull_check(secret);
    notnull_check(key);
    notnull_check(iv);

    GUARD(s2n_hkdf_expand_label(&keys->hmac, keys->hmac_algorithm, secret,
        &s2n_tls13_label_traffic_secret_key, &zero_length_blob, key));
    GUARD(s2n_hkdf_expand_label(&keys->hmac, keys->hmac_algorithm, secret,
        &s2n_tls13_label_traffic_secret_iv, &zero_length_blob, iv));
    return 0;
}
