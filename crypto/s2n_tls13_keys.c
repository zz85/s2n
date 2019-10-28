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

S2N_BLOB_LABEL(s2n_tls13_label_finished, "finished")

static const struct s2n_blob zero_length_blob = { .data = NULL, .size = 0 };

/* Generate a key that will be use to compute finish hashes */
int s2n_tls13_derive_finish_key(struct s2n_tls13_keys *keys, struct s2n_blob *secret_key, struct s2n_blob *output_finish_key) 
{
    GUARD(s2n_hkdf_expand_label(&keys->hmac, keys->hmac_algorithm, secret_key, &s2n_tls13_label_finished, &zero_length_blob, output_finish_key));
    return 0;
}

int s2n_handle_tls13_secrets_update(struct s2n_connection *conn) {
    struct s2n_blob shared_secret = { 0 };

    conn->secure.server_ecc_params.negotiated_curve = conn->secure.client_ecc_params[0].negotiated_curve;

    GUARD(s2n_ecc_compute_shared_secret_from_params(
        &conn->secure.client_ecc_params[0],
        &conn->secure.server_ecc_params,
        &shared_secret));

    printf("[handshake] === Computed shared secret ===\n");
    print_hex_blob(shared_secret);

    // ---------- set up -------------
    struct s2n_tls13_keys secrets = {0};

    printf("HMAC algo %d\n", conn->secure.cipher_suite->tls12_prf_alg);

    // either S2N_HMAC_SHA384 or S2N_HMAC_SHA256
    s2n_tls13_keys_init(&secrets, conn->secure.cipher_suite->tls12_prf_alg);

    printf("Secrets size %d\n", secrets.size);

    s2n_tls13_derive_early_secrets(&secrets);

    s2n_stack_blob(client_hs_secret, secrets.size, S2N_TLS13_SECRET_MAX_LEN);
    s2n_stack_blob(server_hs_secret, secrets.size, S2N_TLS13_SECRET_MAX_LEN);

    // chosen_hash_alg,
    struct s2n_hash_state hash_state = {0};
    GUARD(s2n_handshake_get_hash_state(conn, secrets.hash_algorithm, &hash_state));
    GUARD(s2n_tls13_derive_handshake_secrets(&secrets, &shared_secret, &hash_state, &client_hs_secret, &server_hs_secret));

    printf("%s", KYEL);

    printf("\n");
    printf("[handshake] === client_handshake_traffic_secret ===\n");
    print_hex(client_hs_secret.data, client_hs_secret.size);

    printf("\n");
    printf("[handshake] === server_handshake_traffic_secret ===\n");
    print_hex(server_hs_secret.data, server_hs_secret.size);
    printf("\n");
    printf("%s", KNRM);

    printf("Key Material size: %d\n", conn->secure.cipher_suite->record_alg->cipher->key_material_size);

    /* Server handshake secrets */

    s2n_tls13_key_blob(s_hs_key, conn->secure.cipher_suite->record_alg->cipher->key_material_size);
    struct s2n_blob s_hs_iv = { .data = conn->secure.server_implicit_iv, .size = S2N_TLS13_FIXED_IV_LEN };
    GUARD(s2n_tls13_derive_traffic_keys(&secrets, &server_hs_secret, &s_hs_key, &s_hs_iv));

    printf("--- Server HS IV --\n");
    print_hex(s_hs_iv.data, s_hs_iv.size);

    printf("--- Server HS key --\n");
    print_hex(s_hs_key.data, s_hs_key.size);

    /* Client handshake secrets */

    s2n_tls13_key_blob(c_hs_key, conn->secure.cipher_suite->record_alg->cipher->key_material_size);
    struct s2n_blob c_hs_iv = { .data = conn->secure.client_implicit_iv, .size = S2N_TLS13_FIXED_IV_LEN };
    GUARD(s2n_tls13_derive_traffic_keys(&secrets, &client_hs_secret, &c_hs_key, &c_hs_iv));

    printf("--- Client HS IV --\n");
    print_hex(c_hs_iv.data, c_hs_iv.size);

    printf("--- Client HS key --\n");
    print_hex(c_hs_key.data, c_hs_key.size);


    PRINT0("Cipher Init\n");
    printf("%d\n", conn->secure.cipher_suite->record_alg->cipher->type);
    GUARD(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.server_key));
    GUARD(conn->secure.cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure.server_key, &s_hs_key));
    // GUARD(conn->secure.cipher_suite->record_alg->cipher->init(&conn->client->client_key));
    GUARD(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.client_key));
    GUARD(conn->secure.cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure.client_key, &c_hs_key));

    // PRINT0("server_hs_secret");
    // print_hex_blob(server_hs_secret);


    // calculate server + client finish keys and store them in handshake struct
    struct s2n_blob server_finished_key = { .data = conn->handshake.server_finished, .size = secrets.size };
    s2n_tls13_derive_finish_key(&secrets, &server_hs_secret, &server_finished_key);

    struct s2n_blob client_finished_key = { .data = conn->handshake.client_finished, .size = secrets.size };
    s2n_tls13_derive_finish_key(&secrets, &client_hs_secret, &client_finished_key);

    PRINT0("Finish Key 0");
    print_hex_blob(server_finished_key);

    return 0;
}



/* Based on a finished key and hash state, compute verify hash */
int s2n_tls13_calculate_finish_verify(struct s2n_tls13_keys *keys, struct s2n_blob *finished_key, struct s2n_hash_state *hash_state, struct s2n_blob *finished_verify) {
    /* Set up a blob to contain hash */
    s2n_tls13_key_blob(transcribe_hash, keys->size);

    /* Make a copy of the hash state */
    struct s2n_hash_state hash_state_copy;
    GUARD(s2n_hash_new(&hash_state_copy));
    GUARD(s2n_hash_copy(&hash_state_copy, hash_state));

    GUARD(s2n_hash_digest(&hash_state_copy, transcribe_hash.data, transcribe_hash.size));
    GUARD(s2n_hash_free(&hash_state_copy));

    print_hex_blob(transcribe_hash);

    GUARD(s2n_hkdf_extract(&keys->hmac, keys->hmac_algorithm, finished_key, &transcribe_hash, finished_verify));

    return 0;
}

// uint8_t** finish_keys
static int wire_finish_verify(struct s2n_tls13_keys *keys, struct s2n_blob *finished_verify, struct s2n_blob *wire_verify) {
    // check wire
    notnull_check(wire_verify->data);
    eq_check(wire_verify->size, keys->size);

    PRINT0("Finish Verify");
    print_hex_blob(*finished_verify);
    PRINT0("Wire Verify");
    print_hex_blob(*wire_verify);

    S2N_ERROR_IF(!s2n_constant_time_equals(finished_verify->data, wire_verify->data, keys->size), S2N_ERR_BAD_MESSAGE);

    return 0;
}


int server_finish_verify(struct s2n_connection *conn, struct s2n_tls13_keys *keys, struct s2n_blob *verify) {
    struct s2n_hash_state hash_state = {0};
    GUARD(s2n_handshake_get_hash_state(conn, keys->hash_algorithm, &hash_state));

    s2n_tls13_key_blob(server_finish_verify, keys->size);  

    struct s2n_blob finished_key = {
        .data = conn->handshake.server_finished,
        .size = keys->size
    };

    GUARD(s2n_tls13_calculate_finish_verify(keys, &finished_key, &hash_state, &server_finish_verify));
    wire_finish_verify(keys, &server_finish_verify, verify);

    return 0;
}

int client_finish_verify(struct s2n_connection *conn, struct s2n_tls13_keys *keys, struct s2n_blob *verify) {
    // get hash state
    struct s2n_hash_state hash_state = {0};
    GUARD(s2n_handshake_get_hash_state(conn, keys->hash_algorithm, &hash_state));

    PRINT0("client Finish Ctx Hash\n");
    
    s2n_tls13_key_blob(client_finish_verify, keys->size);  

    struct s2n_blob finished_key = {
        .data = conn->handshake.client_finished,
        .size = keys->size
    };

    PRINT0("client Finish Key");
    print_hex_blob(finished_key);

    GUARD(s2n_tls13_calculate_finish_verify(keys, &finished_key, &hash_state, &client_finish_verify));
    wire_finish_verify(keys, &client_finish_verify, verify);

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

// calculate finish key
// server finish verify data
