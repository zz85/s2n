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

#include "tls/extensions/s2n_server_key_share.h"

#include "tls/s2n_client_extensions.h"
#include "utils/s2n_safety.h"

/* Calculate the data length for Server Key Share extension */
int s2n_extensions_server_key_share_send_size(struct s2n_connection *conn)
{
    const struct s2n_ecc_named_curve* curve = conn->secure.server_ecc_params.negotiated_curve;

    /* Negotiated curve is currently selected by s2n_recv_client_supported_groups() */
    if (curve == NULL)
    {
        return 0;
    }

    const int key_share_size = S2N_SIZE_OF_EXTENSION_TYPE
        + S2N_SIZE_OF_EXTENSION_DATA_SIZE
        + S2N_SIZE_OF_NAMED_GROUP
        + S2N_SIZE_OF_KEY_SHARE_SIZE
        + curve->share_size;

    return key_share_size;
}

/*
    Sends Key Share extension in Server Hello.
    Expects negotiated_curve to be set and generates a ephemeral key for key sharing
*/
int s2n_extensions_server_key_share_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    notnull_check(conn->secure.server_ecc_params.negotiated_curve);
    notnull_check(out);

    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_KEY_SHARE));
    GUARD(s2n_stuffer_write_uint16(out, s2n_extensions_server_key_share_send_size(conn) - 2));

    GUARD(s2n_ecdhe_parameters_send(&conn->secure.server_ecc_params, out));

    return 0;
}

int s2n_ecc_find_curve_index_by_iana_id(int iana_id)
{
    for (int i = 0; i < S2N_ECC_SUPPORTED_CURVES_COUNT; i++)
    {
        if (iana_id == s2n_ecc_supported_curves[i].iana_id)
        {
            return i;
        }
    }

    return -1;
}
/*
    Client receives a Server Hello key share.
    If the curve is supported, conn->secure.server_ecc_params will be set.
*/
int s2n_extensions_server_key_share_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    notnull_check(conn);
    notnull_check(extension);

    uint16_t named_group, share_size;

    GUARD(s2n_stuffer_read_uint16(extension, &named_group));
    GUARD(s2n_stuffer_read_uint16(extension, &share_size));

    int curve_index = s2n_ecc_find_curve_index_by_iana_id(named_group);

    struct s2n_blob point_blob;
    struct s2n_ecc_params* server_ecc_params = &conn->secure.server_ecc_params;

    /*
        https://tools.ietf.org/html/rfc8446#section-4.2.8

        If using (EC)DHE key establishment, servers offer exactly one
        KeyShareEntry in the ServerHello.  This value MUST be in the same
        group as the KeyShareEntry value offered by the client that the
        server has selected for the negotiated key exchange.  Servers
        MUST NOT send a KeyShareEntry for any group not indicated in the
        client's "supported_groups" extension and MUST NOT send a
        KeyShareEntry when using the "psk_ke" PskKeyExchangeMode.
    */

    /* Key share unsupported by s2n */
    S2N_ERROR_IF(curve_index < 0  || curve_index >= S2N_ECC_SUPPORTED_CURVES_COUNT, S2N_ERR_BAD_KEY_SHARE);

    /* Key share not sent by client */
    S2N_ERROR_IF(conn->secure.client_ecc_params[curve_index].ec_key == NULL, S2N_ERR_BAD_KEY_SHARE);

    /* Proceed to parse curve */
    server_ecc_params->negotiated_curve = &s2n_ecc_supported_curves[curve_index];

    S2N_ERROR_IF(s2n_ecc_read_ecc_params_point(extension, &point_blob, share_size) < 0, S2N_ERR_BAD_KEY_SHARE);
    S2N_ERROR_IF(s2n_ecc_parse_ecc_params_point(server_ecc_params, &point_blob) < 0, S2N_ERR_BAD_KEY_SHARE);

    return 0;
}
