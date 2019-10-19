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

#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"

uint8_t s2n_highest_protocol_version = S2N_TLS13;
uint8_t s2n_unknown_protocol_version = S2N_UNKNOWN_PROTOCOL_VERSION;

/*
 * Convert max_fragment_length codes to length.
 * RFC 6066 says:
 *    enum{
 *        2^9(1), 2^10(2), 2^11(3), 2^12(4), (255)
 *    } MaxFragmentLength;
 * and we add 0 -> extension unused
 */
uint16_t mfl_code_to_length[5] =
{
    S2N_DEFAULT_FRAGMENT_LENGTH,     /* S2N_TLS_MAX_FRAG_LEN_EXT_NONE */
    512,                             /* S2N_TLS_MAX_FRAG_LEN_512  */
    1024,                            /* S2N_TLS_MAX_FRAG_LEN_1024 */
    2048,                            /* S2N_TLS_MAX_FRAG_LEN_2048 */
    4096,                            /* S2N_TLS_MAX_FRAG_LEN_4096 */
};

void print_hex(uint8_t *s, size_t len) {
    printf("Hex: ");
    for(int i = 0; i < len; i++) {
        printf("%02x ", s[i]);
    }
    printf("\n");

    printf("Dec: ");
    for(int i = 0; i < len; i++) {
        printf("%d ", s[i]);
    }

    printf("\n");
}

void print_hex2(uint8_t *s, size_t len) {
    printf("Hex: ");
    for(int i = 0; i < len; i++) {
        printf("%02x", s[i]);
    }
    printf("\n");

    printf("Dec: ");
    for(int i = 0; i < len; i++) {
        printf("%d ", s[i]);
    }

    printf("\n");
}

void print_hex_blob(struct s2n_blob blob) {
    print_hex(blob.data, blob.size);
}
