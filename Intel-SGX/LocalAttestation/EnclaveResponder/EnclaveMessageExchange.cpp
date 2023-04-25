/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "sgx_trts.h"
#include "sgx_utils.h"
#include "EnclaveMessageExchange.h"
#include "sgx_eid.h"
#include "error_codes.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include <map>
#include "janus_session_protocol.h"
#include "sgx_tcrypto.h"
#include "../EnclaveResponder/EnclaveResponder_t.h"

#define MAX_SESSION_COUNT  16

//number of open sessions
uint32_t g_session_count = 0;

ATTESTATION_STATUS generate_session_id(uint32_t *session_id);
extern "C" ATTESTATION_STATUS end_session(uint32_t session_id);

//Array of open session ids
session_id_tracker_t *g_session_id_tracker[MAX_SESSION_COUNT];

//Map between the session id and the session information associated with that particular session
std::map<uint32_t, janus_session_t>g_dest_session_info_map;

//Create a session with the destination enclave

const uint8_t g_measurement[MEASUREMENT_LEN] = { 0x2 };
uint8_t g_nonce[NONCE_LEN];

#ifndef MIN
#define MIN(a, b)               \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a < _b ? _a : _b;      \
    })
#endif
#ifndef MAX
#define MAX(a, b)               \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a > _b ? _a : _b;      \
    })
#endif

/*!
 * \brief Low-level wrapper around RDRAND instruction (get hardware-generated random value).
 */
static inline uint32_t rdrand(void) {
    uint32_t ret;
    __asm__ volatile(
        "1: .byte 0x0f, 0xc7, 0xf0\n" /* RDRAND %EAX */
        "jnc 1b\n"
        :"=a"(ret)
        :: "cc");
    return ret;
}

int random_bits_read(void* buffer, size_t size) {
    uint32_t rand;
    for (size_t i = 0; i < size; i += sizeof(rand)) {
        rand = rdrand();
        memcpy(buffer + i, &rand, MIN(sizeof(rand), size - i));
    }
    return 0;
}

int puf_get_response(const uint8_t* puf_challenge, uint8_t* puf_resp, size_t puf_resp_len) {
    const unsigned char *hmac_key = reinterpret_cast<const unsigned char *>("\x3c\x4f\xd3\x55\x3b\x89\xa1\xf8\xfa\xcb\x3b\xb7\x68\x2c\x8c\x4f\x0a\x69\x03\xde\x7b\x45\x8c\x6a\xd8\x7b\x6b\xe1\x3d\x1b\x96\x67\xe0\xb6\x47\xa7\xe4\x59\x5d\x56\xc8\xf1\x3a\x34\x02\x79\xb9\xeb\x61\xa0\x13\x87\xc2\x34\x88\x05\xc1\xe4\x43\x36\x26\xaf\xb0\x52");
    memcpy(puf_resp, hmac_key, puf_resp_len);

    return 0;
}

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

int verify_tag(const janus_msg_z* z, const uint8_t* t, const uint8_t* key) {
    int ret = -1;
    sgx_hmac_state_handle_t context;
    sgx_hmac256_init(key, HMAC_KEY_LEN, &context);

    uint8_t t_calc[HMAC_TAG_LEN] = {0};
    ret = sgx_hmac_sha256_msg((const unsigned char*)z, sizeof(*z), key, HMAC_KEY_LEN,
                              t_calc, HMAC_TAG_LEN);
    if (ret < 0) {
        return ret;
    }

    return memcmp(t_calc, t, HMAC_TAG_LEN);
}

int produce_hash_c_r(const struct janus_msg_z* janus_msg_z,
                                               const uint8_t* measurement, const uint8_t* nonce,
                                               uint8_t* hash_buf) {
    uint8_t puf_resp_m[MEASUREMENT_LEN] = {0};
    uint8_t puf_resp_n[NONCE_LEN] = {0};
    uint8_t c[SHA256_HASH_SIZE] = {0};
    uint8_t puf_resp_c[SHA256_HASH_SIZE] = {0};
    sgx_sha_state_handle_t sha_handle = NULL;
    sgx_status_t sgx_status = SGX_SUCCESS;

    if (puf_get_response(measurement, puf_resp_m, MEASUREMENT_LEN) < 0) {
        return -1;
    }
    if (puf_get_response(nonce, puf_resp_n, NONCE_LEN) < 0) {
        return -1;
    }

    do {
        sgx_status = sgx_sha256_init(&sha_handle);
        if (SGX_SUCCESS != sgx_status)
            break;

        sgx_status = sgx_sha256_update((const uint8_t*)janus_msg_z, sizeof(*janus_msg_z),
                                       sha_handle);
        if (SGX_SUCCESS != sgx_status)
            break;
        sgx_status = sgx_sha256_update(puf_resp_m, sizeof(puf_resp_m), sha_handle);
        if (SGX_SUCCESS != sgx_status)
            break;
        sgx_status = sgx_sha256_update(puf_resp_n, sizeof(puf_resp_n), sha_handle);
        if (SGX_SUCCESS != sgx_status)
            break;
        sgx_status = sgx_sha256_get_hash(sha_handle, reinterpret_cast<sgx_sha256_hash_t *>(c));
    } while (0);
    if (SGX_SUCCESS != sgx_status) {
        return -1;
    }

    if (puf_get_response(c, puf_resp_c, SHA256_HASH_SIZE) < 0) {
        return -1;
    }

    do {
        sgx_status = sgx_sha256_init(&sha_handle);
        if (SGX_SUCCESS != sgx_status)
            break;

        sgx_status = sgx_sha256_update(c, sizeof(c), sha_handle);
        if (SGX_SUCCESS != sgx_status)
            break;
        sgx_status = sgx_sha256_update(puf_resp_c, sizeof(puf_resp_c), sha_handle);
        if (SGX_SUCCESS != sgx_status)
            break;
        sgx_status = sgx_sha256_get_hash(sha_handle,
                                         reinterpret_cast<sgx_sha256_hash_t *>(hash_buf));
    } while (0);
    if (SGX_SUCCESS != sgx_status) {
        return -1;
    }

    return 0;
}

extern "C" ATTESTATION_STATUS verify_la_msg(const size_t round, const janus_la_msg_t* janus_msg) {
    switch (round) {
        case JANUS_LA_R1: {
            uint8_t hmac_key[HMAC_KEY_LEN] = {0};
            puf_get_response(NULL, hmac_key, HMAC_KEY_LEN);

            if (verify_tag(&janus_msg->z, janus_msg->t, hmac_key) < 0) {
                return ERROR_UNEXPECTED;
            }

            break;
        }
        case JANUS_LA_R2:
        case JANUS_LA_R3: {
            uint8_t t_calc[SHA256_HASH_SIZE] = {0};

            if (produce_hash_c_r(&janus_msg->z, (janus_msg->z).measurement, g_nonce, t_calc) < 0) {
                return ERROR_UNEXPECTED;
            }

            if (memcmp(t_calc, janus_msg->t, SHA256_HASH_SIZE)) {
                return ERROR_UNEXPECTED;
            }

            break;
        }
        default: {
            printf("JANUS: unsupported round in verify_la_msg: %d!\n", round);
            return ERROR_UNEXPECTED;
        }
    }

    return SUCCESS;
}

int construct_z_message(const uint8_t* aid, const uint8_t pid, const uint8_t* measurement,
                        bool with_nonce, janus_msg_z* z) {
    memset(z, 0, sizeof(*z));

    memcpy(z->aid, aid, sizeof(z->aid));
    z->pid = pid;
    if (measurement) {
        memcpy(z->measurement, measurement, sizeof(z->measurement));
    }
    if (with_nonce) {
        if (random_bits_read(z->nonce, sizeof(z->nonce)) < 0) {
            return GEN_RANDOM_ERROR;
        }
        memcpy(g_nonce, z->nonce, sizeof(g_nonce));
    }

    return 0;
}

int construct_tag(const janus_msg_z* z, const uint8_t* key, uint8_t* t) {
    memset(t, 0, sizeof(HMAC_TAG_LEN));

    sgx_hmac_state_handle_t context;
    sgx_hmac256_init(key, HMAC_KEY_LEN, &context);

    if (sgx_hmac_sha256_msg((const unsigned char*)z, sizeof(*z), key, HMAC_KEY_LEN,
                            t, HMAC_TAG_LEN) < 0) {
        return -1;
    }
    return 0;
}

extern "C" ATTESTATION_STATUS generate_la_msg(const size_t round,
                                              janus_la_msg_t* in_out_janus_msg) {
    uint8_t aid[40] = {0};
    uint8_t pid = 0x01;
    janus_la_msg_t janus_msg = {0};

    switch (round) {
        case JANUS_LA_R1: {
            if (construct_z_message(aid, pid, NULL, true, &janus_msg.z) < 0) {
                return ERROR_UNEXPECTED;
            }
            break;
        }
        case JANUS_LA_R2: {
            if (construct_z_message(aid, pid, g_measurement, true, &janus_msg.z) < 0) {
                return ERROR_UNEXPECTED;
            }
            break;
        }
        case JANUS_LA_R3: {
            if (construct_z_message(aid, pid, g_measurement, false, &janus_msg.z) < 0) {
                return ERROR_UNEXPECTED;
            }
            break;
        }
        default: {
            printf("JANUS: unsupported round in generate_la_msg: %d!\n", round);
            return ERROR_UNEXPECTED;
        }
    }

    switch (round) {
        case JANUS_LA_R1: {
            uint8_t hmac_key[HMAC_KEY_LEN] = {0};
            puf_get_response(NULL, hmac_key, HMAC_KEY_LEN);

            if (construct_tag(&janus_msg.z, hmac_key, janus_msg.t) < 0) {
                return ERROR_UNEXPECTED;
            }
            break;
        }
        case JANUS_LA_R2:
        case JANUS_LA_R3: {
            if (produce_hash_c_r(&janus_msg.z, g_measurement, (in_out_janus_msg->z).nonce,
                                 janus_msg.t) < 0) {
                return ERROR_UNEXPECTED;
            }

            break;
        }
        default: {
            printf("JANUS: unsupported round in generate_la_msg: %d!\n", round);
            return ERROR_UNEXPECTED;
        }
    }

    memcpy(in_out_janus_msg, &janus_msg, sizeof(*in_out_janus_msg));

    return SUCCESS;
}

//Respond to the request from the Source Enclave to close the session
extern "C" ATTESTATION_STATUS end_session(uint32_t session_id) {
    ATTESTATION_STATUS status = SUCCESS;
    int i;
    janus_session_t session_info;
    //uint32_t session_id;

    //Get the session information from the map corresponding to the source enclave id
    std::map<uint32_t, janus_session_t>::iterator it = g_dest_session_info_map.find(session_id);
    if(it != g_dest_session_info_map.end()) {
        session_info = it->second;
    }
    else {
        return INVALID_SESSION;
    }

    //session_id = session_info.session_id;
    //Erase the session information for the current session
    g_dest_session_info_map.erase(session_id);

    //Update the session id tracker
    if (g_session_count > 0) {
        //check if session exists
        for (i=1; i <= MAX_SESSION_COUNT; i++) {
            if(g_session_id_tracker[i-1] != NULL &&
               g_session_id_tracker[i-1]->session_id == session_id) {
                memset(g_session_id_tracker[i-1], 0, sizeof(session_id_tracker_t));
                SAFE_FREE(g_session_id_tracker[i-1]);
                g_session_count--;
                break;
            }
        }
    }

    return status;

}

//Returns a new sessionID for the source destination session
ATTESTATION_STATUS generate_session_id(uint32_t *session_id) {
    ATTESTATION_STATUS status = SUCCESS;

    if(!session_id) {
        return INVALID_PARAMETER_ERROR;
    }
    //if the session structure is uninitialized, set that as the next session ID
    for (int i = 0; i < MAX_SESSION_COUNT; i++) {
        if (g_session_id_tracker[i] == NULL) {
            *session_id = i;
            return status;
        }
    }

    status = NO_AVAILABLE_SESSION_ERROR;

    return status;

}
