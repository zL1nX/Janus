#include "janus_remote_attestation.h"

uint8_t g_nonce[JANUS_NONCE_LEN]; // global nonce

int construct_A_message(struct janus_msg_A* A, const uint8_t* id, const uint8_t pid, bool with_nonce) {
    memset(A, 0, sizeof(*A));

    memcpy(A->id, id, sizeof(A->id));
    A->pid = pid;
    if (with_nonce) {
        if(generate_random_array(A->nonce, sizeof(A->nonce)) < 0) {
            return GEN_RANDOM_ERROR;
        }
        memcpy(g_nonce, A->nonce, sizeof(g_nonce));
    }
    return SUCCESS;
}

int construct_payload(uint8_t* payload, const size_t payload_len, const uint8_t* measurement, const uint8_t* signature, bool with_random) {
    memset(payload, 0, payload_len);     size_t cur = 0;
    memcpy(payload + cur, measurement, MEASUREMENT_LEN); cur += MEASUREMENT_LEN; 
    if(with_random)
    {
        if(generate_random_array(payload + cur, JANUS_COMM_KEY_LEN) < 0) {
            return GEN_RANDOM_ERROR;
        }
        cur += JANUS_COMM_KEY_LEN;
    }
    memcpy(payload + cur, signature, SIGNATURE_SIZE); cur += SIGNATURE_SIZE;
    return SUCCESS;
}

int construct_CT_message(uint8_t* C, uint8_t* T, const uint8_t* payload, const size_t payload_len, struct janus_msg_A* A, const uint8_t* commuication_key, bool with_nonce) {
    memset(C, 0, sizeof(*C));
    memset(T, 0, sizeof(*T));
    uint8_t ascon_nonce[ASCON_AEAD_NONCE_LEN] = { 0 };
    if(generate_random_array(ascon_nonce, ASCON_AEAD_NONCE_LEN) < 0)
    {
        return GEN_RANDOM_ERROR;
    }
    size_t tssize = sizeof(A->timestamp);
    size_t aux_len = ID_LEN + tssize + 1;
    if(with_nonce)
    {
        aux_len += JANUS_NONCE_LEN;
    }

    uint8_t auxdata[aux_len];
    memcpy(auxdata, A->id, ID_LEN);
    auxdata[ID_LEN] = A->pid;
    memcpy(auxdata + ID_LEN + 1, &(A->timestamp), tssize);
    if(with_nonce)
    {
        memcpy(auxdata + ID_LEN + 1 + tssize, &(A->nonce), JANUS_NONCE_LEN);
    }

    ascon_aead128_encrypt(C, T,
                        commuication_key,
                        ascon_nonce,
                        auxdata,
                        payload,
                        aux_len,
                        payload_len,
                        sizeof(T));

    return SUCCESS;
}


int construct_ra_message()
{
    // TODO
    return SUCCESS;
}