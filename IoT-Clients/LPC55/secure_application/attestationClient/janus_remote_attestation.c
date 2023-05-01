#include "janus_remote_attestation.h"

const uint8_t g_measurement[MEASUREMENT_LEN] = { 0x2 };
uint8_t g_nonce[JANUS_NONCE_LEN]; // global nonce

int construct_A_message(struct janus_msg_A* A, const uint8_t* id, const uint8_t pid, bool with_nonce) {
    memset(A, 0, sizeof(*A));

    memcpy(A->id, id, sizeof(A->id));
    A->pid = pid;
    A->timestamp = generate_timestamp();
    if (with_nonce) {
        if(generate_random_array(A->nonce, sizeof(A->nonce)) < 0) {
            return GEN_RANDOM_ERROR;
        }
        memcpy(g_nonce, A->nonce, sizeof(g_nonce));
    }
    return SUCCESS;
}

int construct_payload(uint8_t* payload, const size_t payload_len, const uint8_t* measurement, bool with_random) {
    memset(payload, 0, payload_len);     size_t cur = 0;
    if(measurement == NULL)
    {
        if(generate_random_array(payload + cur, JANUS_COMM_KEY_LEN) < 0) // RT
        {
            return GEN_RANDOM_ERROR;
        }
        cur += JANUS_COMM_KEY_LEN; 
    }
    else
    {
        memcpy(payload + cur, measurement, MEASUREMENT_LEN); cur += MEASUREMENT_LEN; 
    }
    if(with_random)
    {
        if(generate_random_array(payload + cur, JANUS_COMM_KEY_LEN) < 0) {
            return GEN_RANDOM_ERROR;
        }
        cur += JANUS_COMM_KEY_LEN;
    }
    return SUCCESS;
}

int construct_signature(uint8_t* signature_buf, const uint8_t* content, const uint8_t* private_key)
{

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
    size_t aux_len = JANUS_ID_LEN + tssize + 1;
    if(with_nonce)
    {
        aux_len += JANUS_NONCE_LEN;
    }

    uint8_t auxdata[aux_len];
    memcpy(auxdata, A->id, JANUS_ID_LEN);
    auxdata[JANUS_ID_LEN] = A->pid;
    memcpy(auxdata + JANUS_ID_LEN + 1, &(A->timestamp), tssize);
    if(with_nonce)
    {
        memcpy(auxdata + JANUS_ID_LEN + 1 + tssize, &(A->nonce), JANUS_NONCE_LEN);
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

int construct_ra_challenge(struct RemoteAttestationClient* client, janus_ra_msg_t* janus_msg, const uint8_t pid)
{
    struct janus_msg_A A;
    size_t payloadlen = 2 * JANUS_COMM_KEY_LEN;
    uint8_t payload[payloadlen], C[payloadlen], T[ASCON_AEAD_TAG_MIN_SECURE_LEN]; // RT || RV 
    
    if(construct_A_message(&A, client->id, pid, true) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    if(construct_payload(payload, payloadlen, NULL, true) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    if(construct_CT_message(C, T, payload, payloadlen, &A, client->personal_key, true) < 0)
    {
        return ERROR_UNEXPECTED;
    }

    janus_msg->A = A;
    memset(janus_msg->T, T, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    memset(janus_msg->C, C, payloadlen);

    return SUCCESS;
}

int construct_ra_response(struct RemoteAttestationClient* client, janus_ra_msg_t* janus_msg, const uint8_t* measurement, const uint8_t pid, bool with_nonce, bool with_random)
{
    struct janus_msg_A A;
    uint8_t signature[SIGNATURE_SIZE];
    size_t payloadlen = JANUS_COMM_KEY_LEN + SIGNATURE_SIZE;
    if(with_random)
    {
        payloadlen += JANUS_COMM_KEY_LEN; // RM || R || sigma
    }
    uint8_t payload[payloadlen], C[payloadlen], T[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    if(construct_A_message(&A, client->id, pid, with_nonce) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    if(construct_payload(payload, payloadlen, g_measurement, with_random) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    if(construct_signature(signature, payload, client->private_key) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    if(construct_CT_message(C, T, payload, payloadlen, &A, client->personal_key, with_nonce) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    janus_msg->A = A;
    memset(janus_msg->T, T, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    memset(janus_msg->C, C, payloadlen);
    return SUCCESS;
}


ATTESTATION_STATUS construct_ra_message(struct RemoteAttestationClient* client, const size_t round, janus_ra_msg_t* in_out_janus_msg)
{
    //uint8_t id[40] = {0};
    uint8_t pid = 0x01;
    janus_ra_msg_t janus_msg;

    switch(round)
    {
        case JANUS_RA_R1: {
            if(construct_ra_challenge(client, &janus_msg, pid) < 0)
            {
                return ERROR_UNEXPECTED;
            }
            break;
        }
        case JANUS_RA_R2: {
            if(check_received_challenge() < 0)
            {
                return INVALID_MESSAGE;
            }
            if(construct_ra_response(client, &janus_msg, g_measurement, pid, true, true)< 0)
            {
                return ERROR_UNEXPECTED;
            }
            break;
        }
        case JANUS_RA_R3: {
            if(check_received_challenge() < 0)
            {
                return INVALID_MESSAGE;
            }
            if(construct_ra_response(client, &janus_msg, g_measurement, pid, false, false)< 0)
            {
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