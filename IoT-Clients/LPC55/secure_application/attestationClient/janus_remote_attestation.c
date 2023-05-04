#include "janus_remote_attestation.h"

const uint8_t g_measurement[MEASUREMENT_LEN] = { 0x2 };
uint8_t g_nonce[JANUS_NONCE_LEN]; // global nonce
uint8_t g_payloadlen[4] = {0, 2 * JANUS_COMM_KEY_LEN, 2 * JANUS_COMM_KEY_LEN + SIGNATURE_SIZE, JANUS_COMM_KEY_LEN + SIGNATURE_SIZE}; 

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

int construct_CT_message(uint8_t* C, uint8_t* T, uint8_t* AN, const uint8_t* payload, const size_t payload_len, struct janus_msg_A* A, const uint8_t* commuication_key, bool with_nonce) {
    memset(C, 0, sizeof(*C));
    memset(T, 0, sizeof(*T));
    if(generate_random_array(AN, ASCON_AEAD_NONCE_LEN) < 0)
    {
        return GEN_RANDOM_ERROR;
    }
    size_t aux_len = get_A_buffer_len(with_nonce);
    uint8_t auxdata[aux_len];
    if(A_message_buffering(auxdata, A, with_nonce) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    ascon_aead128_encrypt(C, T,
                        commuication_key,
                        AN,
                        auxdata,
                        payload,
                        aux_len,
                        payload_len,
                        sizeof(T));

    return SUCCESS;
}

int deconstruct_encrypted_payload(uint8_t* payload, const uint8_t* communication_key, janus_ra_msg_t* received_msg, const size_t payloadlen, int round)
{
    memset(payload, 0, payloadlen);
    size_t auxlen = get_A_buffer_len((round == 1 || round == 2));
    uint8_t auxdata[auxlen];

    if(ascon_aead128_decrypt(
        payload, 
        communication_key, 
        received_msg->AN, 
        auxdata, 
        received_msg->C, 
        received_msg->T, 
        auxlen, 
        payloadlen, 
        ASCON_AEAD_TAG_MIN_SECURE_LEN) == false)
    {
        return INVALID_MESSAGE;
    }
    return SUCCESS;
}

int construct_ra_challenge(struct RemoteAttestationClient* client, janus_ra_msg_t* janus_msg, int round)
{
    struct janus_msg_A A;
    size_t payloadlen = g_payloadlen[round];
    uint8_t payload[payloadlen], C[payloadlen], T[ASCON_AEAD_TAG_MIN_SECURE_LEN], AN[ASCON_AEAD_NONCE_LEN];
    
    uint8_t* measurement = round == 1 ? NULL: g_measurement;
    uint8_t pid = round == 1 ? 1 : -1;
    bool with_random = round == 3 ? false : true;
    
    if(construct_A_message(&A, client->id, pid, with_random) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    if(construct_payload(payload, payloadlen, measurement, with_random) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    if(round == 2 || round == 3)
    {
        if(generate_serialized_signature(payload, payloadlen - SIGNATURE_SIZE, payloadlen, client) < 0)
        {
            return ERROR_UNEXPECTED;
        }
    }
    if(construct_CT_message(C, T, AN, payload, payloadlen, &A, client->personal_key, true) < 0)
    {
        return ERROR_UNEXPECTED;
    }

    janus_msg->A = A;
    memcpy(janus_msg->T, T, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    memcpy(janus_msg->AN, AN, ASCON_AEAD_NONCE_LEN);
    memcpy(janus_msg->C, C, payloadlen);

    return SUCCESS;
}

int check_received_message(struct RemoteAttestationClient* client, janus_ra_msg_t* received_msg, int round)
{
    size_t payloadlen = g_payloadlen[round];
    uint8_t* communication_key[JANUS_COMM_KEY_LEN], group_key[JANUS_COMM_KEY_LEN];
    uint8_t* payload[payloadlen];
    // need to retrieve the encrypted secret from chain first
    // and recover the group key
    if(decrypt_onchain_secret(communication_key, group_key) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    if(deconstruct_encrypted_payload(payload, communication_key, received_msg, payloadlen, round) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    if(round == 2 || round == 3)
    {
        if(verify_signature(client, payload, payloadlen) == false || verify_measurement(client, payload, payloadlen, received_msg->A.id, received_msg->A.pid, g_measurement) == false)
        {
            return INVALID_MESSAGE;
        }
    }
    if(round == 1 || round == 2)
    {
        obtain_shared_secret();
    }
    
    return SUCCESS;
}


ATTESTATION_STATUS construct_ra_message(struct RemoteAttestationClient* client, const size_t round, janus_ra_msg_t* in_out_janus_msg)
{
    //uint8_t id[40] = {0};
    janus_ra_msg_t janus_msg;

    switch(round)
    {
        case JANUS_RA_R1: {
            if(construct_ra_challenge(client, &janus_msg, 1) < 0)
            {
                return ERROR_UNEXPECTED;
            }
            break;
        }
        case JANUS_RA_R2: {
            if(check_received_message(client, in_out_janus_msg, 2) != SUCCESS)
            {
                return INVALID_MESSAGE;
            }
            if(construct_ra_challenge(client, &janus_msg, 2)< 0)
            {
                return ERROR_UNEXPECTED;
            }
            break;
        }
        case JANUS_RA_R3: {
            if(check_received_message(client, in_out_janus_msg, 3) == SUCCESS)
            {
                return INVALID_MESSAGE;
            }
            if(construct_ra_challenge(client, &janus_msg, 3)< 0)
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