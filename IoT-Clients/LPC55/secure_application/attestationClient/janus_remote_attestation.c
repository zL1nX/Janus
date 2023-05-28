#include "janus_remote_attestation.h"

const uint8_t g_measurement[MEASUREMENT_LEN] = {0xba, 0x8b, 0xa7, 0x1f, 0x6c, 0x76, 0xda, 0x0c, 0xf3, 0x24, 0xd6, 0x66, 0x3d, 0xc4, 0x80, 0x20, 0x47, 0x19, 0xf3, 0x75, 0xdf, 0xfe, 0xb2, 0x1f, 0xae, 0x76, 0xa7, 0x90, 0x20, 0xa4, 0x43, 0xf1};
const uint8_t g_puf_measurement[PUF_RESPONESE_LEN] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10}; // RM = PUF(M)
const uint8_t g_hash_puf_measurement[MEASUREMENT_LEN] = {0xf0, 0x5b, 0x5b, 0xd6, 0x60, 0xc5, 0x2e, 0x61, 0x96, 0x91, 0x50, 0xdb, 0x79, 0xcf, 0x5a, 0x88, 0x7d, 0xcb, 0x18, 0x7e, 0x04, 0xc7, 0xbb, 0xe5, 0x42, 0xf4, 0x61, 0x52, 0xbb, 0xb4, 0x8c, 0x2e}; // H(RM||id||pid)

uint8_t g_nonce[JANUS_NONCE_LEN]; // global nonce
uint8_t g_payloadlen[4] = {0, 2 * JANUS_COMM_KEY_LEN, 2 * JANUS_COMM_KEY_LEN + SIGNATURE_SIZE, JANUS_COMM_KEY_LEN + SIGNATURE_SIZE}; 

extern struct RemoteAttestationClient g_client;

int construct_A_message(uint8_t* A, const uint8_t* id, const uint8_t pid, bool with_nonce) {
    size_t cur = 0;
    uint16_t ts = generate_timestamp();
    memcpy(A, id, JANUS_ID_LEN); cur += JANUS_ID_LEN;
    memcpy(A + cur, &pid, JANUS_ID_LEN); cur += 1;
    memcpy(A + cur, &ts, 2); cur += 2;
    if (with_nonce) {
        if(generate_random_array(A + cur, JANUS_NONCE_LEN) < 0) {
            return GEN_RANDOM_ERROR;
        }
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
        memcpy(payload + cur, measurement, PUF_MEASUREMENT_LEN); cur += PUF_MEASUREMENT_LEN; 
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

int construct_CT_message(uint8_t* C, uint8_t* T, uint8_t* AN, const uint8_t* payload, const size_t payload_len, const uint8_t* A, const size_t alen, const uint8_t* commuication_key, bool with_nonce) {
    memset(C, 0, payload_len);
    memset(T, 0, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    if(generate_random_array(AN, ASCON_AEAD_NONCE_LEN) < 0)
    {
        return GEN_RANDOM_ERROR;
    }
    ascon_aead128_encrypt(C, T,
                        commuication_key,
                        AN,
                        A,
                        payload,
                        alen,
                        payload_len,
                        ASCON_AEAD_TAG_MIN_SECURE_LEN);
    return SUCCESS;
}

int deconstruct_encrypted_payload(uint8_t* payload, const uint8_t* communication_key, janus_ra_msg_t* received_msg, int round)
{
    memset(payload, 0, received_msg->clen);
    bool with_nonce = (round == 1 || round == 2);

    if(ascon_aead128_decrypt(
        payload, 
        communication_key, 
        received_msg->AN, 
        received_msg->A, 
        received_msg->C, 
        received_msg->T, 
        received_msg->alen, 
        received_msg->clen, 
        ASCON_AEAD_TAG_MIN_SECURE_LEN) == false)
    {
        return INVALID_MESSAGE;
    }
    return SUCCESS;
}

int construct_ra_challenge(janus_ra_msg_t* janus_msg, int round)
{
    //janus_msg = (janus_ra_msg_t*)malloc(sizeof(janus_ra_msg_t));
    
    size_t payloadlen = g_payloadlen[round];
    size_t alen = JANUS_ID_LEN + 2 + 1;
    if(round == 1 || round == 2)
    {
        alen += JANUS_NONCE_LEN;
    }
    
    uint8_t A[alen], payload[payloadlen], C[payloadlen], T[ASCON_AEAD_TAG_MIN_SECURE_LEN], AN[ASCON_AEAD_NONCE_LEN];
    uint8_t pid = round == 1 ? 1 : 255;
    bool with_random = round == 3 ? false : true;

//    uint8_t real_puf_measurement[PUF_MEASUREMENT_LEN];
//    if(janus_puf_evaluate(g_client.sr, real_puf_measurement, g_measurement) != SUCCESS)
//    {
//        return ERROR_UNEXPECTED;
//    }
    const uint8_t* measurement = round == 1 ? NULL: g_puf_measurement;
    
    // for(int i = 0; i < PUF_MEASUREMENT_LEN; i++)
    // {
    //     printf("%x ", real_puf_measurement[i]);
    // }
    // printf("\n");
    
    if(construct_A_message(A, g_client.id, pid, with_random) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    if(construct_payload(payload, payloadlen, measurement, with_random) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    if(round == 2 || round == 3)
    {
        if(generate_serialized_signature(payload, payloadlen - SIGNATURE_SIZE, &g_client) < 0)
        {
            return ERROR_UNEXPECTED;
        }
    }

    if(construct_CT_message(C, T, AN, payload, payloadlen, A, alen, g_client.personal_key, true) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    
    janus_msg->A = (uint8_t*)malloc(alen * sizeof(uint8_t));
    janus_msg->C = (uint8_t*)malloc(payloadlen * sizeof(uint8_t));

    memcpy(janus_msg->T, T, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    memcpy(janus_msg->AN, AN, ASCON_AEAD_NONCE_LEN);
    memcpy(janus_msg->C, C, payloadlen);
    memcpy(janus_msg->A, A, alen);
    janus_msg->alen = alen;
    janus_msg->clen = payloadlen;

    return SUCCESS;
}

int check_received_message(janus_ra_msg_t* received_msg, int round)
{
    size_t payloadlen = g_payloadlen[round];
    uint8_t communication_key[JANUS_COMM_KEY_LEN], group_key[JANUS_COMM_KEY_LEN];
    uint8_t payload[payloadlen];
    // need to retrieve the encrypted secret from chain first
    // and recover the group key
    if(decrypt_onchain_secret(communication_key, group_key) < 0)
    {  
        return ERROR_UNEXPECTED;
    }
    uint8_t test_communication_key[] = { 0xba, 0x8b, 0xa7, 0x1f, 0x6c, 0x76, 0xda, 0x0c, 0xf3, 0x24, 0xd6, 0x66, 0x3d, 0xc4, 0x80, 0x20};
    if(deconstruct_encrypted_payload(payload, test_communication_key, received_msg, round) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    if(round == 2 || round == 3)
    {
        // first get pubkey from somewhere, here its the client itself
        if(verify_signature(&g_client, payload, payloadlen) == false)
        {   
            return INVALID_MESSAGE;
        }
        if(verify_measurement(&g_client, payload, payloadlen, received_msg->A, g_hash_puf_measurement) == false)
        {
            return INVALID_MESSAGE;
        }
    }
    if(round == 1 || round == 2)
    {
        // obtain_shared_secret();
    }
    
    return SUCCESS;
}


ATTESTATION_STATUS construct_ra_message(const size_t round, janus_ra_msg_t* in_out_janus_msg)
{
    //uint8_t id[40] = {0};
    janus_ra_msg_t janus_msg;

    switch(round)
    {
        case JANUS_RA_R1: {
            if(construct_ra_challenge(&janus_msg, 1) < 0)
            {
                return ERROR_UNEXPECTED;
            }
            break;
        }
        case JANUS_RA_R2: {
            if(check_received_message(in_out_janus_msg, 1) != SUCCESS)
            {
                return INVALID_MESSAGE;
            }
            if(construct_ra_challenge(&janus_msg, 2)< 0)
            {
                return ERROR_UNEXPECTED;
            }
            break;
        }
        case JANUS_RA_R3: {
            if(check_received_message(in_out_janus_msg, 2) == SUCCESS)
            {
                return INVALID_MESSAGE;
            }
            if(construct_ra_challenge(&janus_msg, 3)< 0)
            {
                return ERROR_UNEXPECTED;
            }
            break;
        }
        default: {
            printf("JANUS: unsupported round in generate_la_msg: %zu!\n", round);
            return ERROR_UNEXPECTED;
        }
    }
    memcpy(in_out_janus_msg, &janus_msg, sizeof(*in_out_janus_msg));

    // dont forget to free janus_msg A and C somewhere

    return SUCCESS;
}

/* test function


uint8_t private_key[] = { 0xc2, 0xcd, 0xf0, 0xa8, 0xb0, 0xa8, 0x3b, 0x35, 0xac, 0xe5, 0x3f, 0x09, 0x7b, 0x5e, 0x6e, 0x6a, 0x0a, 0x1f, 0x2d, 0x40, 0x53, 0x5e, 0xff, 0x1c, 0xf4, 0x34, 0xf5, 0x2a, 0x43, 0xd5, 0x9d, 0x8f };
uint8_t personal_key[] = { 0xba, 0x8b, 0xa7, 0x1f, 0x6c, 0x76, 0xda, 0x0c, 0xf3, 0x24, 0xd6, 0x66, 0x3d, 0xc4, 0x80, 0x20};
struct RemoteAttestationClient client;
int role = IS_ATTESTER;

int init_session()
{
    uint8_t* priv = private_key;
    memcpy(client.personal_key, personal_key, JANUS_COMM_KEY_LEN);
    if(initClient(&client, IS_ATTESTER, priv) != SUCCESS)
    {
        return ERROR_UNEXPECTED;
    }
    return SUCCESS;
}

int main()
{   
    srand((unsigned int)time(NULL));
    init_session();
    janus_ra_msg_t janus_msg_r1, janus_msg_r2, janus_msg_r3;

    printf("---------- A1 C1 T1 ----------\n");
    construct_ra_challenge(&client, &janus_msg_r1, 1);
    printf("---------- end ----------\n\n");

    printf("---------- verify A1 C1 T1 ----------\n");
    if(check_received_message(&client, &janus_msg_r1, 1) == SUCCESS)
    {
        printf("verify r1 ok\n");
    }
    printf("---------- end ----------\n\n");

    free(janus_msg_r1.A);
    free(janus_msg_r1.C);


    printf("---------- A2 C2 T2 ----------\n");
    construct_ra_challenge(&client, &janus_msg_r2, 2);
    printf("---------- end ----------\n\n");

    printf("---------- verify A2 C2 T2 ----------\n");
    if(check_received_message(&client, &janus_msg_r2, 2) == SUCCESS)
    {
        printf("verify r2 ok\n");
    }
    printf("---------- end ----------\n\n");
    
    free(janus_msg_r2.A);
    free(janus_msg_r2.C);


    printf("---------- A3 C3 T3 ----------\n");
    construct_ra_challenge(&client, &janus_msg_r3, 3);
    printf("---------- end ----------\n\n");

    printf("---------- verify A3 C3 T3 ----------\n");
    if(check_received_message(&client, &janus_msg_r3, 3) == SUCCESS)
    {
        printf("verify r3 ok\n");
    }
    printf("---------- end ----------\n\n");
    
    free(janus_msg_r3.A);
    free(janus_msg_r3.C);
    return 0;
}
*/
