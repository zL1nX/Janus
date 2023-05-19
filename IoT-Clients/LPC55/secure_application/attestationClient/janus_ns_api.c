#include "janus_session.h"
#include "janus_ns_api.h"

void init_janus_session()
{
    if(init_session() != SUCCESS)
    {
        printf("init wrong\n");
        exit(1);
    }
}


void construct_janus_message_e(uint8_t* output, int round)
{
    janus_ra_msg_t out;
    if(construct_ra_challenge(&out, round) != SUCCESS)
    {
        printf("generate challeng wrong\n");
        exit(1);
    }
    
    // convert out to uint8 array
    output[0] = out.alen;
    output[1] = out.clen;

    size_t cur = 2;
    memcpy(output + cur, out.A, out.alen); cur += out.alen;
    memcpy(output + cur, out.AN, ASCON_AEAD_NONCE_LEN); cur += ASCON_AEAD_NONCE_LEN;
    memcpy(output + cur, out.C, out.clen); cur += out.clen;
    memcpy(output + cur, out.T, ASCON_AEAD_TAG_MIN_SECURE_LEN); cur += ASCON_AEAD_TAG_MIN_SECURE_LEN;

}  

int verify_janus_message_e(uint8_t *input, int inlen, int round)
{
    // convert uin8_t input to janus message
    int alen = input[0], clen = input[1];
    janus_ra_msg_t in;
    in.A = (uint8_t*)malloc(alen);
    in.C = (uint8_t*)malloc(clen);

    int cur = 2;
    memcpy(in.A, input + cur, alen); cur += alen;
    memcpy(in.AN, input + cur, ASCON_AEAD_NONCE_LEN); cur += ASCON_AEAD_NONCE_LEN;
    memcpy(in.C, input + cur, clen); cur += clen;
    memcpy(in.T, input + cur, ASCON_AEAD_TAG_MIN_SECURE_LEN); cur += ASCON_AEAD_TAG_MIN_SECURE_LEN;

    int res = 0;
    if(check_received_message(&in, round) != SUCCESS)
    {
        printf("verify message wrong\n");
        res = 1;
    }

    free(in.A);
    free(in.C);
    
    return res;
}

void set_materials_onchain_e(uint8_t *data_fromchain)
{
    set_onchain_material(data_fromchain);
}