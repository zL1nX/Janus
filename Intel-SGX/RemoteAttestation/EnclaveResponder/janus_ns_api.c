#include "janus_session.h"
#include "janus_ns_api.h"

void init_janus_session() {
    if(init_session() != SUCCESS)
    {
        ocall_print_string("init wrong\n");
        return;
    }
}


void construct_janus_message(uint8_t* output, int round) {
    janus_ra_msg_t out;
    if(construct_ra_challenge(&out, round) != SUCCESS)
    {
        ocall_print_string("generate challeng wrong\n");
        return;
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

int verify_janus_message(janus_ra_msg_t *input, int inlen, int round) {
    int res = 0;
    if(check_received_message(input, round) != SUCCESS)
    {
        ocall_print_string("verify message wrong\n");
        res = 1;
    }

    return res;
}

void set_materials_onchain(uint8_t *data_fromchain) {
    set_onchain_material(data_fromchain);
}
