#include "janus_session.h"
#include "janus_ns_api.h"
#include "fsl_debug_console.h"

extern struct RemoteAttestationClient client;
extern uint8_t g_hash_puf_measurement[MEASUREMENT_LEN];
extern uint8_t g_other_pubkey[PUBKEY_SERIAL_SIZE];
extern uint8_t g_other_personalkey[JANUS_COMM_KEY_LEN];

void init_janus_session()
{
    if(init_session() == SUCCESS)
    {
    	PRINTF("init done\r\n");
    }
}


void construct_janus_message_e(uint8_t* output, int round)
{
    janus_ra_msg_t out;
    if(construct_ra_challenge(&out, round) != SUCCESS)
    {
    	PRINTF("generate challeng wrong\n");
    }
    PRINTF("janus message len %d %d\r\n", out.alen, out.clen);
    // convert out to uint8 array
    output[0] = out.alen;
    output[1] = out.clen;

    check_received_message(&out, 1);

    size_t cur = 2;
    memcpy(output + cur, out.A, out.alen); cur += out.alen;
    for(int i = 0; i < out.alen; i++)
    {
    	PRINTF("%x ", out.A[i]);
    }
    PRINTF("\r\n");

    memcpy(output + cur, out.AN, ASCON_AEAD_NONCE_LEN); cur += ASCON_AEAD_NONCE_LEN;
    for(int i = 0; i < ASCON_AEAD_NONCE_LEN; i++)
	{
		PRINTF("%x ", out.AN[i]);
	}
	PRINTF("\r\n");
    memcpy(output + cur, out.C, out.clen); cur += out.clen;
    for(int i = 0; i < out.clen; i++)
	{
		PRINTF("%x ", out.C[i]);
	}
	PRINTF("\r\n");
    memcpy(output + cur, out.T, ASCON_AEAD_TAG_MIN_SECURE_LEN); cur += ASCON_AEAD_TAG_MIN_SECURE_LEN;

    for(int i = 0; i < ASCON_AEAD_TAG_MIN_SECURE_LEN; i++)
    {
		PRINTF("%x ", out.T[i]);
	}
    PRINTF("\r\n");
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
        PRINTF("verify message wrong\n");
        res = 1;
    }

    free(in.A);
    free(in.C);
    
    return res;
}

void set_materials_onchain_e(uint8_t *payload_fromchain, int payload_len)
{
	PRINTF("Accept %d bytes data from non secure application.\n", payload_len);
	size_t cur = 0;
	// payload = PUBLICKEY + HASHMEASURE + EncKey
	memcpy(g_other_pubkey, payload_fromchain + cur, PUBKEY_SERIAL_SIZE); cur += PUBKEY_SERIAL_SIZE;
	memcpy(g_hash_puf_measurement, payload_fromchain + cur, MEASUREMENT_LEN); cur += MEASUREMENT_LEN;
	memcpy(g_other_personalkey, payload_fromchain + cur, JANUS_COMM_KEY_LEN); cur += JANUS_COMM_KEY_LEN;

}
