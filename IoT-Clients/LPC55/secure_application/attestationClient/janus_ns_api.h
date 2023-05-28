#include "janus_remote_attestation.h"

void init_janus_session();
void construct_janus_message_e(uint8_t* output, int round);
int verify_janus_message_e(uint8_t *input, int inlen, int round);
void set_materials_onchain_e(uint8_t *payload_fromchain, int payload_len);
