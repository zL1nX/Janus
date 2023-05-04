#include "janus_datatype.h"


int generate_random_array(uint8_t* random, size_t random_len);
int calculate_hashed_measurement(uint8_t* out, uint8_t* puf_measurement, uint8_t* id, uint8_t pid);
int decrypt_onchain_secret(uint8_t* in, uint8_t* key);
uint16_t generate_timestamp();
int initClient(struct RemoteAttestationClient* client, int role, const uint8_t* priv_key);
int generate_serialized_signature(uint8_t* msg_sig_buf, const size_t buf_start, size_t message_len, struct RemoteAttestationClient* client);