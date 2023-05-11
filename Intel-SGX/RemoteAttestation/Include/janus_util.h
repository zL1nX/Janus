#include "janus_datatype.h"

int generate_random_array(uint8_t* random, size_t random_len);
int calculate_hashed_measurement(uint8_t* out, const uint8_t* puf_measurement, const uint8_t* id, uint8_t pid);
int decrypt_onchain_secret(uint8_t* in, uint8_t* key);
uint16_t generate_timestamp();
int initClient(struct RemoteAttestationClient* client, int role, const uint8_t* priv_key);
int generate_serialized_signature(uint8_t* msg_sig_buf, size_t message_len, struct RemoteAttestationClient* client);
size_t get_A_buffer_len(bool with_nonce);
int A_message_buffering(uint8_t* buffer, const struct janus_msg_A* A, bool with_nonce);
bool verify_signature(struct RemoteAttestationClient* client, uint8_t* payload, size_t payloadlen);
bool verify_measurement(struct RemoteAttestationClient* client, const uint8_t* payload, size_t payloadlen, const uint8_t* A, const uint8_t* g_measurement);
