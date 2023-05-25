#include "../Include/janus_util.h"

int construct_A_message(uint8_t* A, const uint8_t* id, const uint8_t pid, bool with_nonce);
int construct_payload(uint8_t* payload, const size_t payload_len, const uint8_t* measurement, bool with_random);
int construct_CT_message(uint8_t* C, uint8_t* T, uint8_t* AN, const uint8_t* payload, const size_t payload_len, const uint8_t* A, const size_t alen, const uint8_t* commuication_key, bool with_nonce);
int deconstruct_encrypted_payload(uint8_t* payload, const uint8_t* communication_key, janus_ra_msg_t* received_msg, int round);
int construct_ra_challenge(janus_ra_msg_t* janus_msg, int round);
int check_received_message(janus_ra_msg_t* received_msg, int round);
ATTESTATION_STATUS construct_ra_message(const size_t round, janus_ra_msg_t* in_out_janus_msg);
