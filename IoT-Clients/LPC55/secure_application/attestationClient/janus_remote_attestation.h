#include "janus_util.h"

int construct_A_message(struct janus_msg_A* A, const uint8_t* id, const uint8_t pid, bool with_nonce);
int construct_payload(uint8_t* payload, const size_t payload_len, const uint8_t* measurement, bool with_random);
int construct_CT_message(uint8_t* C, uint8_t* T, uint8_t* AN, const uint8_t* payload, const size_t payload_len, struct janus_msg_A* A, const uint8_t* commuication_key, bool with_nonce);