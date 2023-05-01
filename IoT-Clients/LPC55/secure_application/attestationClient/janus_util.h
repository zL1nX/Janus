#include "janus_datatype.h"


int generate_random_array(uint8_t* random, size_t random_len);
int calculate_hashed_measurement(uint8_t* out, uint8_t* puf_measurement, uint8_t* id, uint8_t pid);
int decrypt_onchain_secret(uint8_t* in, uint8_t* key);
uint64_t generate_timestamp();