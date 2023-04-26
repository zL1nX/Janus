#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "janus_datatype.h"
#include "ascon.h"
#include "hmac_sha256.h"
#include "aes.h"

int generate_random_array(uint8_t* random, size_t random_len);
int calculate_hashed_measurement(uint8_t* out, uint8_t* puf_measurement, uint8_t* id, uint8_t pid);
int decrypt_onchain_secret(uint8_t* in, uint8_t* key);