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

struct janus_msg_A {
    uint8_t aid[ID_LEN]; // 同上 (如果本地的话, 理论上可以只存uint8_t* (逃))
    uint16_t timestamp; // 需要确认下具体的cast长度
    uint8_t pid; // 一个byte够了
    uint8_t measurement[MEASUREMENT_LEN]; // 假设一串SHA256的measurement
    uint8_t nonce[JANUS_NONCE_LEN]; // 把一个random double给snprintf成一个char array
};

struct _janus_ra_msg  {
    struct janus_msg_A A;
    uint8_t C[2 * SIGNATURE_SIZE]; // maximum length is 16 + 16 + 64
    uint8_t T[ASCON_AEAD_TAG_MIN_SECURE_LEN]; //12 byte tag in AES-GCM
};

// TODO: 128 or 256 ?

int generate_random_array(uint8_t* random, size_t random_len);
int calculate_hashed_measurement(uint8_t* out, uint8_t* puf_measurement, uint8_t* id, uint8_t pid);
int decrypt_onchain_secret(uint8_t* in, uint8_t* key);