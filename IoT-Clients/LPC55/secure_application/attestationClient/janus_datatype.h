#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ascon.h"
#include "hmac_sha256.h"
#include "aes.h"

// protocol relevant
#define ID_LEN 40
#define JANUS_NONCE_LEN  8
#define JANUS_COMM_KEY_LEN 16
#define MEASUREMENT_LEN  32


// error code
#define SUCCESS 0x00
#define ERROR_UNEXPECTED 0xF1
#define GEN_RANDOM_ERROR 0xF2


#define SIGNATURE_SIZE 64


struct janus_msg_A {
    uint8_t id[ID_LEN]; // 同上 (如果本地的话, 理论上可以只存uint8_t* (逃))
    uint16_t timestamp; // 需要确认下具体的cast长度
    uint8_t pid; // 一个byte够了
    //uint8_t measurement[MEASUREMENT_LEN]; // 假设一串SHA256的measurement
    uint8_t nonce[JANUS_NONCE_LEN] ; // 把一个random double给snprintf成一个char array
};

struct _janus_ra_msg  {
    struct janus_msg_A A;
    uint8_t T[ASCON_AEAD_TAG_MIN_SECURE_LEN]; //12 byte tag in AES-GCM
    uint8_t C[]; // flexible array member, a legal operation in C99
};

// TODO: 128 or 256 ?
