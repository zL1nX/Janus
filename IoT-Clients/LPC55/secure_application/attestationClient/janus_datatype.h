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
#define JANUS_ID_LEN 40
#define JANUS_NONCE_LEN  8
#define JANUS_COMM_KEY_LEN 16
#define MEASUREMENT_LEN  32
#define PUF_CHALLENGE_LEN 16
#define PUF_RESPONESE_LEN 16

#define IS_ATTESTER 0
#define IS_VERIFIER 1

#define ATT_ADDRESS "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
#define VRF_ADDRESS "8bb0cf6eb9b17d0f7d22b456f121257dc1254e1f01665370476383ea776df414"
#define DSN "0001"
#define SPN "0002"
#define GROUP_ID "0003"


// error code
#define SUCCESS 0x00
#define ERROR_UNEXPECTED 0xF1
#define GEN_RANDOM_ERROR 0xF2
#define INVALID_MESSAGE 0XF3


#define SIGNATURE_SIZE 64

typedef uint32_t ATTESTATION_STATUS;

typedef enum {
    JANUS_RA_R1,
    JANUS_RA_R2,
    JANUS_RA_R3
} JANUS_RA_ROUND;

struct RemoteAttestationClient {
    int role;
    uint8_t id[JANUS_ID_LEN];
    uint8_t personal_key[JANUS_COMM_KEY_LEN];
    uint8_t init_challenge[PUF_CHALLENGE_LEN];
    uint8_t session_key;
    uint8_t *private_key; // sk 这里完了再说
    uint8_t *public_key; // pk
};

struct janus_msg_A {
    uint8_t id[JANUS_ID_LEN]; // 同上 (如果本地的话, 理论上可以只存uint8_t* (逃))
    uint16_t timestamp; // 需要确认下具体的cast长度
    uint8_t pid; // 一个byte够了
    //uint8_t measurement[MEASUREMENT_LEN]; // 假设一串SHA256的measurement
    uint8_t nonce[JANUS_NONCE_LEN] ; // 把一个random double给snprintf成一个char array
};

typedef struct _janus_ra_msg  {
    struct janus_msg_A A;
    uint8_t T[ASCON_AEAD_TAG_MIN_SECURE_LEN]; // ASCON Tag
    uint8_t AN[ASCON_AEAD_NONCE_LEN]; // AEAD NONCE
    uint8_t C[]; // flexible array member, a legal operation in C99
} janus_ra_msg_t;

// TODO: 128 or 256 ?
