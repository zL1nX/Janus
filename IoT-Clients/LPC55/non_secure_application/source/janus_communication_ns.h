#include "veneer_table.h"

#define HASH_MEASUREMENT_LEN 32
#define PUF_MEASUREMENT_LEN 16
#define HASH_PUF_MEASUREMENT_LEN 32

#define JANUS_COMMKEY_LEN 16
#define SIGNATURE_SIZE 64
#define ASCON_TAG 16
#define ASCON_NONCE 16

#define JANUS_IDLEN 40
#define JANUS_NONCE_LEN 8

#define A1_LEN JANUS_IDLEN + 1 + 2 + JANUS_NONCE_LEN
#define A2_LEN JANUS_IDLEN + 1 + 2 + JANUS_NONCE_LEN
#define A3_LEN JANUS_IDLEN + 1 + 2

#define JANUS_R1_MSG_LEN 2 + A1_LEN + ASCON_TAG + ASCON_NONCE + 2 * JANUS_COMMKEY_LEN
#define JANUS_R2_MSG_LEN 2 + A2_LEN + ASCON_TAG + ASCON_NONCE + JANUS_COMMKEY_LEN + PUF_MEASUREMENT_LEN + SIGNATURE_SIZE
#define JANUS_R3_MSG_LEN 2 + A3_LEN + ASCON_TAG + ASCON_NONCE + HASH_MEASUREMENT_LEN + SIGNATURE_SIZE  // 这块第三轮的长度在secure里没对应, 完了需要对应一下


void janus_round_one_send(int sock);
void janus_round_two_recv(int sock);
void janus_round_three_send(int sock);