#ifndef _JANUS_SESSION_PROROCOL_H
#define _JANUS_SESSION_PROROCOL_H

#include "sgx_ecp_types.h"
#include "sgx_key.h"
#include "sgx_report.h"
#include "sgx_attributes.h"

#define HMAC_KEY_LEN     64
#define HMAC_TAG_LEN     32
#define MEASUREMENT_LEN  32
#define NONCE_LEN        20
#define SHA256_HASH_SIZE 32

typedef enum {
    JANUS_LA_R1,
    JANUS_LA_R2,
    JANUS_LA_R3
} JANUS_LA_ROUND;

struct janus_la_client {
    uint8_t address[32];
    uint8_t serialno[4];
    uint8_t groupid[4];
};

struct janus_msg_z {
    uint8_t aid[40]; // attester ID
    uint64_t timestamp;
    uint8_t pid; // PUF ID
    uint8_t measurement[MEASUREMENT_LEN];
    uint8_t nonce[NONCE_LEN];
};

typedef struct _janus_la_msg {
    struct janus_msg_z z;
    uint8_t t[HMAC_TAG_LEN] ; //32 byte SHA 256 output
} janus_la_msg_t;

//Session information structure
typedef struct _la_janus_session_t
{
    uint32_t  session_id; //Identifies the current session
    uint32_t  status; //Indicates session is in progress, active or closed
    union
    {
        struct
        {
            janus_la_msg_t janus_session;
        }in_progress;

        struct
        {
            sgx_key_128bit_t AEK; //Session Key
            uint32_t counter; //Used to store Message Sequence Number
        }active;
    };
} janus_session_t;


#endif
