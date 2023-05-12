#include "janus_remote_attestation.h"

// 测试命令 gcc ./utility/secp256k1.c hmac_sha256.c ascon_aead.c aes.c janus_util.c janus_remote_attestation.c test_main.c -o ./main && ./main

uint8_t private_key[] = { 0xc2, 0xcd, 0xf0, 0xa8, 0xb0, 0xa8, 0x3b, 0x35, 0xac, 0xe5, 0x3f, 0x09, 0x7b, 0x5e, 0x6e, 0x6a, 0x0a, 0x1f, 0x2d, 0x40, 0x53, 0x5e, 0xff, 0x1c, 0xf4, 0x34, 0xf5, 0x2a, 0x43, 0xd5, 0x9d, 0x8f };
uint8_t personal_key[] = { 0xba, 0x8b, 0xa7, 0x1f, 0x6c, 0x76, 0xda, 0x0c, 0xf3, 0x24, 0xd6, 0x66, 0x3d, 0xc4, 0x80, 0x20};
struct RemoteAttestationClient client;
int role = IS_ATTESTER;

int init_session()
{
    uint8_t* priv = private_key;
    memcpy(client.personal_key, personal_key, JANUS_COMM_KEY_LEN);
    if(initClient(&client, IS_ATTESTER, priv) != SUCCESS)
    {
        return ERROR_UNEXPECTED;
    }
    return SUCCESS;
}

int main()
{   
    srand((unsigned int)time(NULL));
    init_session();
    janus_ra_msg_t janus_msg_r1, janus_msg_r2, janus_msg_r3;

    printf("---------- A1 C1 T1 ----------\n");
    construct_ra_challenge(&client, &janus_msg_r1, 1);
    printf("---------- end ----------\n\n");

    printf("---------- verify A1 C1 T1 ----------\n");
    if(check_received_message(&client, &janus_msg_r1, 1) == SUCCESS)
    {
        printf("verify r1 ok\n");
    }
    printf("---------- end ----------\n\n");

    free(janus_msg_r1.A);
    free(janus_msg_r1.C);


    printf("---------- A2 C2 T2 ----------\n");
    construct_ra_challenge(&client, &janus_msg_r2, 2);
    printf("---------- end ----------\n\n");

    printf("---------- verify A2 C2 T2 ----------\n");
    if(check_received_message(&client, &janus_msg_r2, 2) == SUCCESS)
    {
        printf("verify r2 ok\n");
    }
    printf("---------- end ----------\n\n");
    
    free(janus_msg_r2.A);
    free(janus_msg_r2.C);


    printf("---------- A3 C3 T3 ----------\n");
    construct_ra_challenge(&client, &janus_msg_r3, 3);
    printf("---------- end ----------\n\n");

    printf("---------- verify A3 C3 T3 ----------\n");
    if(check_received_message(&client, &janus_msg_r3, 3) == SUCCESS)
    {
        printf("verify r3 ok\n");
    }
    printf("---------- end ----------\n\n");
    
    free(janus_msg_r3.A);
    free(janus_msg_r3.C);
    return 0;
}