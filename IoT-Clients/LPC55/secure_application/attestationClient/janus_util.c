#include "janus_util.h"

/*
generate nonce or random bytes array
*/

int generate_random_array(uint8_t* random, size_t random_len)
{
    for (int i = 0; i < random_len; i++)
    {
        random[i] = rand ();
    }
    return 0;
}

// int main()
// {
//     int random_len = 16;
//     uint8_t random[random_len];
//     generate_random(random, random_len);
//     for(int i = 0; i < random_len; i++)
//     {
//         printf("%02x ", random[i]);
//     }
//     printf("\n");
//     return 0;
// }

/*
verify the RM through calculating the hash output
H(RM || id || pid), pid is optional, id is aid or vid.
*/
int calculate_hashed_measurement(uint8_t* out, uint8_t* puf_measurement, uint8_t* id, uint8_t pid)
{
    Sha256Context ctx;
    SHA256_HASH hash;

    Sha256Initialise(&ctx);
    Sha256Update(&ctx, puf_measurement, MEASUREMENT_LEN);
    Sha256Update(&ctx, id, JANUS_ID_LEN);
    if(pid >= 0) // pid is valid
    {
        Sha256Update(&ctx, &pid, 1);
    }
    Sha256Finalise(&ctx, &hash);
    memcpy(out, hash.bytes, SHA256_HASH_SIZE);
    return 0;
}

// int main() // test function
// {
//     srand ((unsigned int) time (NULL));

//     int random_len = 32;
//     uint8_t random[random_len], id[ID_LEN], output[random_len];
//     generate_random_array(random, random_len);
//     generate_random_array(id, ID_LEN);
//     for(int i = 0; i < random_len; i++)
//     {
//         printf("%02x", random[i]);
//     }
//     printf("\n");

//     for(int i = 0; i < ID_LEN; i++)
//     {
//         printf("%02x", id[i]);
//     }
//     printf("\n");

//     calculate_hashed_measurement(output, random, id, 0);
//     for(int i = 0; i < random_len; i++)
//     {
//         printf("%02x", output[i]);
//     }
//     printf("\n");
//     // b6a558837172015cb1e9e88c95ca88906133e3d25d401b4cefed0f50990e45bc || 242d6f3e3ed2aecac4e0869bf8eb1ee07c2e73a010f3800d8b5d37bc28889253aad2e529d0bcb7d1 || 00 ==> 7556872ddb3addf91955731a3ea721d1cd54d5cbac58990f2af5c8bfc9391c27
//     return 0;
// }

/*
decrypt the secret key on chain
Enc_{Kg}(si)
Note that the "in" buffer is also the result, avoid additional memory allocation.
*/

int decrypt_onchain_secret(uint8_t* in, uint8_t* key)
{
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    AES_ECB_decrypt(&ctx, in);
    return 0;
}

uint16_t generate_timestamp()
{
    return 1470918308;
}

int sign_all()
{
    return 0;
}

bool verify_all()
{
    return true;
}

bool verify_measurement()
{
    return true;
}

int initClient(struct RemoteAttestationClient* client, int role)
{
    uint8_t cid[JANUS_ID_LEN];
    size_t cur = 0;

    client->role = role;
    if(role == IS_ATTESTER)
    {
        memcpy(client->id + cur, ATT_ADDRESS, SHA256_HASH_SIZE); cur += SHA256_HASH_SIZE;
        memcpy(client->id + cur, DSN, 4); cur += 4;
    }
    else
    {
        memcpy(client->id + cur, VRF_ADDRESS, SHA256_HASH_SIZE); cur += SHA256_HASH_SIZE;
        memcpy(client->id + cur, SPN, 4); cur += 4;
    }
    memcpy(client->id + cur, GROUP_ID, 4); cur += 4;
    return SUCCESS;
}

size_t get_A_buffer_len(bool with_nonce)
{
    size_t tssize = 2;
    size_t aux_len = JANUS_ID_LEN + tssize + 1;
    if(with_nonce)
    {
        aux_len += JANUS_NONCE_LEN;
    }
    return aux_len;
}

int A_message_buffering(uint8_t* buffer, const struct janus_msg_A* A, bool with_nonce)
{
    memcpy(buffer, A->id, JANUS_ID_LEN);
    buffer[JANUS_ID_LEN] = A->pid;
    memcpy(buffer + JANUS_ID_LEN + 1, &(A->timestamp), sizeof(A->timestamp));
    if(with_nonce)
    {
        memcpy(buffer + JANUS_ID_LEN + 1 + sizeof(A->timestamp), &(A->nonce), JANUS_NONCE_LEN);
    }
    return SUCCESS;
}