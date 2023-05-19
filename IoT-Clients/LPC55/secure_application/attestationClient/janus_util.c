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
int calculate_hashed_measurement(uint8_t* out, const uint8_t* puf_measurement, const uint8_t* id, uint8_t pid)
{
    Sha256Context ctx;
    SHA256_HASH hash;

    Sha256Initialise(&ctx);
    Sha256Update(&ctx, puf_measurement, PUF_MEASUREMENT_LEN);
    Sha256Update(&ctx, id, JANUS_ID_LEN);
    Sha256Update(&ctx, &pid, 1);
    
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
    return (uint16_t)1470918308;
}

int generate_serialized_signature(uint8_t* msg_sig_buf, size_t message_len, struct RemoteAttestationClient* client)
{
    uint8_t signature_buffer[SIGNATURE_SIZE];
    uint8_t unsigned_message[SHA256_HASH_SIZE]; // at least 32 bytes
    memset(unsigned_message, 0, SHA256_HASH_SIZE);
    memcpy(unsigned_message, msg_sig_buf, message_len);

    secp256k1_ecdsa_signature signature;

	secp256k1_ecdsa_sign(client->ctx, &signature, unsigned_message, client->private_key, NULL, NULL);

    // serialize
	uint8_t der_of_signature[SIGNATURE_SIZE];
	secp256k1_ecdsa_signature_serialize_compact(client->ctx, der_of_signature, &signature);
    // append the serialized signature after the payload
    memcpy(msg_sig_buf + message_len, der_of_signature, SIGNATURE_SIZE);

    return SUCCESS;
}

bool verify_signature(struct RemoteAttestationClient* client, uint8_t* payload, size_t payloadlen)
{
    secp256k1_pubkey pubkey;
    int result = secp256k1_ec_pubkey_parse(client->ctx, &pubkey, client->public_key, SIG_PUBKEY_SIZE);
    // aprint(client->public_key, SIG_PUBKEY_SIZE, "public key");
    //result = secp256k1_ec_pubkey_parse(client->ctx, &public_key, client->public_key, length);

    size_t message_len = payloadlen - SIGNATURE_SIZE;
    uint8_t message[SHA256_HASH_SIZE];
    memset(message, 0, SHA256_HASH_SIZE);
    secp256k1_ecdsa_signature signature;
    memcpy(message, payload, message_len);

    if(secp256k1_ecdsa_signature_parse_compact(client->ctx, &signature, payload + message_len) == 0)
    {
        return false;
    }
    if(secp256k1_ecdsa_verify(client->ctx, &signature, message, &pubkey) == 0)
    {   
        return false;
    }
    return true;
}

bool verify_measurement(struct RemoteAttestationClient* client, const uint8_t* payload, size_t payloadlen, const uint8_t* A, const uint8_t* stored_meas)
{
    uint8_t cal_measurement[MEASUREMENT_LEN];
    if(calculate_hashed_measurement(cal_measurement, payload, A, A[JANUS_ID_LEN]) < 0)
    {
        return false;
    }
    bool res = memcmp(cal_measurement, stored_meas, MEASUREMENT_LEN) == 0;
    // printf("comp %d\n", res);
    return res;
}

int initClientSign(struct RemoteAttestationClient* client)
{
    uint8_t private_key[SIG_PRIVKEY_SIZE];
	strncpy((char*) private_key, (char*) client->private_key, SIG_PRIVKEY_SIZE);

	secp256k1_context *ctx = NULL;
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

	int result = secp256k1_ec_seckey_verify(ctx, private_key);

	printf("priv key valid: %d\n", result);

    // 先只管私钥签名, 公钥完了再说

	secp256k1_pubkey public_key;
	result = secp256k1_ec_pubkey_create(ctx, &public_key, private_key);

	uint8_t public_key_serialized[PUBKEY_SERIAL_SIZE];
	size_t length = sizeof(public_key);

	result = secp256k1_ec_pubkey_serialize(ctx, public_key_serialized, &length, &public_key, SECP256K1_EC_COMPRESSED);

	strncpy((char*) client->public_key, (char*) public_key_serialized, SIG_PUBKEY_SIZE);

	result = secp256k1_ec_pubkey_parse(client->ctx, &public_key, client->public_key, SIG_PUBKEY_SIZE);

	client->ctx = ctx;


	//client->address = assembleAddress(client->public_key, PUBLIC_KEY_SIZE);
    return SUCCESS;
}

int initClient(struct RemoteAttestationClient* client, int role, const uint8_t* priv_key)
{
    uint8_t cid[JANUS_ID_LEN];
    size_t cur = 0;

    client->role = role;
    client->private_key = priv_key;
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
    
    if(initClientSign(client) < 0)
    {
        return ERROR_UNEXPECTED;
    }
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

void set_onchain_material(uint8_t *data_fromchain)
{
    // deconstruct and get measurement, key, cert

    // then set different global variables

    // this function should be called before the message verification
}