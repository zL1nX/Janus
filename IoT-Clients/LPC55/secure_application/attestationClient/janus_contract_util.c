#include "janus_contract_util.h"
#include "fsl_debug_console.h"

extern struct RemoteAttestationClient g_client;

// Hashing helper method
void hash512(uint8_t *data, size_t len, uint8_t *toString) {
	unsigned char hash[SHA512_DIGEST_LENGTH];
	SHA512(data, len, hash);
	memcpy(toString, hash, SHA512_DIGEST_LENGTH);
}

// Hashing helper method
// MAKE SURE LEN IS NOT SIZE OF CHAR BUT STRLEN OF CHAR
void hash256(uint8_t *data, size_t len, uint8_t *toString) {
	SHA256_CTX sha256;
	unsigned char hash[SHA256_BLOCK_SIZE];
	sha256_init(&sha256);
	sha256_update(&sha256, data, len);
	sha256_final(&sha256, hash);
	memcpy(toString, hash, SHA256_BLOCK_SIZE);
}

// Helper method for address assembly with current transaction family name
char* assembleAddress(const char* name, uint8_t *data, size_t size) {
	char *assembledAddress = malloc(sizeof(char) * 71);

	char hashoffamilyname[SHA512_DIGEST_LENGTH];
	hash512(name, strlen(name), hashoffamilyname);

	char *string_of_hashoffamilyname[SHA512_DIGEST_LENGTH * 2 + 1];
	int8_to_char(hashoffamilyname, SHA512_DIGEST_LENGTH, string_of_hashoffamilyname);

	char hashpublic_key[SHA512_DIGEST_LENGTH];
	hash512(data, size, hashpublic_key);

	char *string_of_hashpublic_key[SHA512_DIGEST_LENGTH * 2 + 1];
	int8_to_char(hashpublic_key, SHA512_DIGEST_LENGTH, string_of_hashpublic_key);

	strncpy(assembledAddress, string_of_hashoffamilyname, 6);
	strncat(assembledAddress, string_of_hashpublic_key, 64);

	assembledAddress[70] = '\0';

	return assembledAddress;
}

// Helper method for address assembly with current transaction family name
char* assembleAddressFromPairs(const char* name, uint8_t *elem1, uint8_t *elem2, size_t size) {
	char *assembledAddress = malloc(sizeof(char) * 71);

	char hashoffamilyname[SHA512_DIGEST_LENGTH];
	hash512(name, strlen(name), hashoffamilyname);

	char *string_of_hashoffamilyname[SHA512_DIGEST_LENGTH * 2 + 1];
	int8_to_char(hashoffamilyname, SHA512_DIGEST_LENGTH, string_of_hashoffamilyname);

	char hashelem1[SHA512_DIGEST_LENGTH];
	hash512(elem1, size, hashelem1);

	char *string_of_hashelem1[SHA512_DIGEST_LENGTH * 2 + 1];
	int8_to_char(hashelem1, SHA512_DIGEST_LENGTH, string_of_hashelem1);

	char hashelem2[SHA512_DIGEST_LENGTH];
	hash512(elem2, size, hashelem2);

	char *string_of_hashelem2[SHA512_DIGEST_LENGTH * 2 + 1];
	int8_to_char(hashelem2, SHA512_DIGEST_LENGTH, string_of_hashelem2);

	strncpy(assembledAddress, string_of_hashoffamilyname, 6);
	strncat(assembledAddress, string_of_hashelem1, 32);
	strncat(assembledAddress, string_of_hashelem2, 32);

	assembledAddress[70] = '\0';

	return assembledAddress;
}

uint8_t * my_wrap_and_send(char* name, char *action, int size, uint8_t *data, int* data_size, int n_input, char *input_address_list[], int n_output, char *output_address_list[]) {

	// +++CBOR of payload and actions
	cbor_item_t *root = cbor_new_definite_map(2);
	cbor_map_add(root, (struct cbor_pair ) { .key = cbor_move(cbor_build_string("Action")), .value = cbor_move(cbor_build_string(action)) });
	cbor_map_add(root, (struct cbor_pair ) { .key = cbor_move(cbor_build_string("Payload")), .value = cbor_move(cbor_build_bytestring(data, size)) });

	uint8_t *cborPayload;
	size_t cborBuffer_size;
	size_t cborLength = cbor_serialize_alloc(root, &cborPayload, &cborBuffer_size);
	// ===CBOR Done

	// +++Create a TransactionHeader.
	TransactionHeader transaction_header = TRANSACTION_HEADER__INIT;
	uint8_t *transaction_header_buffer;
	size_t transaction_header_length;

	char public_key_as_String[SIG_PUBKEY_SIZE * 2 + 1];
	int8_to_char(g_client.public_key, SIG_PUBKEY_SIZE, public_key_as_String);

	transaction_header.signer_public_key = public_key_as_String;
	transaction_header.family_name = name;
	transaction_header.family_version = "1.0";

	transaction_header.n_inputs = n_input;
	transaction_header.inputs = input_address_list;

	transaction_header.n_outputs = n_output;
	transaction_header.outputs = output_address_list;

	//char *dependencies[] = { };
	transaction_header.n_dependencies = 0;
	transaction_header.dependencies = NULL;

	char hash_of_transaction_header_payload[SHA512_DIGEST_LENGTH];
	hash512(cborPayload, cborLength, hash_of_transaction_header_payload);

	char string_of_hash_of_transaction_header_payload[SHA512_DIGEST_LENGTH * 2 + 1];
	int8_to_char(hash_of_transaction_header_payload, SHA512_DIGEST_LENGTH, string_of_hash_of_transaction_header_payload);

	transaction_header.payload_sha512 = string_of_hash_of_transaction_header_payload;

	transaction_header.batcher_public_key = public_key_as_String;

	srand(time(NULL));
	double nonce = (double) rand() / (double) RAND_MAX;
	char sNonce[21];
	snprintf(sNonce, 21, "%.18f", nonce);
	for(int i = 0; i < 21; i++)
	{
		PRINTF("%x", sNonce[i]);
	}
	PRINTF("\r\n");

	transaction_header.nonce = sNonce;

	transaction_header_length = transaction_header__get_packed_size(&transaction_header);
	transaction_header_buffer = malloc(transaction_header_length);
	transaction_header__pack(&transaction_header, transaction_header_buffer);

	// ===Transaction Header Done

	char *transaction_header_signature;

	// +++Create a Transaction from the header and payload above.
	Transaction transaction = TRANSACTION__INIT;
	uint8_t *transaction_buffer;
	size_t transaction_length;

	ProtobufCBinaryData transaction_transaction_header;
	transaction_transaction_header.data = transaction_header_buffer;
	transaction_transaction_header.len = transaction_header_length;

	ProtobufCBinaryData transaction_cborPayload;
	transaction_cborPayload.data = cborPayload;
	transaction_cborPayload.len = cborLength;

	transaction.header = transaction_transaction_header;
	transaction.payload = transaction_cborPayload;

	secp256k1_ecdsa_signature transaction_transaction_header_signature;
	uint8_t *hash_of_transaction_header = malloc(SHA256_HASH_SIZE);
	hash256(transaction_header_buffer, transaction_header_length, hash_of_transaction_header);
	secp256k1_ecdsa_sign(g_client.ctx, &transaction_transaction_header_signature, hash_of_transaction_header, g_client.private_key, NULL, NULL);

	uint8_t der_of_transaction_transaction_header_signature[SIGNATURE_SIZE];
	secp256k1_ecdsa_signature_serialize_compact(g_client.ctx, der_of_transaction_transaction_header_signature, &transaction_transaction_header_signature);

	char string_of_transaction_header_der_signature[SIGNATURE_SIZE * 2 + 1];
	int8_to_char(der_of_transaction_transaction_header_signature, SIGNATURE_SIZE, string_of_transaction_header_der_signature);
	transaction.header_signature = string_of_transaction_header_der_signature;

	transaction_header_signature = malloc(SIGNATURE_SIZE * 2 + 1);
	strncpy(transaction_header_signature, string_of_transaction_header_der_signature, SIGNATURE_SIZE * 2 + 1);

	transaction_length = transaction__get_packed_size(&transaction);
	transaction_buffer = malloc(transaction_length);
	transaction__pack(&transaction, transaction_buffer);
	// ===Transaction Done
	PRINTF("Transaction Done \r\n");

	// +++Create a BatchHeader from transaction_list above.
	BatchHeader batch_header = BATCH_HEADER__INIT;
	uint8_t *batch_header_buffer;
	size_t batch_header_length;

	batch_header.signer_public_key = public_key_as_String;

	Transaction *transactions;
	Transaction **transaction_list;
	transactions = &transaction;
	transaction_list = &transactions;
	char **transaction_ids_list;
	transaction_ids_list = &transaction_header_signature;

	batch_header.n_transaction_ids = 1;
	batch_header.transaction_ids = transaction_ids_list;

	batch_header_length = batch_header__get_packed_size(&batch_header);
	batch_header_buffer = malloc(batch_header_length + 200);
	batch_header__pack(&batch_header, batch_header_buffer);
	// ===Batch Header Done

	char *batch_header_signature;

	// +++Create Batch using the BatchHeader and transaction_list above.
	Batch batch = BATCH__INIT;
	uint8_t *batch_buffer;
	size_t batch_length;

	ProtobufCBinaryData batch_batch_header;
	batch_batch_header.data = batch_header_buffer;
	batch_batch_header.len = batch_header_length;

	secp256k1_ecdsa_signature batch_batch_header_signature;
	uint8_t *hash_of_batch_header = malloc(SHA256_HASH_SIZE);
	hash256(batch_header_buffer, batch_header_length, hash_of_batch_header);
	secp256k1_ecdsa_sign(g_client.ctx, &batch_batch_header_signature, hash_of_batch_header, g_client.private_key, NULL, NULL);

	uint8_t der_of_batch_batch_header_signature[SIGNATURE_SIZE];
	secp256k1_ecdsa_signature_serialize_compact(g_client.ctx, der_of_batch_batch_header_signature, &batch_batch_header_signature);

	batch.header = batch_batch_header;
	char string_of_batch_header_der_signature[SIGNATURE_SIZE * 2 + 1];
	int8_to_char(der_of_batch_batch_header_signature, SIGNATURE_SIZE, string_of_batch_header_der_signature);
	batch.header_signature = string_of_batch_header_der_signature;

	batch.n_transactions = 1;
	batch.transactions = transaction_list;

	batch_header_signature = malloc(SIGNATURE_SIZE * 2 + 1);
	strncpy(batch_header_signature, string_of_batch_header_der_signature, SIGNATURE_SIZE * 2 + 1);

	batch_length = batch__get_packed_size(&batch);
	batch_buffer = malloc(batch_length);
	batch__pack(&batch, batch_buffer);
	// ===Batch Done

	// +++Create a Batch List from Batch above

	BatchList batch_list = BATCH_LIST__INIT;
	uint8_t *batch_list_buffer;
	//uint8_t *batch_list_buffer;
	size_t batch_list_length;

	Batch *batche;
	Batch **batches;
	batche = &batch;
	batches = &batche;

	batch_list.n_batches = 1;
	batch_list.batches = batches;

	batch_list_length = batch_list__get_packed_size(&batch_list);
	batch_list_buffer = malloc(batch_list_length);
	batch_list__pack(&batch_list, batch_list_buffer);
	*data_size = batch_list_length;

	//printf("BatchList HEX: ");
	//println_hex(batch_list_buffer, batch_list_length);

	//PRINTF("BatchList: %s\r\n", batch_list_buffer);

	uint8_t *batch_id = batch_header_signature;

	free(hash_of_batch_header);
	free(hash_of_transaction_header);
	free(transaction_header_buffer);
	free(transaction_header_signature);
	free(transaction_buffer);
	free(batch_header_buffer);
	free(batch_header_signature);
	free(batch_buffer);
   // free(batch_list_buffer);
	cbor_decref(&root);
	//pb_ostream_t stream = pb_ostream_from_buffer(batch_list_buffer, sizeof(batch_list_buffer));
	//pb_encode(&stream, &batch_list__descriptor, &batch_list);
	PRINTF("Batch wrapping done\r\n");
	return batch_list_buffer;
}
