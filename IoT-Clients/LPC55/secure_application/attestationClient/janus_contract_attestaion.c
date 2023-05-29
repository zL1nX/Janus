#include "janus_contract_attestation.h"
#include "janus_attestation.pb-c.h"
#include "fsl_debug_console.h"
#include "aes.h"

extern struct RemoteAttestationClient g_client;
extern uint8_t g_hash_puf_measurement[PUF_MEASUREMENT_LEN];


char *ATT_FAMILY_NAME = "attestation";

uint8_t* construct_attestation_challenge(char* aid, int* size)
{
	uint8_t* chall = NULL;
	Challenge att_chall = CHALLENGE__INIT;
	char anonce[JANUS_NONCE_LEN];
	generate_random_array(anonce, JANUS_NONCE_LEN);

	att_chall.vid = "5678"; //g_client.id;
	att_chall.aid = aid;
	att_chall.nonce = anonce;

	size_t length = challenge__get_packed_size(&att_chall);
	chall = (uint8_t*)malloc(length);

	challenge__pack(&att_chall, chall);
	*size = length;

	PRINTF("attestation challenge size: %d\r\n", *size);

	for(int i = 0; i < length; i++)
	{
		PRINTF("%x ", chall[i]);
	}
	PRINTF("\r\n");

	return chall;
}

int submit_attestation_challenge(uint8_t* out, char* aid)
{
	int payload_size = 0, data_size = 0;
	uint8_t* pb_challenge = construct_attestation_challenge(aid, &payload_size);
	// submit pb_condition to chain
	char* tempid = "1234"; // aid
	char* add = assembleAddress(ATT_FAMILY_NAME, tempid, strlen(tempid));
	PRINTF("address: %s\r\n", add);
	char* addlist[] = {add};

	uint8_t* data = my_wrap_and_send(ATT_FAMILY_NAME, "submit_challenge", payload_size, pb_challenge, &data_size, 1, addlist, 1, addlist);
	PRINTF("attestation challenge out data: %d\r\n", data_size);
	for(int i = 0; i < data_size; i++)
	{
		out[i] = data[i];
		if(i <= 30) PRINTF("%x ", data[i]);
	}
	if(pb_challenge != NULL)
	{
		free(pb_challenge);
	}
	if(add != NULL)
	{
		free(add);
	}
	return data_size;
}

int generate_encrypted_meas_report(uint8_t* report, int report_size)
{
	struct AES_ctx ctx;
	memset(report, 0, report_size);

	generate_random_array(report, JANUS_NONCE_LEN);

	memcpy(report + JANUS_NONCE_LEN, g_hash_puf_measurement, PUF_MEASUREMENT_LEN); 
	generate_serialized_signature(report + JANUS_NONCE_LEN, PUF_MEASUREMENT_LEN, &g_client);

	uint8_t iv[AES_BLOCKLEN];
	generate_random_array(iv, AES_BLOCKLEN);

	AES_init_ctx_iv(&ctx, g_client.personal_key, iv);
	AES_CTR_xcrypt_buffer(&ctx, report, report_size);

	// PRINTF("encrypted report: ");
	// for(int i = 0; i < report_size; i++)
	// {
	// 	PRINTF("%x ", report[i]);
	// }
	// PRINTF("\r\n");

	return SUCCESS;
}

uint8_t* construct_attestation_report(int* size)
{
	uint8_t* report = NULL;
	Report att_report = REPORT__INIT;
	int report_size = JANUS_NONCE_LEN + PUF_MEASUREMENT_LEN + SIGNATURE_SIZE;
	uint8_t encrypted_report[report_size];
	
	att_report.aid = "1234"; // g_client.aid;

	if(generate_encrypted_meas_report(encrypted_report, report_size) != SUCCESS)
	{
		PRINTF("Something wrong generate_encrypted_meas_report\r\n");
	}

	att_report.payload = encrypted_report;

	size_t length = report__get_packed_size(&att_report);
	report = (uint8_t*)malloc(length);

	report__pack(&att_report, report);
	*size = length;

	// PRINTF("attestation report size: %d\r\n", *size);

	// for(int i = 0; i < length; i++)
	// {
	// 	PRINTF("%x ", report[i]);
	// }
	// PRINTF("\r\n");

	return report;
}

int submit_attestation_response(uint8_t* out)
{
	int payload_size = 0, data_size = 0;
	uint8_t* pb_response = construct_attestation_report(&payload_size);
	// submit pb_condition to chain
	char* tempid = "1234"; // aid
	char* add = assembleAddress(ATT_FAMILY_NAME, tempid, strlen(tempid));
	PRINTF("address: %s\r\n", add);
	char* addlist[] = {add};

	uint8_t* data = my_wrap_and_send(ATT_FAMILY_NAME, "submit_attestation_response", payload_size, pb_response, &data_size, 1, addlist, 1, addlist);
	PRINTF("attestation response out data: %d\r\n", data_size);
	for(int i = 0; i < data_size; i++)
	{
		out[i] = data[i];
		//if(i <= 30) PRINTF("%x ", data[i]);
	}
	if(pb_response != NULL)
	{
		free(pb_response);
	}
	if(add != NULL)
	{
		free(add);
	}
	return data_size;
}


uint8_t* construct_verification_request(int* size, char** aid_list)
{
	uint8_t* request = NULL;
	Verify verf_request = VERIFY__INIT;

	int list_len = sizeof(aid_list) / sizeof(aid_list[0]);
	char* list[list_len];
	for(int i = 0; i < list_len; i++)
	{
		list[i] = aid_list[i];
	}

	verf_request.vid = "5678"; //g_client.id;
	verf_request.aid = list;
	verf_request.n_aid = list_len; // len

	size_t length = verify__get_packed_size(&verf_request);
	request = (uint8_t*)malloc(length);

	verify__pack(&verf_request, request);
	*size = length;

	PRINTF("verify request size: %d\r\n", *size);

	for(int i = 0; i < length; i++)
	{
		PRINTF("%x ", request[i]);
	}
	PRINTF("\r\n");

	return request;
}

int submit_verification_request(uint8_t* out, char** aid_list)
{
	int payload_size = 0, data_size = 0;
	uint8_t* pb_request = construct_verification_request(&payload_size, aid_list);
	// submit pb_condition to chain
	char* tempid = "5678"; // vid
	char* add = assembleAddress(ATT_FAMILY_NAME, tempid, strlen(tempid));
	PRINTF("address: %s\r\n", add);
	char* addlist[] = {add};

	uint8_t* data = my_wrap_and_send(ATT_FAMILY_NAME, "submit_verification_request", payload_size, pb_request, &data_size, 1, addlist, 1, addlist);
	PRINTF("verification request out data: %d\r\n", data_size);
	for(int i = 0; i < data_size; i++)
	{
		out[i] = data[i];
		if(i <= 30) PRINTF("%x ", data[i]);
	}
	if(pb_request != NULL)
	{
		free(pb_request);
	}
	if(add != NULL)
	{
		free(add);
	}
	return data_size;
}

