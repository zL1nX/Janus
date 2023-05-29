#include "janus_contract_audit.h"
#include "janus_audit.pb-c.h"
#include "fsl_debug_console.h"

char* AUDIT_FAMILY_NAME = "audit";

uint8_t g_attester_ks[] = {0x75, 0xd5, 0x73, 0x97, 0x6a, 0x97, 0x7b, 0xa4, 0x5d, 0xf5, 0xa1, 0x7c, 0x9d, 0x9b, 0xc, 0x66};

uint8_t g_attester_kg[] = {0xe3, 0x5c, 0x71, 0x60, 0xec, 0x63, 0x85, 0xd1, 0x6f, 0xfb, 0x6d, 0x12, 0xe0, 0x27, 0x67, 0x8b};

const uint8_t g_attester_measurement[MEASUREMENT_LEN] = {0xf0, 0x5b, 0x5b, 0xd6, 0x60, 0xc5, 0x2e, 0x61, 0x96, 0x91, 0x50, 0xdb, 0x79, 0xcf, 0x5a, 0x88, 0x7d, 0xcb, 0x18, 0x7e, 0x04, 0xc7, 0xbb, 0xe5, 0x42, 0xf4, 0x61, 0x52, 0xbb, 0xb4, 0x8c, 0x2e};

uint8_t g_verifier_ks[] = {0xb5, 0xfb, 0xe2, 0x16, 0xe, 0x9a, 0x50, 0x75, 0x23, 0x81, 0x8e, 0x75, 0x35, 0x1f, 0x70, 0x76};

uint8_t g_verifier_kg[] = {0x27, 0x33, 0xcc, 0x6e, 0xf1, 0x45, 0xdd, 0x9d, 0x4f, 0xc7, 0xf, 0xbb, 0x95, 0xe4, 0xc4, 0xe7};

const uint8_t g_verifier_measurement[MEASUREMENT_LEN] = {0x45, 0x58, 0x71, 0x57, 0x31, 0xe2, 0x3b, 0xad, 0x3b, 0x8a, 0x45, 0x99, 0x49, 0x35, 0x06, 0xc2, 0x1a, 0xf7, 0xc6, 0x7c, 0x24, 0x81, 0x60, 0x11, 0x92, 0x69, 0xc5, 0xb1, 0xde, 0x4d, 0xeb, 0x26};

// Helper method to calculate credential
void calculate_credential(uint8_t* aid, uint8_t* vid, bool is_attester, uint8_t* out_cred) {
	uint8_t cred[SHA512_DIGEST_LENGTH] = {0};
	size_t inner_length = MEASUREMENT_LEN * 2 + strlen(aid) + strlen(vid) + 16;
	uint8_t* inner = malloc(inner_length);

	size_t offset = 0;
	memcpy(inner + offset, g_attester_measurement, MEASUREMENT_LEN);
	offset += MEASUREMENT_LEN;
	memcpy(inner + offset, g_verifier_measurement, MEASUREMENT_LEN);
	offset += MEASUREMENT_LEN;
	memcpy(inner + offset, aid, strlen(aid));
	offset += strlen(aid);
	memcpy(inner + offset, vid, strlen(vid));
	offset += strlen(vid);
	if (is_attester) {
		memcpy(inner + offset, g_verifier_ks, 16);
	} else {
		memcpy(inner + offset, g_attester_ks, 16);
	}
	hash512(inner, inner_length, cred);
	if (inner) {
		free(inner);
	}

	size_t outer_length = SHA512_DIGEST_LENGTH + 16;
	uint8_t* outer = malloc(outer_length);
	memcpy(outer, cred, SHA512_DIGEST_LENGTH);
	if (is_attester) {
		memcpy(outer + SHA512_DIGEST_LENGTH, g_attester_kg, 16);
	} else {
		memcpy(outer + SHA512_DIGEST_LENGTH, g_verifier_kg, 16);
	}
	hash512(outer, outer_length, cred);
	if (outer) {
		free(outer);
	}

	memcpy(out_cred, cred, SHA512_DIGEST_LENGTH);
}

uint8_t* construct_audit_credential(uint8_t* aid, uint8_t* vid, bool is_attester, int* size)
{
	uint8_t* cred = NULL;
	AuditCredential audit_cred = AUDIT_CREDENTIAL__INIT;

	uint8_t cred_calc[SHA512_DIGEST_LENGTH] = {0};
	calculate_credential(aid, vid, is_attester, cred_calc);

	PRINTF("credential: ");
	for(int i = 0; i < SHA512_DIGEST_LENGTH; i++)
	{
		PRINTF("%x ", cred_calc[i]);
	}
	PRINTF("\r\n");

	audit_cred.credential = (char*)cred_calc;
	audit_cred.aid = aid;
	audit_cred.vid = vid;

	size_t length = audit_credential__get_packed_size(&audit_cred);
	cred = (uint8_t*)malloc(length);

	audit_credential__pack(&audit_cred, cred);
	*size = length;

	return cred;
}

int submit_audit_credential(uint8_t* out, uint8_t* aid, uint8_t* vid, bool is_attester)
{
	int payload_size = 0, data_size = 0;
	uint8_t* pb_cred = construct_audit_credential(aid, vid, is_attester, &payload_size);

	// submit pb_cred to chain
	char* addr = assembleAddressFromPairs(AUDIT_FAMILY_NAME, "1234", "5678", 4);
	PRINTF("address: %s\r\n", addr);
	char* addlist[] = {addr};

	uint8_t* data = my_wrap_and_send(AUDIT_FAMILY_NAME, "submit_audit_credential", payload_size, pb_cred, &data_size, 1, addlist, 1, addlist);
	for(int i = 0; i < 30; i++)
	{
		out[i] = data[i];
		PRINTF("%x ", data[i]);
	}
	if(pb_cred != NULL)
	{
		free(pb_cred);
	}
	if(addr != NULL)
	{
		free(addr);
	}

	return data_size;
}

uint8_t* construct_audit_request(uint8_t* audit_id, uint8_t* aid, uint8_t* vid, int* size)
{
	uint8_t* req = NULL;
	AuditRequest audit_req = AUDIT_REQUEST__INIT;

	audit_req.audit_id = audit_id;
	audit_req.aid = aid;
	audit_req.vid = vid;

	size_t length = audit_request__get_packed_size(&audit_req);
	req = (uint8_t*)malloc(length);

	audit_request__pack(&audit_req, req);
	*size = length;

	return req;
}

int submit_audit_request(uint8_t* out, uint8_t* audit_id, uint8_t* aid, uint8_t* vid)
{
	int payload_size = 0, data_size = 0;
	uint8_t* pb_audit_req = construct_audit_request(audit_id, aid, vid, &payload_size);

	// submit pb_audit_req to chain
	char* input_address = assembleAddressFromPairs(AUDIT_FAMILY_NAME, aid, vid, strlen(aid));
	char* input_list[] = {input_address};
	char* output_address = assembleAddress(AUDIT_FAMILY_NAME, audit_id, strlen(audit_id));
	char* output_list[] = {output_address};

	PRINTF("input address: %s\r\n", input_address);
	PRINTF("output address: %s\r\n", output_address);


	uint8_t* data = my_wrap_and_send(AUDIT_FAMILY_NAME, "submit_audit_request", payload_size, pb_audit_req, &data_size, 1, input_list, 1, output_list);
	for(int i = 0; i < 30; i++)
	{
		out[i] = data[i];
		PRINTF("%x ", data[i]);
	}
	if(pb_audit_req != NULL)
	{
		free(pb_audit_req);
	}
	if(input_address != NULL)
	{
		free(input_address);
	}
	if(output_address != NULL)
	{
		free(output_address);
	}

	return data_size;
}
