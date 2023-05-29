#include "janus_contract_audit.h"
#include "janus_audit.pb-c.h"

char* AUDIT_FAMILY_NAME = "audit";

uint8_t* construct_audit_credentials(uint8_t* cr1, uint8_t* cr2, uint8_t* aid, uint8_t* vid, int* size)
{
	uint8_t* creds = NULL;
	Credentials audit_creds;

	audit_creds.credential1 = cr1;
	audit_creds.credential2 = cr2;
	audit_creds.aid = aid;
	audit_creds.vid = vid;

	size_t length = credentials__get_packed_size(&audit_creds);
	creds = (uint8_t*)malloc(length);

	credentials__pack(&audit_creds, creds);
	*size = length;

	return creds;
}

int submit_audit_credentials(uint8_t* out, uint8_t* cr1, uint8_t* cr2, uint8_t* aid, uint8_t* vid)
{
	int payload_size = 0, data_size = 0;
	uint8_t* pb_creds = construct_audit_credentials(cr1, cr2, aid, vid, &payload_size);

	// submit pb_creds to chain
	char* addr = assembleAddressFromPairs(AUDIT_FAMILY_NAME, aid, vid, strlen(aid));
	char* addlist[] = {addr};

	uint8_t* data = my_wrap_and_send(AUDIT_FAMILY_NAME, "submit_audit_credentials", payload_size, pb_creds, &data_size, 1, addlist, 1, addlist);
	for(int i = 0; i < 30; i++)
	{
		out[i] = data[i];
		PRINTF("%x ", data[i]);
	}
	if(pb_creds != NULL)
	{
		free(pb_creds);
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
	AuditRequest audit_req;

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
