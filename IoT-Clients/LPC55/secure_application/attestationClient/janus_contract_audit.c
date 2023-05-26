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

void submit_audit_credentials(uint8_t* out, uint8_t* cr1, uint8_t* cr2, uint8_t* aid, uint8_t* vid)
{
	int size = 0;
	uint8_t* pb_creds = construct_audit_credentials(cr1, cr2, aid, vid, &size);
	// submit pb_condition to chain
	char* address[] = {calculate_address_from_pairs(aid, vid)};
	out = _wrap_and_send(AUDIT_FAMILY_NAME, "submit_audit_credentials", size, pb_creds, 1, address, 1, address);
	if(pb_creds != NULL)
	{
		free(pb_creds);
	}
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

void submit_audit_request(uint8_t* out, uint8_t* audit_id, uint8_t* aid, uint8_t* vid)
{
	int size = 0;
	uint8_t* pb_audit_req = construct_audit_request(cr1, cr2, aid, vid, &size);
	// submit pb_condition to chain
	char* input_address[] = {calculate_address_from_pairs(aid, vid)};
	char* output_address[] = {calculate_address(audit_id)};
	out = _wrap_and_send(AUDIT_FAMILY_NAME, "submit_audit_credentials", size, pb_audit_req, 1, input_address, 1, output_address);
	if(pb_audit_req != NULL)
	{
		free(pb_audit_req);
	}
}