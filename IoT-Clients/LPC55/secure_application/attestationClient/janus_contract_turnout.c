#include "janus_contract_turnout.h"
#include "janus_turnout.pb-c.h"

extern struct RemoteAttestationClient g_client;

char* TURNOUR_FAMILY_NAME = "turnout";



uint8_t* construct_device_condition(int* size, int cond_int)
{
	uint8_t* condition = NULL;
	DeviceCondition device_condition;

	device_condition.aid = g_client.id;
	device_condition.device_condition = cond_int;

	size_t length = device_condition__get_packed_size(&device_condition);
	condition = (uint8_t*)malloc(length);

	device_condition__pack(&device_condition, condition);
	*size = length;

	return condition;
}

int submit_device_condition(uint8_t* out, int cond_int)
{
	int size = 0;
	uint8_t* pb_condition = construct_device_condition(&size, cond_int);
	// submit pb_condition to chain
	char* address[] = {calculate_address("condition")};
	out = _wrap_and_send(TURNOUR_FAMILY_NAME, "change_device_condition", size, pb_condition, 1, address, 1, address);
	if(pb_condition != NULL)
	{
		free(pb_condition);
	}
	return size;
}

uint8_t* construct_attestation_state(uint8_t* aid, int* size)
{
	uint8_t* state = NULL;
	AttestationState att_state;

	att_state.vid = g_client.id;
	att_state.aid = aid;
	att_state.attestation_state = ON_CHAIN_ATTEST;

	size_t length = attestation_state__get_packed_size(&att_state);
	state = (uint8_t*)malloc(length);

	attestation_state__pack(&att_state, state);
	*size = length;

	return state;
}


void submit_attestation_state(uint8_t* out, uint8_t* aid)
{
	int size = 0;
	uint8_t* pb_state = construct_attestation_state(aid, &size);
	// submit pb_condition to chain
	char* address[] = {calculate_address("state")};
	out = _wrap_and_send(TURNOUR_FAMILY_NAME, "set_attestation_state", size, pb_state, 1, address, 1, address);
	if(pb_state != NULL)
	{
		free(pb_state);
	}
}




