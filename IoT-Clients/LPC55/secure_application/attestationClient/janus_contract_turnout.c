#include "janus_contract_turnout.h"
#include "janus_turnout.pb-c.h"
#include "fsl_debug_console.h"

extern struct RemoteAttestationClient g_client;

char* TURNOUT_FAMILY_NAME = "turnout";


uint8_t* construct_device_condition(int* size, int cond_int)
{
	uint8_t* condition = NULL;
	DeviceCondition device_condition = DEVICE_CONDITION__INIT;

	device_condition.aid = "1234"; //g_client.id;
	device_condition.device_condition = cond_int;

	size_t length = device_condition__get_packed_size(&device_condition);
	condition = (uint8_t*)malloc(length);

	device_condition__pack(&device_condition, condition);
	*size = length;

	PRINTF("condition size: %d\r\n", *size);
	for(int i = 0; i < length; i++)
	{
		PRINTF("%x ", condition[i]);
	}
	PRINTF("\r\n");
	return condition;
}

int submit_device_condition(uint8_t* out, int cond_int)
{
	int payload_size = 0, data_size = 0;
	uint8_t* pb_condition = construct_device_condition(&payload_size, cond_int);
	// submit pb_condition to chain
	char* tempid = "1234condition";
	char* add = assembleAddress(TURNOUT_FAMILY_NAME, tempid, strlen(tempid));
	PRINTF("%address: %s\r\n", add);
	char* addlist[] = {add};

	uint8_t* data = my_wrap_and_send(TURNOUT_FAMILY_NAME, "change_device_condition", payload_size, pb_condition, &data_size, 1, addlist, 1, addlist);
	PRINTF("device condition out data: %d\r\n", data_size);
	for(int i = 0; i < 30; i++)
	{
		out[i] = data[i];
		PRINTF("%x ", data[i]);
	}
	PRINTF("\r\n");
	if(pb_condition != NULL)
	{
		free(pb_condition);
	}
	if(add != NULL)
	{
		free(add);
	}
	return data_size;
}


//
//uint8_t* construct_attestation_state(uint8_t* aid, int* size)
//{
//	uint8_t* state = NULL;
//	AttestationState att_state;
//
//	att_state.vid = g_client.id;
//	att_state.aid = aid;
//	att_state.attestation_state = ON_CHAIN_ATTEST;
//
//	size_t length = attestation_state__get_packed_size(&att_state);
//	state = (uint8_t*)malloc(length);
//
//	attestation_state__pack(&att_state, state);
//	*size = length;
//
//	return state;
//}
//
//
//void submit_attestation_state(uint8_t* out, uint8_t* aid)
//{
//	int size = 0;
//	uint8_t* pb_state = construct_attestation_state(aid, &size);
//	// submit pb_condition to chain
//	char* address[] = {calculate_address("state")};
//	out = _wrap_and_send(TURNOUR_FAMILY_NAME, "set_attestation_state", size, pb_state, 1, address, 1, address);
//	if(pb_state != NULL)
//	{
//		free(pb_state);
//	}
//}
//
//
//
//
