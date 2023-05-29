#include "janus_contract_turnout.h"
#include "janus_turnout.pb-c.h"
#include "fsl_debug_console.h"

#include <time.h>

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

//	PRINTF("condition size: %d\r\n", *size);
//	for(int i = 0; i < length; i++)
//	{
//		PRINTF("%x ", condition[i]);
//	}
//	PRINTF("\r\n");
	return condition;
}


uint8_t* construct_attestation_state(char* aid, int* size, int st_int)
{
	uint8_t* state = NULL;
	AttestationState att_state = ATTESTATION_STATE__INIT;

	att_state.vid = "5678"; //g_client.id;
	att_state.aid = aid;
	att_state.attestation_state = st_int;

	size_t length = attestation_state__get_packed_size(&att_state);
	state = (uint8_t*)malloc(length);

	attestation_state__pack(&att_state, state);
	*size = length;

	PRINTF("attestation state size: %d\r\n", *size);

	for(int i = 0; i < length; i++)
	{
		PRINTF("%x ", state[i]);
	}
	PRINTF("\r\n");

	return state;
}

int submit_device_condition(uint8_t* out, int cond_int)
{
	KIN1_InitCycleCounter(); /* enable DWT hardware */
    KIN1_ResetCycleCounter(); /* reset cycle counter */
    KIN1_EnableCycleCounter(); /* start counting */

	int payload_size = 0, data_size = 0;
	uint8_t* pb_condition = construct_device_condition(&payload_size, cond_int);

	uint32_t cycles = KIN1_GetCycleCounter(); /* get cycle counter */
	PRINTF("Cycles: %d, Elapsed Time: %.5f\r\n", cycles, (double) cycles/ DEVICE_FREQUENCY);

	// submit pb_condition to chain
	char* tempid = "1234condition";
	char* add = assembleAddress(TURNOUT_FAMILY_NAME, tempid, strlen(tempid));
	//PRINTF("%address: %s\r\n", add);
	char* addlist[] = {add};
	
	uint8_t* data = my_wrap_and_send(TURNOUT_FAMILY_NAME, "change_device_condition", payload_size, pb_condition, &data_size, 1, addlist, 1, addlist);
	PRINTF("device condition out data: %d\r\n", data_size);

	cycles = KIN1_GetCycleCounter(); /* get cycle counter */
    KIN1_DisableCycleCounter(); /* disable counting if not used any more */
    PRINTF("Cycles: %d, Elapsed Time: %.5f\r\n", cycles, (double) cycles/ DEVICE_FREQUENCY);

	for(int i = 0; i < data_size; i++)
	{
		out[i] = data[i];
		//if(i <= 30) PRINTF("%x ", data[i]);
	}
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



int submit_attestation_state(uint8_t* out, char* aid, int cond_int)
{

	int payload_size = 0, data_size = 0;
	uint8_t* pb_state = construct_attestation_state(aid, &payload_size, cond_int);
	// submit pb_condition to chain
	
	char* tempid = "1234state";
	char* add = assembleAddress(TURNOUT_FAMILY_NAME, tempid, strlen(tempid));
	PRINTF("%address: %s\r\n", add);
	char* addlist[] = {add};

	uint8_t* data = my_wrap_and_send(TURNOUT_FAMILY_NAME, "set_attestation_state", payload_size, pb_state, &data_size, 1, addlist, 1, addlist);
	PRINTF("attestation out data: %d\r\n", data_size);

	for(int i = 0; i < data_size; i++)
	{
		out[i] = data[i];
		if(i <= 30) PRINTF("%x ", data[i]);
	}
	PRINTF("\r\n");
	if(pb_state != NULL)
	{
		free(pb_state);
	}
	if(add != NULL)
	{
		free(add);
	}
	return data_size;
}
//
//
//
//
