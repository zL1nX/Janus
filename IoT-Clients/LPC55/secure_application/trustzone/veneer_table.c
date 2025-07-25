/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if (__ARM_FEATURE_CMSE & 1) == 0
#error "Need ARMv8-M security extensions"
#elif (__ARM_FEATURE_CMSE & 2) == 0
#error "Compile with --cmse"
#endif

#include "stdint.h"
#include <stdbool.h>
#include "arm_cmse.h"
#include "veneer_table.h"
#include "fsl_debug_console.h"
#include "janus_ns_api.h"
#include "janus_contract_turnout.h"
#include "janus_contract_attestation.h"
#include "janus_contract_audit.h"
//#include "attrmgr.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define MAX_STRING_LENGTH 0x400
typedef int (*callbackptr_NS)(char const *s1, char const *s2) __attribute__((cmse_nonsecure_call));

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
extern uint32_t GetTestCaseNumber(void);

/*******************************************************************************
 * Code
 ******************************************************************************/
/* strnlen function implementation for arm compiler */
#if defined(__arm__)
size_t strnlen(const char *s, size_t maxLength)
{
    size_t length = 0;
    while ((length <= maxLength) && (*s))
    {
        s++;
        length++;
    }
    return length;
}
#endif

/* Non-secure callable (entry) function */
__attribute__((cmse_nonsecure_entry)) void DbgConsole_Printf_NSE(char const *s)
{
    size_t string_length;
    /* Access to non-secure memory from secure world has to be properly validated */
    /* Check whether string is properly terminated */
    string_length = strnlen(s, MAX_STRING_LENGTH);
    if ((string_length == MAX_STRING_LENGTH) && (s[string_length] != '\0'))
    {
        PRINTF("Input data error: String too long or invalid string termination!\r\n");
        while (1)
            ;
    }

    /* Check whether string is located in non-secure memory */
    if (cmse_check_address_range((void *)s, string_length, CMSE_NONSECURE | CMSE_MPU_READ) == NULL)
    {
        PRINTF("Input data error: String is not located in normal world!\r\n");
        while (1)
            ;
    }
    // PRINTF("Sent from normal world:\r\n");
    PRINTF(s);
}

/* Non-secure callable (entry) function, calling a non-secure callback function */
__attribute__((cmse_nonsecure_entry)) uint32_t StringCompare_NSE(volatile callbackptr callback,
                                                                 char const *s1,
                                                                 char const *s2)
{
    callbackptr_NS callback_NS;
    size_t string_length;
    uint32_t result;

    /* Input parameters check */
    /* Check whether function pointer is located in non-secure memory */
    callback_NS = (callbackptr_NS)cmse_nsfptr_create(callback);
    if (cmse_check_pointed_object((int *)callback_NS, CMSE_NONSECURE) == NULL)
    {
        PRINTF("Input data error: The callback is not located in normal world!\r\n");
        while (1)
            ;
    }
    /* Check whether string is properly terminated */
    string_length = strnlen(s1, MAX_STRING_LENGTH);
    if ((string_length == MAX_STRING_LENGTH) && (s1[string_length] != '\0'))
    {
        PRINTF("Input data error: First string too long or invalid string termination!\r\n");
        while (1)
            ;
    }
    /* Check whether string is properly terminated */
    string_length = strnlen(s2, MAX_STRING_LENGTH);
    if ((string_length == MAX_STRING_LENGTH) && (s2[string_length] != '\0'))
    {
        PRINTF("Input data error: Second string too long or invalid string termination!\r\n");
        while (1)
            ;
    }
    PRINTF("Comparing two string as a callback to normal world\r\n");
    PRINTF("String 1: ");
    PRINTF(s1);
    PRINTF("String 2: ");
    PRINTF(s2);
    result = callback_NS(s1, s2);
    return result;
}

// __attribute__((cmse_nonsecure_entry)) void trustQuerry(char *trustee,  char *s, int len) {

// 		trustQueryDirect(trustee, s, len);
// }
// __attribute__((cmse_nonsecure_entry)) void submitEvidenceVeneer(char *blockID, char  *output, int len) {

// 	submit_evidence(blockID,output,len);
// }
__attribute__((cmse_nonsecure_entry)) void checkRequest(char *s, int len) {

if (cmse_check_address_range((void *)s, len, CMSE_NONSECURE | CMSE_MPU_READ) == NULL)
	{
		PRINTF("Input data error: Output buffer is NOT located in normal world!\r\n");

	}
else{
		//checkRequests(s, len);
	}
}



__attribute__((cmse_nonsecure_entry)) void init_session_ns() {

	init_janus_session();
}

__attribute__((cmse_nonsecure_entry)) void construct_janus_message(uint8_t *output,  int round) {

	construct_janus_message_e(output, round);
}

__attribute__((cmse_nonsecure_entry)) int verify_janus_message(uint8_t *input, int inlen, int round) {

	return verify_janus_message_e(input, inlen, round);
}

__attribute__((cmse_nonsecure_entry)) void set_materials_onchain(uint8_t *input_fromchain, int payload_len) {

	set_materials_onchain_e(input_fromchain, payload_len);
}

__attribute__((cmse_nonsecure_entry)) int submit_device_condition_ns(uint8_t* out, int cond_int) {

	return submit_device_condition(out, cond_int);
}

__attribute__((cmse_nonsecure_entry)) int submit_attestation_state_ns(uint8_t* out, char* aid, int cond_int) {

	return submit_attestation_state(out, aid, cond_int);
}

__attribute__((cmse_nonsecure_entry)) int submit_attestation_challenge_ns(uint8_t* out, char* aid) {

	return submit_attestation_challenge(out, aid);
}

__attribute__((cmse_nonsecure_entry)) int submit_attestation_response_ns(uint8_t* out) {

	return submit_attestation_response(out);
}

__attribute__((cmse_nonsecure_entry)) int submit_verification_request_ns(uint8_t* out, char** aid_list) {

	return submit_verification_request(out, aid_list);
}


__attribute__((cmse_nonsecure_entry)) int submit_audit_request_ns(uint8_t* out, uint8_t* audit_id, uint8_t* aid, uint8_t* vid) {

	return submit_audit_request(out, audit_id, aid, vid);
}


__attribute__((cmse_nonsecure_entry)) int submit_audit_credential_ns(uint8_t* out, uint8_t* aid, uint8_t* vid, bool is_attester) {

	return submit_audit_credential(out, aid, vid, is_attester);
}
