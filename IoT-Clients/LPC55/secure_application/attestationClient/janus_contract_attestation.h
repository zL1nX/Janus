/*
 * janus_contract_client.h
 *
 *  Created on: 2023年5月23日
 *      Author: LoCCS-GoCE
 */

#ifndef JANUS_CONTRACT_ATTESTATION_H_
#define JANUS_CONTRACT_ATTESTATION_H_

#include "janus_contract_util.h"
#include "janus_session.h"
#include "aes.h"

int submit_attestation_challenge(uint8_t* out, char* aid);
int submit_attestation_response(uint8_t* out);
int submit_verification_request(uint8_t* out, char** aid_list);

#endif /* JANUS_CONTRACT_ATTESTATION_H_ */
