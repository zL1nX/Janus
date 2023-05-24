/*
 * janus_contract_util.h
 *
 *  Created on: 2023年5月23日
 *      Author: LoCCS-GoCE
 */

#ifndef JANUS_CONTRACT_UTIL_H_
#define JANUS_CONTRACT_UTIL_H_

#include "janus_util.h"
#include "cbor.h"
#include "utils.h"
#include "batch.pb-c.h"
#include "sha256.h"
#include "sha512.h"
//#include "secp256k1.h"
//#include "secp256k1_preallocated.h"

uint8_t * _wrap_and_send(char* name, char *action, int size, uint8_t *data, int n_input, char *input_address_list[], int n_output, char *output_address_list[]);
char* calculate_address(uint8_t* content);




#endif /* JANUS_CONTRACT_UTIL_H_ */
