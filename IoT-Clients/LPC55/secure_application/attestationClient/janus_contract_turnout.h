#ifndef JANUS_CONTRACT_TURNOUT_H_
#define JANUS_CONTRACT_TURNOUT_H_

#include "janus_contract_util.h"
#include "janus_session.h"


int submit_device_condition(uint8_t* out, int cond_int);
void submit_attestation_state(uint8_t* out, uint8_t* aid);


#endif /* JANUS_CONTRACT_TURNOUT_H_ */
