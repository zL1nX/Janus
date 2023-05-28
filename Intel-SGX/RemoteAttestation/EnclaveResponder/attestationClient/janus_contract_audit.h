#ifndef JANUS_CONTRACT_AUDIT_H_
#define JANUS_CONTRACT_AUDIT_H_

#include "janus_contract_util.h"

int submit_audit_credentials(uint8_t* out, uint8_t* cr1, uint8_t* cr2, uint8_t* aid, uint8_t* vid);
int submit_audit_request(uint8_t* out, uint8_t* audit_id, uint8_t* aid, uint8_t* vid);


#endif /* JANUS_CONTRACT_AUDIT_H_ */
