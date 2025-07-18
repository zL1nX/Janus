#ifndef JANUS_CONTRACT_AUDIT_H_
#define JANUS_CONTRACT_AUDIT_H_

#include "janus_contract_util.h"
#include "janus_session.h"


int submit_audit_credential(uint8_t* out, uint8_t* aid, uint8_t* vid, bool is_attester);
int submit_audit_request(uint8_t* out, uint8_t* audit_id, uint8_t* aid, uint8_t* vid);


#endif /* JANUS_CONTRACT_AUDIT_H_ */
