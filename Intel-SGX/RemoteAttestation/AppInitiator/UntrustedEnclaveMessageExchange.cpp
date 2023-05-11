/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "sgx_eid.h"
#include "error_codes.h"
#include "sgx_urts.h"
#include "UntrustedEnclaveMessageExchange.h"

#include "fifo_def.h"

#include "EnclaveInitiator_u.h"

#include <map>

ATTESTATION_STATUS round1_send(const janus_ra_msg_t* janus_msg1,
                               janus_ra_msg_t* janus_msg2, uint32_t* session_id) {
    FIFO_MSG *msgreq = NULL, *msgresp= NULL;
    FIFO_MSGBODY_REQ* msgbody;
    SESSION_MSG* msg_respbody = NULL;

    size_t reqsize, respsize;

    reqsize = sizeof(FIFO_MSG_HEADER) + sizeof(FIFO_MSGBODY_REQ) + sizeof(janus_ra_msg_t);

    msgreq = (FIFO_MSG *)malloc(reqsize);
    if (!msgreq)
    {
        return ERROR_OUT_OF_MEMORY;
    }
    memset(msgreq, 0, reqsize);

    msgreq->header.type = FIFO_JANUS_RA_R1;
    msgreq->header.size = sizeof(FIFO_MSGBODY_REQ) + sizeof(janus_ra_msg_t);

    msgbody = (FIFO_MSGBODY_REQ*)msgreq->msgbuf;
    msgbody->max_payload_size = sizeof(janus_ra_msg_t);
    msgbody->size = sizeof(janus_ra_msg_t);

    memcpy(msgbody->buf, janus_msg1, sizeof(janus_ra_msg_t));

    if (client_send_receive(msgreq, reqsize, &msgresp, &respsize) != 0) {
        printf("fail to send and receive message.\n");
        return INVALID_SESSION;
    }

    msg_respbody = (SESSION_MSG*)msgresp->msgbuf;
    memcpy(janus_msg2, &msg_respbody->janus_msg, sizeof(janus_ra_msg_t));

    *session_id = msg_respbody->sessionid;
        free(msgresp);

    return (ATTESTATION_STATUS)0;
}

ATTESTATION_STATUS round3_send(const janus_ra_msg_t* janus_msg3, uint32_t session_id) {
    FIFO_MSG* msg3 = NULL, *msg4 = NULL;
    FIFO_MSG_HEADER * msg3_header = NULL;
    SESSION_MSG *msg3_body = NULL;
    size_t msg3size, msg4size;

    msg3size = sizeof(FIFO_MSG_HEADER) + sizeof(SESSION_MSG);
    msg3 = (FIFO_MSG *)malloc(msg3size);
    if (!msg3)
    {
        return ERROR_OUT_OF_MEMORY;
    }
    memset(msg3, 0, msg3size);

    msg3_header = (FIFO_MSG_HEADER *)msg3;
    msg3_header->type = FIFO_JANUS_RA_R3;
    msg3_header->size = sizeof(SESSION_MSG);

    msg3_body = (SESSION_MSG*)msg3->msgbuf;
    memcpy(&msg3_body->janus_msg, janus_msg3, sizeof(janus_ra_msg_t));
    msg3_body->sessionid = session_id;

    if (client_send_receive(msg3, msg3size, &msg4, &msg4size) != 0) {
        free(msg3);
        printf("failed to send and receive message.\n");
        return INVALID_SESSION;
    }

    free(msg3);

    return (ATTESTATION_STATUS)0;
}

/* Function Description: this is send interface for initiator enclave to close secure session
 * Parameter Description:
 *      [input] session_id: this is session id allocated by responder enclave
 * */
ATTESTATION_STATUS end_session_send(uint32_t session_id) {
    FIFO_MSG *msgresp = NULL;
    FIFO_MSG *closemsg;
    SESSION_CLOSE_REQ * body;
    size_t reqsize, respsize;

    reqsize = sizeof(FIFO_MSG) + sizeof(SESSION_CLOSE_REQ);
    closemsg = (FIFO_MSG *)malloc(reqsize);
    if (!closemsg)
    {
        return ERROR_OUT_OF_MEMORY;
    }
    memset(closemsg, 0,reqsize);

    closemsg->header.type = FIFO_JANUS_CLOSE_REQ;
    closemsg->header.size = sizeof(SESSION_CLOSE_REQ);

    body = (SESSION_CLOSE_REQ *)closemsg->msgbuf;
    body->session_id = session_id;

    if (client_send_receive(closemsg, reqsize, &msgresp, &respsize) != 0)
    {
        free(closemsg);
        printf("fail to send and receive message.\n");
        return INVALID_SESSION;
    }

    free(closemsg);
    free(msgresp);

    return (ATTESTATION_STATUS)0;
}

ATTESTATION_STATUS test_create_session(sgx_enclave_id_t initiator_enclave_id) {
    ATTESTATION_STATUS ret = SUCCESS;
    janus_ra_msg_t msg1 = {0};
    janus_ra_msg_t msg2 = {0};
    janus_ra_msg_t msg3 = {0};
    uint32_t ret_status;
    uint32_t session_id;

    sgx_status_t status = init_session(initiator_enclave_id, &ret_status);
    if (status == SGX_SUCCESS) {
        if ((ATTESTATION_STATUS)ret_status != SUCCESS)
            return ((ATTESTATION_STATUS)ret_status);
    }
    else {
        return ATTESTATION_SE_ERROR;
    }

    status = construct_ra_challenge(initiator_enclave_id, &ret_status, &msg1, JANUS_RA_R1);
    if (status == SGX_SUCCESS) {
        if ((ATTESTATION_STATUS)ret_status != SUCCESS)
            return ((ATTESTATION_STATUS)ret_status);
    }
    else {
        return ATTESTATION_SE_ERROR;
    }

    ret = round1_send(&msg1, &msg2, &session_id);
    if (ret != SUCCESS)
        return ret;

    status = check_received_message(initiator_enclave_id, &ret_status, &msg2, JANUS_RA_R2);
    if (status == SGX_SUCCESS) {
        if ((ATTESTATION_STATUS)ret_status != SUCCESS)
            return ((ATTESTATION_STATUS)ret_status);
    }
    else {
        return ATTESTATION_SE_ERROR;
    }

    status = construct_ra_challenge(initiator_enclave_id, &ret_status, &msg3, JANUS_RA_R3);
    if (status == SGX_SUCCESS) {
        if ((ATTESTATION_STATUS)ret_status != SUCCESS)
            return ((ATTESTATION_STATUS)ret_status);
    }
    else {
        return ATTESTATION_SE_ERROR;
    }

    ret = round3_send(&msg3, session_id);
    if (ret != SUCCESS)
        return ret;

    return ret;
}
