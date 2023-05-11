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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <map>
#include <sys/stat.h>
#include <sched.h>

#include "EnclaveResponder_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"

#include "cpdef.h"
#include "fifo_def.h"
#include "datatypes.h"

#include "CPTask.h"
#include "CPServer.h"

sgx_enclave_id_t e2_enclave_id = 0;

#define ENCLAVE_RESPONDER_NAME "libenclave_responder.signed.so"

/* Function Description: load responder enclave
 * */
int load_enclaves() {
    sgx_status_t ret = SGX_SUCCESS;
    sgx_launch_token_t token = {0};
    int update = 0;

    ret = sgx_create_enclave(ENCLAVE_RESPONDER_NAME, SGX_DEBUG_FLAG, &token, &update,
                             &e2_enclave_id, NULL);
    if (ret != SGX_SUCCESS)
    {
        printf("failed to load enclave %s, error code is 0x%x.\n", ENCLAVE_RESPONDER_NAME, ret);
        return -1;
    }

    return 0;
}

int process_round1(int clientfd, FIFO_MSGBODY_REQ *req_msg) {
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    FIFO_MSG * msgresp = NULL;
    SESSION_MSG session_msgresp = {0};
    size_t resp_message_size;

    if (!req_msg)
    {
        printf("invalid parameter.\n");
        return -1;
    }

    ret = check_received_message(e2_enclave_id, &status, (const janus_ra_msg_t*)req_msg->buf,
                                 JANUS_RA_R1);
    if (ret != SGX_SUCCESS)
    {
        printf("EnclaveResponder check_received_message error.\n");
        return -1;
    }

    janus_ra_msg_t janus_msg = {0};
    ret = construct_ra_challenge(e2_enclave_id, &status, &janus_msg, JANUS_RA_R2);
    if (ret != SGX_SUCCESS)
    {
        printf("EnclaveResponder construct_ra_challenge error.\n");
        return -1;
    }
    memcpy(&session_msgresp.janus_msg, &janus_msg, sizeof(janus_ra_msg_t));

    msgresp = (FIFO_MSG *)malloc(sizeof(FIFO_MSG) + sizeof(SESSION_MSG));
    if (!msgresp)
    {
        printf("memory allocation failure.\n");
        return -1;
    }
    memset(msgresp, 0, sizeof(FIFO_MSG) + sizeof(SESSION_MSG));

    msgresp->header.type = FIFO_JANUS_RA_R2;
    msgresp->header.size = sizeof(janus_ra_msg_t);
    memcpy(msgresp->msgbuf, &session_msgresp, sizeof(SESSION_MSG));

    if (send(clientfd, reinterpret_cast<char *>(msgresp),
             sizeof(FIFO_MSG) + static_cast<int>(sizeof(SESSION_MSG)), 0) == -1)
    {
        printf("server_send() failure.\n");
        free(msgresp);
        return -1;
    }
    free(msgresp);

    return 0;
}

int process_round3(int clientfd, SESSION_MSG* msg) {
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    FIFO_MSG * msgresp = NULL;
    SESSION_MSG session_msgresp = {0};
    size_t resp_message_size;

    if (!msg)
    {
        printf("invalid parameter.\n");
        return -1;
    }

    ret = check_received_message(e2_enclave_id, &status, (const janus_ra_msg_t*)&msg->janus_msg,
                                 JANUS_RA_R3);
    if (ret != SGX_SUCCESS)
    {
        printf("EnclaveResponder check_received_message error.\n");
        return -1;
    }

    return 0;
}

/* Function Description: This is process session close request from client
 * Parameter Description:
 *  [input] clientfd: this is client connection id
 *  [input] close_req: this is pointer to client's session close request
 * */
int process_close_req(int clientfd, SESSION_CLOSE_REQ * close_req) {
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    FIFO_MSG close_ack;

    if (!close_req)
        return -1;

    // call responder enclave to close this session
    // ret = end_session(e2_enclave_id, &status, close_req->session_id);
    if (ret != SGX_SUCCESS)
        return -1;

    // send back response
    close_ack.header.type = FIFO_JANUS_CLOSE_RESP;
    close_ack.header.size = 0;

    if (send(clientfd, reinterpret_cast<char *>(&close_ack), sizeof(FIFO_MSG), 0) == -1) {
        printf("server_send() failure.\n");
        return -1;
    }

    return 0;
}

void CPTask::run() {
    FIFO_MSG * message = NULL;
    sgx_launch_token_t token = {0};
    sgx_status_t status;
    int update = 0;
    uint32_t ret_status = 0;
    int test_ret = 0;

    // load responder enclave
    status = sgx_create_enclave(ENCLAVE_RESPONDER_NAME, SGX_DEBUG_FLAG, &token, &update,
                                &e2_enclave_id, NULL);
    if (status != SGX_SUCCESS) {
        printf("failed to load enclave %s, error code is 0x%x.\n", ENCLAVE_RESPONDER_NAME, status);
        return;
    }

    status = test_func(e2_enclave_id, &test_ret);
    if (status != SGX_SUCCESS) {
        printf("verifier test_func error.\n");
        return;
    }

    status = init_session(e2_enclave_id, &ret_status);
    if (status != SGX_SUCCESS) {
        printf("verifier init_session error.\n");
        return;
    }

    while (!isStopped()) {
        /* receive task frome queue */
        message  = m_queue.blockingPop();
        if (isStopped()) {
            free(message);
            break;
        }

        switch (message->header.type) {
            case FIFO_JANUS_RA_R1: {
                // process message transfer request
                int clientfd = message->header.sockfd;
                FIFO_MSGBODY_REQ *msg = NULL;

                msg = (FIFO_MSGBODY_REQ *)message->msgbuf;

                if (process_round1(clientfd, msg) != 0) {
                    printf("failed to process round 1 message transfer request.\n");
                    break;
                }
            }
            break;

            case FIFO_JANUS_RA_R3: {
                // process message transfer request
                int clientfd = message->header.sockfd;
                SESSION_MSG *msg = NULL;

                msg = (SESSION_MSG*)message->msgbuf;

                if (process_round3(clientfd, msg) != 0) {
                    printf("failed to process round 3 message transfer request.\n");
                    break;
                }
            }
            break;

            case FIFO_JANUS_CLOSE_REQ: {
                // process message close request
                int clientfd = message->header.sockfd;
                SESSION_CLOSE_REQ * closereq = NULL;

                closereq = (SESSION_CLOSE_REQ *)message->msgbuf;

                process_close_req(clientfd, closereq);

            }
            break;

            default: {
                printf("Unknown message.\n");
            }
            break;
        }

        free(message);
        message = NULL;
    }

    sgx_destroy_enclave(e2_enclave_id);
}

void CPTask::shutdown() {
    stop();
    m_queue.close();
    join();
}

void CPTask::puttask(FIFO_MSG* requestData) {
    if (isStopped()) {
        return;
    }

    m_queue.push(requestData);
}
