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
#ifndef _FIFO_DEF_H_
#define _FIFO_DEF_H_

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "sgx_eid.h"
#include "sgx_dh.h"
#include "janus_session_protocol.h"

typedef enum {
    FIFO_JANUS_LA_R1,
    FIFO_JANUS_LA_R2,
    FIFO_JANUS_LA_R3,
    FIFO_JANUS_CLOSE_REQ,
    FIFO_JANUS_CLOSE_RESP
} FIFO_MSG_TYPE;

typedef struct _fifomsgheader {
    FIFO_MSG_TYPE type;
    size_t size; // demonstrate FIFO message content size
    int sockfd;
} FIFO_MSG_HEADER;

typedef struct _fifomsg {
    FIFO_MSG_HEADER header;
    unsigned char msgbuf[1];
} FIFO_MSG;

typedef struct _session_close {
    uint32_t session_id;
} SESSION_CLOSE_REQ;

typedef struct _session_msg {
    uint32_t sessionid;   // responder create a session ID and input here
    janus_la_msg_t janus_msg; // responder returns JANUS msg
} SESSION_MSG;

typedef struct _fifo_msg_req {
    uint32_t session_id;
    size_t max_payload_size;
    size_t size;
    unsigned char buf[1];
} FIFO_MSGBODY_REQ;

#ifdef __cplusplus
extern "C" {
#endif

int client_send_receive(FIFO_MSG *fiforequest, size_t fiforequest_size, FIFO_MSG **fiforesponse, size_t *fiforesponse_size);

#ifdef __cplusplus
}
#endif

#endif
