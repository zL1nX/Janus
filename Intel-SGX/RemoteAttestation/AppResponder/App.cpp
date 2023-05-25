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


// App.cpp : Defines the entry point for the console application.
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <sys/types.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <signal.h>

#include "EnclaveResponder_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"

#include "fifo_def.h"
#include "datatypes.h"

#include "CPTask.h"
#include "CPServer.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>


#define UNUSED(val) (void)(val)
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str
#define scanf_s scanf
#define _tmain  main

#define PORT 18083

#define ENCLAVE_RESPONDER_NAME "libenclave_responder.signed.so"

sgx_enclave_id_t e2_enclave_id = 0;

CPTask * g_cptask = NULL;
CPServer * g_cpserver = NULL;

void signal_handler(int sig) {
    switch(sig)
    {
        case SIGINT:
        case SIGTERM:
        {
            if (g_cpserver)
                g_cpserver->shutDown();
        }
        break;
    default:
        break;
    }

    exit(1);
}

void cleanup() {
    if(g_cptask != NULL)
        delete g_cptask;
    if(g_cpserver != NULL)
        delete g_cpserver;
}

/* OCall functions */
void ocall_print_string(const char *str) {
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    sgx_status_t ret = SGX_SUCCESS;
    sgx_launch_token_t token = {0};
    int ret_status = 0;
    int update = 0;

    ret = sgx_create_enclave(ENCLAVE_RESPONDER_NAME, SGX_DEBUG_FLAG, &token, &update,
                             &e2_enclave_id, NULL);
    if (ret != SGX_SUCCESS)
    {
        printf("failed to load enclave %s, error code is 0x%x.\n", ENCLAVE_RESPONDER_NAME, ret);
        return -1;
    }

    ret = init_janus_session(e2_enclave_id);
    if (ret != SGX_SUCCESS) {
        printf("attester init_session error.\n");
        return -1;
    }

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    uint8_t buffer[1024] = {0};
    char *hello = "Hello from server";

    // Create a socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to a port and address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    // Accept an incoming connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept failed");
        exit(EXIT_FAILURE);
    }
    int recvlen = 0;
    // Receive data from the client
    if ((recvlen = recv(new_socket, buffer, 1024, 0)) < 0) {
        perror("recv failed");
        exit(EXIT_FAILURE);
    }
    //printf("Received message from client: %s\n", buffer);
    // 看下前20个字节,
    for(int i = 0; i < 20; i++)
    {
        printf("%x ", buffer[i]);
    }
    printf("\n");

    int alen = buffer[0], clen = buffer[1];
    janus_ra_msg_t in;
    in.A = (uint8_t*)malloc(alen);
    in.C = (uint8_t*)malloc(clen);

    int cur = 2;
    memcpy(in.A, buffer + cur, alen); cur += alen;
    memcpy(in.AN, buffer + cur, ASCON_AEAD_NONCE_LEN); cur += ASCON_AEAD_NONCE_LEN;
    memcpy(in.C, buffer + cur, clen); cur += clen;
    memcpy(in.T, buffer + cur, ASCON_AEAD_TAG_MIN_SECURE_LEN); cur += ASCON_AEAD_TAG_MIN_SECURE_LEN;

    ret = verify_janus_message(e2_enclave_id, &ret_status, &in, recvlen, 1);
    if (ret != SGX_SUCCESS) {
        printf("attester verify_janus_message error.\n");
        return -1;
    }

    printf("attester round 1 verify_janus_message done.\n");

    // Send a message to the client
    // if (send(new_socket, hello, strlen(hello), 0) < 0) {
    //     perror("send failed");
    //     exit(EXIT_FAILURE);
    // }
    // printf("Hello message sent to client\n");

    // Close the connection
    close(new_socket);
    close(server_fd);

    sgx_destroy_enclave(e2_enclave_id);

    return 0;

    // create server instance, it would listen on sockets and proceeds client's requests
    // g_cptask = new (std::nothrow) CPTask;
    // g_cpserver = new (std::nothrow) CPServer(g_cptask);

    // if (!g_cptask || !g_cpserver)
    //      return -1;

    // atexit(cleanup);

    // // register signal handler so to respond to user interception
    // signal(SIGINT, signal_handler);
    // signal(SIGTERM, signal_handler);

    // g_cptask->start();

    // if (g_cpserver->init() != 0)
    // {
    //      printf("fail to init server\n");
    // }else
    // {
    //      printf("Server is ON...\n");
    //      printf("Press Ctrl+C to exit...\n");
    //      g_cpserver->doWork();
    // }

    // return 0;
}
