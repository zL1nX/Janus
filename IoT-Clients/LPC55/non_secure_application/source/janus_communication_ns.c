#include "janus_communication_ns.h"
#include "network_communication.h"

void janus_round_one_send(int sock)
{
    int outlen = JANUS_R1_MSG_LEN, inlen = 0;
    uint8_t secure_out[outlen];
    memset(secure_out, 0, outlen);

    construct_janus_message(secure_out, 1);
    
    // send A1, C1, T1 through socket;
    // nonsecure_out = custom_alloc(outlen);
    // memcpy(nonsecure_out, outlen, secure_out);
    int sent = qcom_send(sock, secure_out, outlen, 0);
    configPRINTF(("TCP should sent %d bytes, actually sent % bytes\r\n", outlen, sent));
    // if(secure_out != NULL)
    // {
    //     custom_free(nonsecure_out);
    // }
    configPRINTF(("Janus Round 1 Successfully Sent.\r\n"));
}

void janus_round_two_recv(int sock)
{
    QCA_CONTEXT_STRUCT *enetCtx = wlan_get_context();
    if((A_STATUS)t_select(enetCtx, sock, 5000) == A_ERROR)
    {
        configPRINTF(("t_select wrong"));
    }
    uint8_t *nonsecure_in = NULL;
    int recvLen = qcom_recv(sock, nonsecure_in, 1024, 0);
    if (recvLen >= 0)
    {
        configPRINTF(("TCP receive %d bytes\r\n", recvLen));
    }
    
    if(recvLen != JANUS_R2_MSG_LEN || verify_janus_message(nonsecure_in, recvLen, 2) != 0)
    {
        configPRINTF(("Verify %d round message invalid\r\n", 2));
    }
    else
    {
        configPRINTF(("Janus %d round message valid\r\n", 2));
    }
    if (nonsecure_in != NULL)
    {
        zero_copy_free(nonsecure_in);
    }
}


void janus_round_three_send(int sock)
{

}