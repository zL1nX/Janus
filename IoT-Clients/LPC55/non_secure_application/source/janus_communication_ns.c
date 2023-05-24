#include "janus_communication_ns.h"
#include "network_communication.h"

void janus_round_one_send(int sock)
{
    int outlen = JANUS_R1_MSG_LEN, inlen = 0;
    uint8_t secure_out[outlen];
    char* nonsecure_out = NULL;
    memset(secure_out, 0, outlen);

    construct_janus_message(secure_out, 1);
    
    // send A1, C1, T1 through socket;
    nonsecure_out = custom_alloc(outlen);
    memcpy(nonsecure_out, secure_out, outlen);
    for(int i = 10; i < 20; i++)
    {
    	configPRINTF(("%x ", secure_out[i]));
    }
    configPRINTF(("\r\n"));

    int sent = qcom_send(sock, nonsecure_out, outlen, 0);
    configPRINTF(("TCP should sent %d bytes, actually sent %d bytes\r\n", outlen, sent));
	if(nonsecure_out != NULL)
	{
		custom_free(nonsecure_out);
	}
    configPRINTF(("Janus Round 1 Successfully Sent.\r\n"));
}

void janus_round_two_recv(int sock)
{
    QCA_CONTEXT_STRUCT *enetCtx = wlan_get_context();
    if((A_STATUS)t_select(enetCtx, sock, 5000) == A_ERROR)
    {
        configPRINTF(("t_select wrong"));
    }
    char *nonsecure_in = NULL;
    int recvLen = qcom_recv(sock, &nonsecure_in, 1024, 0);
    if (recvLen >= 0)
    {
        configPRINTF(("TCP receive %d bytes\r\n", recvLen));
    }
    
//    if(recvLen != JANUS_R2_MSG_LEN || verify_janus_message((uint8_t*)nonsecure_in, recvLen, 2) != 0)
//    {
//        configPRINTF(("Verify %d round message invalid\r\n", 2));
//    }
//    else
//    {
//        configPRINTF(("Janus %d round message valid\r\n", 2));
//    }
    if (nonsecure_in != NULL)
    {
        zero_copy_free(nonsecure_in);
    }
}


void janus_round_three_send(int sock)
{

}


int retrieve_data_from_chain()
{
	// calculate address to get url

	// http get raw json
	uint8_t* raw_json = NULL;
	size_t json_len = 0;
	const char* url_body = "/state/d8237565e86d7a1a709f3e40b4ff9f42e0f35c6b7da6a68ff70b004db1cfd66795d5b2";
	raw_json = http_get_from_chain(&json_len, "10.168.1.180", url_body, 8008, 5000);
	configPRINTF(("json len %d\r\n", json_len));

	// cjson parse
	uint8_t payload[128];
	size_t plen = 0;
	parse_json_from_chain(payload, &plen, raw_json);
	configPRINTF(("json data len %d\r\n", plen));
	if(raw_json != NULL)
	{
		custom_free(raw_json);
	}

	//  set onchain data to secure part
    set_materials_onchain(payload, plen);
}

void submit_data_to_chain(uint8_t* data_tochain, int send_len)
{
    const char* url_body = "/state/d8237565e86d7a1a709f3e40b4ff9f42e0f35c6b7da6a68ff70b004db1cfd66795d5b2";

    if(http_post_to_chain("10.168.1.180", url_body, 8008, 5000, data_tochain, send_len) == 0)
    {
        configPRINTF(("Send fail\r\n"));
    }
}

void janus_contract_client()
{
    uint8_t* out = NULL;
    
    int send_len = submit_device_condition_ns(out, ONLY_OFF_CHAIN);
    // 类似的换其他client函数

    // http_post
    if(out != NULL)
    {
        submit_data_to_chain(out, send_len);
    }
}