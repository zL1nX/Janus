#include "network_communication.h"
#include "cJSON.h"
#include "b64.h"

const WIFINetworkParams_t pxNetworkParams = {
    .pcSSID           = clientcredentialWIFI_SSID,
    .ucSSIDLength     = sizeof(clientcredentialWIFI_SSID) - 1,
    .pcPassword       = clientcredentialWIFI_PASSWORD,
    .ucPasswordLength = sizeof(clientcredentialWIFI_PASSWORD) - 1,
    .xSecurity        = clientcredentialWIFI_SECURITY,
};

static uint32_t ipv4_str_to_uint32(const char* ip_str) {
    char ip_copy[16];
    strncpy(ip_copy, ip_str, 15);
    ip_copy[15] = '\0';

    uint32_t ip_uint32 = 0;
    int octet_count = 0;
    char* octet_str = strtok(ip_copy, ".");
    while (octet_str != NULL && octet_count < 4) {
        int octet = atoi(octet_str);
        if (octet < 0 || octet > 255) {
            exit(EXIT_FAILURE);
        }
        ip_uint32 = (ip_uint32 << 8) | octet;
        octet_str = strtok(NULL, ".");
        octet_count++;
    }
    if (octet_count != 4) {
        exit(EXIT_FAILURE);
    }
    return ip_uint32;
}

int socket_test(const char* ip, uint16_t port)
{
    int32_t sock = 0;
    SOCKADDR_T addr;
    A_STATUS status;
    char *hello = "Hello from LPC client";
    char *request_data = NULL;
    char *received_data = NULL;

    memset(&addr, 0, sizeof(addr));

    addr.sin_family = ATH_AF_INET;
    addr.sin_port = port;
    addr.sin_addr.s_addr = ipv4_str_to_uint32(ip);

    sock = qcom_socket(ATH_AF_INET, SOCK_STREAM_TYPE, 0);
    if (sock < 0)
    {
        configPRINTF(("isValueFailed\r\n"));
    }

    /* Connect to remote */
    status = (A_STATUS)qcom_connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if(status != A_OK)
    {
    	configPRINTF(("connect wrong\r\n"));
    }
    configPRINTF(("qcom_connect\r\n"));

    uint32_t hellosize = strlen(hello);
    request_data = custom_alloc(hellosize);
    memset(request_data, 0, hellosize);
    memcpy(request_data, hello, hellosize);

    int sent = qcom_send(sock, request_data, hellosize, 0);
    configPRINTF(("TCP sent %d bytes\r\n", sent));
    custom_free(request_data);

    QCA_CONTEXT_STRUCT *enetCtx = wlan_get_context();
    status = (A_STATUS)t_select(enetCtx, sock, 5000);
    if(status == A_ERROR)
        configPRINTF(("t_select wrong"));
    
    int recvLen = qcom_recv(sock, &received_data, 1024, 0);
    if (recvLen >= 0)
    {
    	received_data[recvLen] = 0;
        configPRINTF(("%s\r\n", received_data));
    }
    if (received_data != NULL)
    {
        zero_copy_free(received_data);
    }
    status = (A_STATUS)qcom_socket_close(sock);
    return 0;
}

int socket_init(const char* ip, uint16_t port)
{
    int32_t sock = 0;
    SOCKADDR_T addr;
    A_STATUS status;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = ATH_AF_INET;
    addr.sin_port = port;
    addr.sin_addr.s_addr = ipv4_str_to_uint32(ip);

    sock = qcom_socket(ATH_AF_INET, SOCK_STREAM_TYPE, 0);
    if (sock < 0)
    {
        configPRINTF(("isValueFailed\r\n"));
    }

    /* Connect to remote */
    status = (A_STATUS)qcom_connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if(status != A_OK)
    {
    	configPRINTF(("connect wrong\r\n"));
    }
    configPRINTF(("qcom_connect\r\n"));
    return sock;
}


uint32_t resolveHostname(const char *hostname)
{
    uint32_t addr = 0;

    // NOTE: This function returns the address in reverse byte order
    A_STATUS status = qcom_dnsc_get_host_by_name((char *)hostname, &addr);
    if (status == 0)
    {
        PRINTF("Looked up %s as %d.%d.%d.%d\r\n", hostname, UINT32_IPADDR_TO_CSV_BYTES(addr));
    }
    return addr;
}

static int isValueFailed(int32_t value, int32_t failValue, const char *funcName)
{
    return (value == failValue);
}


uint8_t* http_get_from_chain(size_t* outlen, const char *ip, const char* url_body, int port, int timeout)
{
    int32_t sock = 0;
    SOCKADDR_T addr;
    A_STATUS status;
    int request_len = 1024;
    char *request_data  = NULL;
    char *response_data = NULL;

    configPRINTF(("****************************************\r\n"));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = ATH_AF_INET;
    addr.sin_addr.s_addr = ipv4_str_to_uint32(ip);
    addr.sin_port = port; // sawtooth rest-api port

	/* Create TCP socket */
	sock = qcom_socket(ATH_AF_INET, SOCK_STREAM_TYPE, 0);
	if (isValueFailed(sock, -1, "qcom_socket"))
		return NULL;

	/* Connect to remote */
	status = (A_STATUS)qcom_connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (status != A_OK)
		return NULL;

	request_data = custom_alloc(request_len);
	assert(!(NULL == request_data));
	if (NULL == request_data)
		return NULL;
	memset(request_data, 0, request_len);

	/* Allocate request_data of size that includes extra '\0' for string functions */
	// 192.168.1.101, 8008, /state/address1234
	const char* request_fmt = "GET %s HTTP/1.1\r\n"
						  "Host: %s:%d\r\n"
						  "User-Agent: Mozilla/5.0\r\n"
						  "Accept: application/json\r\n"
						  "Connection: close\r\n\r\n";
	snprintf(request_data, request_len, request_fmt, url_body, ip, port);

	/* Send HTTP header in TCP request */
	configPRINTF(("request data %s", request_data));
	int sent = qcom_send(sock, request_data, strlen(request_data), 0);
	configPRINTF(("TCP sent %d bytes\r\n", sent));

	/* Free request data */
	custom_free(request_data);
	request_data = NULL;
	if (sent < 0)
		return NULL;

	/* Block wait for response */
	configPRINTF(("Waiting for response (with t_select)\r\n"));
	QCA_CONTEXT_STRUCT *enetCtx = wlan_get_context();
	status = (A_STATUS)t_select(enetCtx, sock, timeout);
	if (status == A_ERROR)
		return NULL;

	/* Receive response */
	int recvLen = qcom_recv(sock, &response_data, 1400, 0);
	configPRINTF(("TCP received %d bytes\r\n", recvLen));
	if (recvLen >= 0)
	{
		response_data[recvLen] = 0;
		configPRINTF(("%x %x %x %x\r\n", response_data[recvLen - 1], response_data[recvLen - 2], response_data[recvLen - 3], response_data[recvLen - 4]));
		//configPRINTF(("%s\r\n", response_data));
	}

	char* json_data = strstr(response_data, "\r\n\r\n");
	if (json_data == NULL) {
		configPRINTF(("No json data from chain\r\n"));
	}
	json_data += 4;
	int header_length = json_data - response_data;
	*outlen = recvLen - header_length;

	uint8_t* json_out = (uint8_t*)custom_alloc(*outlen);
	memcpy(json_out, json_data, *outlen); // substract the http response header.

	/* Free 'receive_data' */
	if (response_data != NULL)
	{
		zero_copy_free(response_data);
	}

    status = (A_STATUS)qcom_socket_close(sock);
    return json_out;
}

int http_post_to_chain(const char *ip, const char* url_body, int port, int timeout, char* data_send, int send_len)
{
    int32_t sock = 0;
    SOCKADDR_T addr;
    A_STATUS status;

    int request_len = 2048;
    char *request_data  = NULL;
    char *response_data = NULL;

    configPRINTF(("****************************************\r\n"));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = ATH_AF_INET;
    addr.sin_addr.s_addr = ipv4_str_to_uint32(ip);
    addr.sin_port = port; // sawtooth rest-api port

    /* Create TCP socket */
    sock = qcom_socket(ATH_AF_INET, SOCK_STREAM_TYPE, 0);
    if (isValueFailed(sock, -1, "qcom_socket"))
        return 0;

    /* Connect to remote */
    status = (A_STATUS)qcom_connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (status != A_OK)
        return 0;

    
    if (NULL == data_send)
        return 0;
    memset(request_data, 0, request_len);

    /* Allocate request_data of size that includes extra '\0' for string functions */
    // 192.168.1.101, 8008, /state/address1234
    const char* request_fmt = "POST %s HTTP/1.1\r\n"
                            "Host: %s:%d\r\n"
                            "Content-Type: application/octet-stream"
                            "Content-Length: %zu\r\n\r\n%s";

    snprintf(request_data, request_len, request_fmt, url_body, ip, port, send_len, data_send);
    
    /* Send HTTP header in TCP request */
    configPRINTF(("HTTP POST from %u.%u.%u.%u:%u\r\n", UINT32_IPADDR_TO_CSV_BYTES(addr.sin_addr.s_addr), addr.sin_port));
    int sent = qcom_send(sock, request_data, strlen(request_data), 0);
    configPRINTF(("TCP sent %d bytes\r\n", sent));

    /* Free request data */
    custom_free(request_data);
    request_data = NULL;
    if (sent < 0)
        return 0;

    /* Block wait for response */
    configPRINTF(("Waiting for response (with t_select)\r\n"));
    QCA_CONTEXT_STRUCT *enetCtx = wlan_get_context();
    status = (A_STATUS)t_select(enetCtx, sock, timeout);
    if (status == A_ERROR)
        return 0;

    /* Receive response */
    int recvLen = qcom_recv(sock, &response_data, 1400, 0);
    configPRINTF(("TCP received %d bytes\r\n", recvLen));
    if (recvLen <= 0)
    {
        configPRINTF(("Http Post Send failed\r\n"));
    }

    /* Free 'receive_data' */
    if (response_data != NULL)
    {
        zero_copy_free(response_data);
    }

    status = (A_STATUS)qcom_socket_close(sock);
    return recvLen;
}


int initNetwork(void)
{
    WIFIReturnCode_t result;

    PRINTF_NSE(("Starting WiFi...\r\n"));

    result = WIFI_On();
    if (result != eWiFiSuccess)
    {
    	configPRINTF(("Could not enable WiFi, reason %d.\r\n", result));
        return 1;
    }

    PRINTF_NSE(("WiFi module initialized.\r\n"));

    result = WIFI_ConnectAP(&pxNetworkParams);
    if (result != eWiFiSuccess)
    {
    	configPRINTF(("Could not connect to WiFi, reason %d.\r\n", result));
        return 1;
    }

    configPRINTF(("WiFi connected to AP %s.\r\n", pxNetworkParams.pcSSID));

    uint8_t tmp_ip[4] = {0};
    result            = WIFI_GetIP(tmp_ip);

    if (result != eWiFiSuccess)
    {
        configPRINTF(("Could not get IP address, reason %d.\r\n", result));
        return 1;
    }

    configPRINTF(("IP Address acquired %d.%d.%d.%d\r\n", tmp_ip[0], tmp_ip[1], tmp_ip[2], tmp_ip[3]));

    return 0;
}

int parse_json_from_chain(uint8_t* parsed_out, size_t* output_len, uint8_t* raw_json)
{
    const cJSON *data_obj = NULL;
    int status = 1;
    cJSON *parsed_json = cJSON_Parse(raw_json);
    if (parsed_json == NULL)
    {
    	configPRINTF(("json parse error\r\n"));
        status = 0;
        goto end;
    }
    data_obj = cJSON_GetObjectItemCaseSensitive(parsed_json, "data");
    char* data = data_obj->valuestring;
    if (cJSON_IsString(data_obj) && (data != NULL))
    {
        if(base64_decode(parsed_out, data, strlen(data), output_len) == 0)
        {
        	configPRINTF(("base 64 decode error\r\n"));
            status = 0;
            goto end;
        }
    }
end:
    cJSON_Delete(parsed_json);
    return status;
}