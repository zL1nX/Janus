#include "network_communication.h"

int socket_test()
{
    int32_t sock = 0;
    SOCKADDR_T addr;
    A_STATUS status;
    char *hello = "Hello from LPC client";
    char *request_data = NULL;
    char *received_data = NULL;

    memset(&addr, 0, sizeof(addr));

    addr.sin_family = ATH_AF_INET;
    addr.sin_port = 8083;
    addr.sin_addr.s_addr = 3232236690;

    sock = qcom_socket(ATH_AF_INET, SOCK_STREAM_TYPE, 0);
    if (sock < 0)
    {
        configPRINTF(("isValueFailed\n"));
    }

    /* Connect to remote */
    status = (A_STATUS)qcom_connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if(status != A_OK)
    {
    	configPRINTF(("connect wrong\n"));
    }
    configPRINTF(("qcom_connect\n"));

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
    
    int recvLen = qcom_recv(sock, received_data, 1024, 0);
    if (recvLen >= 0)
    {
        configPRINTF(("%s\n", received_data));
    }
    if (received_data != NULL)
    {
        zero_copy_free(received_data);
    }
    status = (A_STATUS)qcom_socket_close(sock);
    return 0;
}

int socket_init()
{
    int32_t sock = 0;
    SOCKADDR_T addr;
    A_STATUS status;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = ATH_AF_INET;
    addr.sin_port = 8083;
    addr.sin_addr.s_addr = 3232236690;

    sock = qcom_socket(ATH_AF_INET, SOCK_STREAM_TYPE, 0);
    if (sock < 0)
    {
        configPRINTF(("isValueFailed\n"));
    }

    /* Connect to remote */
    status = (A_STATUS)qcom_connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if(status != A_OK)
    {
    	configPRINTF(("connect wrong\n"));
    }
    configPRINTF(("qcom_connect\n"));
    return sock;
}

static int isQcomError(A_STATUS status, const char *funcName)
{
    if (status != A_OK)
    {
        printError(status, funcName);
    }
    else if (_traceQcomApi)
    {
        PRINTF("%s() OK\r\n", funcName);
    }
    return (status != A_OK);
}

uint32_t resolveHostname(const char *hostname)
{
    uint32_t addr = 0;

    // NOTE: This function returns the address in reverse byte order
    A_STATUS status = qcom_dnsc_get_host_by_name((char *)hostname, &addr);
    isQcomError(status, "qcom_dnsc_get_host_by_name");
    if (status == 0)
    {
        PRINTF("Looked up %s as %d.%d.%d.%d\r\n", hostname, UINT32_IPADDR_TO_CSV_BYTES(addr));
    }
    return addr;
}

static int isValueFailed(int32_t value, int32_t failValue, const char *funcName)
{
    if (value == failValue)
    {
        printError(value, funcName);
    }
    else if (_traceQcomApi)
    {
        PRINTF("%s() OK\r\n", funcName);
    }
    return (value == failValue);
}

void httpGet(const char *hostname, int timeout)
{
    int32_t sock = 0;
    SOCKADDR_T addr;
    A_STATUS status;
    char *request_data  = NULL;
    char *response_data = NULL;

    PRINTF("****************************************\r\n");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = ATH_AF_INET;
    addr.sin_addr.s_addr = resolveHostname(hostname);
	if (addr.sin_addr.s_addr == 0)
	{
		PRINTF("ERROR: Failed to resolve %s\r\n", hostname);
		return;
	}
    addr.sin_port = 80;

    do
    {
        /* Create TCP socket */
        sock = qcom_socket(ATH_AF_INET, SOCK_STREAM_TYPE, 0);
        if (isValueFailed(sock, -1, "qcom_socket"))
            break;

        /* Connect to remote */
        status = (A_STATUS)qcom_connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        if (isQcomError(status, "qcom_connect"))
            break;

        /* No explicit hostname, use gateway addr */

        /* Allocate request_data of size that includes extra '\0' for string functions */
        uint32_t hostname_len      = strlen(hostname);
        uint32_t request_data_size = CONSTSTR_LEN(header_start) + hostname_len + CONSTSTR_LEN(header_end) + 1;
        request_data               = custom_alloc(request_data_size);
        assert(!(NULL == request_data));
        if (NULL == request_data)
            break;
        memset(request_data, 0, request_data_size);

        /* Assemble HTTP header*/
        uint32_t request_data_i = 0, request_piece_size = 0;
        /* Copy 'header_start' to request_data */
        request_piece_size = CONSTSTR_LEN(header_start);
        memcpy(&request_data[request_data_i], header_start, request_piece_size);
        request_data_i += request_piece_size;
        /* Copy 'hostname' to 'request_data' */
        request_piece_size = hostname_len;
        memcpy(&request_data[request_data_i], hostname, request_piece_size);
        request_data_i += request_piece_size;
        /* Copy 'header_end' to 'request_data' */
        request_piece_size = CONSTSTR_LEN(header_end);
        memcpy(&request_data[request_data_i], header_end, request_piece_size);
        request_data_i += request_piece_size;

        /* Send HTTP header in TCP request */
        PRINTF("HTTP GET from %u.%u.%u.%u:%u\r\n", UINT32_IPADDR_TO_CSV_BYTES(addr.sin_addr.s_addr), addr.sin_port);
        PRINTF("%s\r\n", request_data);
        int sent = qcom_send(sock, request_data, request_data_size, 0);
        PRINTF("TCP sent %d bytes\r\n", sent);

        /* Free request data */
        custom_free(request_data);
        request_data = NULL;
        if (sent < 0)
            break;

        /* Block wait for response */
        PRINTF("Waiting for response (with t_select)\r\n");
        if (timeout == 0)
            timeout = 5000;
        QCA_CONTEXT_STRUCT *enetCtx = wlan_get_context();
        status                      = (A_STATUS)t_select(enetCtx, sock, timeout);
        if (status == A_ERROR)
            break;

        /* Receive response */
        PRINTF("qcom_recv() receiving response\r\n");
        int recvLen = qcom_recv(sock, &response_data, 1400, 0);
        PRINTF("TCP received %d bytes\r\n", recvLen);
        if (recvLen >= 0)
        {
            response_data[recvLen] = 0;
            PRINTF("%s\r\n", response_data);
        }

        /* Free 'receive_data' */
        if (response_data != NULL)
        {
            zero_copy_free(response_data);
        }
    } while (0);

    status = (A_STATUS)qcom_socket_close(sock);
    isQcomError(status, "qcom_socket_close");
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