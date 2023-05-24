#include "aws_clientcredential.h"
#include "qcom_api.h"
#include "iot_wifi.h"
#include "fsl_debug_console.h"
#include "veneer_table.h"
#include <stdio.h>


// Convert IP address in uint32_t to comma separated bytes
#define UINT32_IPADDR_TO_CSV_BYTES(a) \
    ((uint8_t)((a) >> 24) & 0xFF), (uint8_t)(((a) >> 16) & 0xFF), (uint8_t)(((a) >> 8) & 0xFF), (uint8_t)((a)&0xFF)
// Convert comma separated bytes to a uint32_t IP address
#define CSV_BYTES_TO_UINT32_IPADDR(a0, a1, a2, a3) \
    (((uint32_t)(a0)&0xFF) << 24) | (((uint32_t)(a1)&0xFF) << 16) | (((uint32_t)(a2)&0xFF) << 8) | ((uint32_t)(a3)&0xFF)
#define CONSTSTR_LEN(variable) (sizeof(variable) - 1)
#define PRINTF_NSE DbgConsole_Printf_NSE


const static char header_start[] =
    "GET / HTTP/1.0\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0\r\n"
    "Accept-Language: en-us\r\n"
    "Host: ";
const static char header_end[] = "\r\n\r\n";


int socket_init(const char* ip, uint16_t port);
int socket_test(const char* ip, uint16_t port);
int initNetwork();
uint8_t* http_get_from_chain(size_t* outlen, const char *ip, const char* url_body, int port, int timeout);
int http_post_to_chain(const char *ip, const char* url_body, int port, int timeout, char* data_send, int send_len);
int parse_json_from_chain(uint8_t* parsed_out, size_t* output_len, uint8_t* raw_json);