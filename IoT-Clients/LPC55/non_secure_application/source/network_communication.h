#include "aws_clientcredential.h"
#include "qcom_api.h"
#include "iot_wifi.h"

// Convert IP address in uint32_t to comma separated bytes
#define UINT32_IPADDR_TO_CSV_BYTES(a) \
    ((uint8_t)((a) >> 24) & 0xFF), (uint8_t)(((a) >> 16) & 0xFF), (uint8_t)(((a) >> 8) & 0xFF), (uint8_t)((a)&0xFF)
// Convert comma separated bytes to a uint32_t IP address
#define CSV_BYTES_TO_UINT32_IPADDR(a0, a1, a2, a3) \
    (((uint32_t)(a0)&0xFF) << 24) | (((uint32_t)(a1)&0xFF) << 16) | (((uint32_t)(a2)&0xFF) << 8) | ((uint32_t)(a3)&0xFF)
#define CONSTSTR_LEN(variable) (sizeof(variable) - 1)

const static char header_start[] =
    "GET / HTTP/1.0\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0\r\n"
    "Accept-Language: en-us\r\n"
    "Host: ";
const static char header_end[] = "\r\n\r\n";
static int _traceQcomApi = 0;

const WIFINetworkParams_t pxNetworkParams = {
    .pcSSID           = clientcredentialWIFI_SSID,
    .ucSSIDLength     = sizeof(clientcredentialWIFI_SSID) - 1,
    .pcPassword       = clientcredentialWIFI_PASSWORD,
    .ucPasswordLength = sizeof(clientcredentialWIFI_PASSWORD) - 1,
    .xSecurity        = clientcredentialWIFI_SECURITY,
};

int socket_init();
