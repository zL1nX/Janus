#include "janus_session.h"


uint8_t private_key[] = { 0xba, 0x8b, 0xa7, 0x1f, 0x6c, 0x76, 0xda, 0x0c, 0xf3, 0x24, 0xd6, 0x66, 0x3d, 0xc4, 0x80, 0x20, 0x47, 0x19, 0xf3, 0x75, 0xdf, 0xfe, 0xb2, 0x1f, 0xae, 0x76, 0xa7, 0x90, 0x20, 0xa4, 0x43, 0xf1 };
struct RemoteAttestationClient client;
serial_t sr;
int role = IS_ATTESTER;
const char* puf = "/dev/ttyUSB1"; // Change this to the desired serial port device
int baud_rate = 19200; 

int init_session()
{
    uint8_t* priv = private_key;
    if(puf_init(&sr, puf, baud_rate) != 0)
    {
        return EXIT_FAILURE;
    }
    if(puf_test(&sr) != 0)
    {
        return EXIT_FAILURE;
    }
    client.sr = &sr;
    
    if(initClient(&client, IS_ATTESTER, priv) < 0)
    {
        return ERROR_UNEXPECTED;
    }
    return SUCCESS;
}