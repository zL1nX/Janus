#include "serial.h"
#include "puf_util.h"


int generate_random_array(uint8_t* random, size_t random_len)
{
    for (int i = 0; i < random_len; i++)
    {
        random[i] = rand ();
    }
    return 0;
}

uint64_t convert_to_uint64_t(uint8_t* input) {
    uint64_t output = 0;
    for (int i = 0; i < 8; i++) {
        output |= ((uint64_t)input[i] << (8 * i));
    }
    return output;
}

int puf_init(serial_t* sr, const char* puf, int baud_rate)
{
    if (!serial_open(sr, puf, baud_rate)) {
        fprintf(stderr, "Error opening serial port\n");
        return EXIT_FAILURE;
    }
    unsigned char cmd_resp;
    if(!serial_empty(sr))
    {
        printf("Serial Buffer is not empty\n");
    }

    // active test
    if(!serial_write_command(sr, 'A')) {
        printf("Test Fail serial_write_command A\n");
        return EXIT_FAILURE;
    }
    if(!serial_read(sr, &cmd_resp, 1) || cmd_resp != 'Y'){
        printf("Test Fail compare_command %c\n", cmd_resp);
        return EXIT_FAILURE;
    }
    return 0;
}

int puf_evaluate(serial_t* sr, uint8_t* response, uint8_t* challenge)
{
    unsigned char cmd_resp;
    if(!serial_empty(sr))
    {
        printf("Serial Buffer is not empty\n");
        return EXIT_FAILURE;
    }
    if(!serial_write_command(sr, 'C') || !serial_write_command(sr, 1)) {
        printf("Test Fail serial_write_command C");
        return EXIT_FAILURE;
    }
    if (!serial_write(sr, challenge, IPUF_CHALL)) {
        fprintf(stderr, "Error writing to serial port challenge\n");
        serial_close(sr);
        return EXIT_FAILURE;
    }


    // if(!serial_write_command(sr, 'V')) {
    //     printf("Test Fail serial_write_command V");
    //     return EXIT_FAILURE;
    // }

    // if(!serial_read(sr, &cmd_resp, 1) || cmd_resp != 'B'){
    //     printf("Test Fail compare_command %c\n", cmd_resp);
    //     return EXIT_FAILURE;
    // }
    // printf("send read challenge command\n");

    // uint8_t received[IPUF_CHALL];
    // if(!serial_read(sr, received, IPUF_CHALL)){
    //     printf("Test Fail read_challenge");
    //     return EXIT_FAILURE;
    // }
    // printf("read challenge\n");

    // // compare 
    // if(memcmp(challenge, received, IPUF_CHALL)!=0){
    //     printf("Test Fail compare_challenge");
    //     return EXIT_FAILURE;
    // }
    if(!serial_empty(sr))
    {
        printf("Serial Buffer is not empty\n");
    }

    // start PUF evaluation 
    if(!serial_write_command(sr, 'S')) {
        printf("Test Fail serial_write_command S");
        return EXIT_FAILURE;
    }
    if(!serial_read(sr, &cmd_resp, 1) || cmd_resp != 'Q'){
        printf("Test Fail start_evaluation");
        return EXIT_FAILURE;
    }

    // wait for response
    do
    {
        if(!serial_write_command(sr, 'W')) {
            printf("Test Fail serial_write_command W");
            return EXIT_FAILURE;
        }
        if(!serial_read(sr, &cmd_resp, 1)){
            printf("Test Fail start_evaluation");
            return EXIT_FAILURE;
        }
    } while (cmd_resp != 'F'); // cmd_resp == F means ready

    if(!serial_read(sr, response, IPUF_RESP)){
        printf("Test Fail read_challenge");
        return EXIT_FAILURE;
    }

    return 0;
}

void puf_close(serial_t* sr)
{
    serial_close(sr);
}

int puf_test(serial_t* sr)
{
    //ping write_command(s,'A')
    unsigned char cmd_resp;
    uint8_t wsize = IPUF_CHALL;
    if(!serial_empty(sr))
    {
        printf("Serial Buffer is not empty\n");
    }

    if(!serial_write_command(sr, 'A')) {
        printf("Test Fail serial_write_command A\n");
        return EXIT_FAILURE;
    }
    if(!serial_read(sr, &cmd_resp, 1) || cmd_resp != 'Y'){
        printf("Test Fail compare_command %c\n", cmd_resp);
        return EXIT_FAILURE;
    }

    printf("%c\n", cmd_resp);

    if(!serial_empty(sr))
    {
        printf("Serial Buffer is not empty\n");
    }
    
    // send challenge
    uint8_t challenge[IPUF_CHALL]={1, 2, 3, 4, 5, 6, 7, 8}, received[IPUF_CHALL];
    //generate_random_array(challenge, IPUF_CHALL);
    for(int i = 0; i < IPUF_CHALL; i++)
    {
        printf("%x ", challenge[i]);
    }
    printf("\n");

    if(!serial_empty(sr))
    {
        printf("Serial Buffer is not empty\n");
    }

    if(!serial_write_command(sr, 'C') || !serial_write_command(sr, 1)) {
        printf("Test Fail serial_write_command C");
        return EXIT_FAILURE;
    }
    if (!serial_write(sr, challenge, IPUF_CHALL)) {
        fprintf(stderr, "Error writing to serial port challenge\n");
        serial_close(sr);
        return EXIT_FAILURE;
    }
    printf("send challenge\n");

    if(!serial_empty(sr))
    {
        printf("Serial Buffer is not empty\n");
    }
    // read challenge
    if(!serial_write_command(sr, 'V')) {
        printf("Test Fail serial_write_command V");
        return EXIT_FAILURE;
    }

    if(!serial_read(sr, &cmd_resp, 1) || cmd_resp != 'B'){
        printf("Test Fail compare_command %c\n", cmd_resp);
        return EXIT_FAILURE;
    }
    printf("send read challenge command\n");

    if(!serial_read(sr, received, IPUF_CHALL)){
        printf("Test Fail read_challenge");
        return EXIT_FAILURE;
    }
    printf("read challenge\n");

    // compare 
    if(memcmp(challenge, received, IPUF_CHALL)!=0){
        printf("Test Fail compare_challenge");
        return EXIT_FAILURE;
    }
    if(!serial_empty(sr))
    {
        printf("Serial Buffer is not empty\n");
    }
    
    // wait for response
    if(!serial_write_command(sr, 'S')) {
        printf("Test Fail serial_write_command S");
        return EXIT_FAILURE;
    }
    if(!serial_read(sr, &cmd_resp, 1) || cmd_resp != 'Q'){
        printf("Test Fail start_evaluation");
        return EXIT_FAILURE;
    }

    clock_t start = clock();
    do
    {
        if(!serial_write_command(sr, 'W')) {
            printf("Test Fail serial_write_command W");
            return EXIT_FAILURE;
        }
        if(!serial_read(sr, &cmd_resp, 1)){
            printf("Test Fail start_evaluation");
            return EXIT_FAILURE;
        }
    } while (cmd_resp != 'F');
    double end = (double)(clock() - start)/CLOCKS_PER_SEC;
    printf("time: %f\n", end);

    printf("response ready\n");

    if(!serial_read(sr, received, IPUF_RESP)){
        printf("Test Fail read_challenge");
        return EXIT_FAILURE;
    }

    for(int i = 0; i < IPUF_RESP; i++)
    {
        printf("%x ", received[i]);
    }
    printf("\n");

    return 0;
}

/*
use this interface

response: 16 bytes
challenge : longer than 8 bytes (only use the first 8 bytes here)

*/
int janus_puf_evaluate(serial_t* sr, uint8_t* response, uint8_t* challenge)
{
    uint8_t puf_response[PUF_RESP], shifted[IPUF_CHALL];
    uint64_t temp = convert_to_uint64_t(challenge);

    // use 8 bytes challenge to generate 8 different challenges by cyclic shift, then we have 8 x 2 bytes response.
    for (int i = 0; i < IPUF_CHALL; i++) {
        temp = (temp << 8) | (temp >> 56); // cyclic shift by byte
        for (int j = 0; j < 8; j++) {
            shifted[j] = (temp >> (8 * (7 - j))) & 0xFF; // convert back to uint8_array;
        }
        puf_evaluate(sr, puf_response + i * 2, shifted);
    }
    return 0;
}


int main()
{
    srand((unsigned int)time(NULL));
    serial_t serial;
    const char* puf = "/dev/ttyUSB1"; // Change this to the desired serial port device
    int baud_rate = 19200; // Change this to the desired baud rate

    uint8_t challenge[IPUF_CHALL] = {1,2,3,4,5,6,7,8}, response[PUF_RESP];

    if(puf_init(&serial, puf, baud_rate) != 0)
    {
        return EXIT_FAILURE;
    }
    if(puf_test(&serial) != 0)
    {
        return EXIT_FAILURE;
    }

    // uint8_t test_response[2];
    // puf_evaluate(&serial, test_response, challenge);
    // for(int i = 0; i < 2; i++)
    // {
    //     printf("%x ", test_response[i]);
    // }printf("\n");

    janus_puf_evaluate(&serial, response, challenge);

        // for(int i = 0; i < IPUF_CHALL; i++)
    // {
    //     printf("%x ", challenge[i]);
    // }printf("\n");

    // for(int i = 0; i < PUF_RESP; i++)
    // {
    //     printf("%x ", response[i]);
    // }printf("\n");
    

    puf_close(&serial);

    return EXIT_SUCCESS;
}

