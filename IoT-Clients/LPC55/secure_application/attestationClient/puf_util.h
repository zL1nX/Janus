#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "janus_datatype.h"


int puf_init(serial_t* sr, const char* puf, int baud_rate);
int puf_evaluate(serial_t* sr, uint8_t* response, const uint8_t* challenge);
int puf_test(serial_t* sr);
void puf_close(serial_t* sr);
int janus_puf_evaluate(serial_t* sr, uint8_t* response, const uint8_t* challenge);