#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "janus_datatype.h"
#include "hmac_sha256.h"

int generate_random_array(uint8_t* random, size_t random_len);