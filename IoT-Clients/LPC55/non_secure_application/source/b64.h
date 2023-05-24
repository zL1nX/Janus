/*
 * b64.h
 *
 *  Created on: 2023年5月23日
 *      Author: LoCCS-GoCE
 */

#ifndef B64_H_
#define B64_H_

#include <stdint.h>
#include <stdlib.h>

int base64_decode(uint8_t* output, const char* input, size_t input_len, size_t* output_len);

#endif /* B64_H_ */