#include "b64.h"

static const uint8_t base64_table[256] = {
    /* ASCII table */
    [65] = 0,  [66] = 1,  [67] = 2,  [68] = 3,  [69] = 4,  [70] = 5,  [71] = 6,  [72] = 7,
    [73] = 8,  [74] = 9,  [75] = 10, [76] = 11, [77] = 12, [78] = 13, [79] = 14, [80] = 15,
    [81] = 16, [82] = 17, [83] = 18, [84] = 19, [85] = 20, [86] = 21, [87] = 22, [88] = 23,
    [89] = 24, [90] = 25,
    /* lowercase letters */
    [97] = 26, [98] = 27, [99] = 28, [100] = 29, [101] = 30, [102] = 31,
    /* digits */
    [48] = 32,[49] = 33, [50] = 34, [51] = 35, [52] = 36, [53] = 37, [54] = 38, [55] = 39,
    [56] = 40, [57] = 41,
    /* special characters */
    [43] = 42, [47] = 43,
};

int base64_decode(uint8_t* output, const char* input, size_t input_len, size_t* output_len) {
    if (input_len % 4 != 0) {
        /* input length must be a multiple of 4 */
        return 0;
    }

    size_t padding = 0;
    if (input[input_len - 1] == '=') {
        padding++;
        if (input[input_len - 2] == '=') {
            padding++;
        }
    }

    *output_len = (input_len / 4) * 3 - padding;

    size_t i, j;
    uint32_t value;
    for (i = 0, j = 0; i < input_len; i += 4, j += 3) {
        value = (base64_table[(uint8_t)input[i]] << 18) |
                (base64_table[(uint8_t)input[i + 1]] << 12) |
                (base64_table[(uint8_t)input[i + 2]] << 6) |
                base64_table[(uint8_t)input[i + 3]];
        output[j] = (value >> 16) & 0xFF;
        if (i + 2 < input_len) {
            output[j + 1] = (value >> 8) & 0xFF;
        }
        if (i + 3 < input_len) {
            output[j + 2] = value & 0xFF;
        }
    }
    return 1;
}