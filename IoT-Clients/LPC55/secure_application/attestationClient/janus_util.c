#include "janus_util.h"

/*
generate nonce or random bytes array
*/

int generate_random_array(uint8_t* random, size_t random_len)
{
    srand ((unsigned int) time (NULL));
    for (int i = 0; i < random_len; i++)
    {
        random[i] = rand ();
    }
    return 0;
}

// int main()
// {
//     int random_len = 16;
//     uint8_t random[random_len];
//     generate_random(random, random_len);
//     for(int i = 0; i < random_len; i++)
//     {
//         printf("%02x ", random[i]);
//     }
//     printf("\n");
//     return 0;
// }