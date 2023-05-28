// from https://github.com/h5p9sl/hmac_sha256

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stddef.h>

typedef struct {
  uint64_t length;
  uint32_t state[8];
  uint32_t curlen;
  uint8_t buf[64];
} Sha256Context;

#define SHA256_HASH_SIZE (256 / 8)

typedef struct {
  uint8_t bytes[SHA256_HASH_SIZE];
} SHA256_HASH;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Sha256Initialise
//
//  Initialises a SHA256 Context. Use this to initialise/reset a context.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void Sha256Initialise(Sha256Context* Context  // [out]
);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Sha256Update
//
//  Adds data to the SHA256 context. This will process the data and update the
//  internal state of the context. Keep on calling this function until all the
//  data has been added. Then call Sha256Finalise to calculate the hash.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void Sha256Update(Sha256Context* Context,  // [in out]
                  void const* Buffer,      // [in]
                  uint32_t BufferSize      // [in]
);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Sha256Finalise
//
//  Performs the final calculation of the hash and returns the digest (32 byte
//  buffer containing 256bit hash). After calling this, Sha256Initialised must
//  be used to reuse the context.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void Sha256Finalise(Sha256Context* Context,  // [in out]
                    SHA256_HASH* Digest      // [out]
);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Sha256Calculate
//
//  Combines Sha256Initialise, Sha256Update, and Sha256Finalise into one
//  function. Calculates the SHA256 hash of the buffer.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void Sha256Calculate(void const* Buffer,   // [in]
                     uint32_t BufferSize,  // [in]
                     SHA256_HASH* Digest   // [in]
);

size_t  // Returns the number of bytes written to `out`
hmac_sha256(
    // [in]: The key and its length.
    //      Should be at least 32 bytes long for optimal security.
    const void* key,
    const size_t keylen,

    // [in]: The data to hash alongside the key.
    const void* data,
    const size_t datalen,

    // [out]: The output hash.
    //      Should be 32 bytes long. If it's less than 32 bytes,
    //      the resulting hash will be truncated to the specified length.
    void* out,
    const size_t outlen);
