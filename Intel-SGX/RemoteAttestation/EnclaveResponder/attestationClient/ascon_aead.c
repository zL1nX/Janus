// from https://github.com/TheMatjaz/LibAscon, https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/ascon-spec-round2.pdf

/* 可惜ASCON团队没给ARMv8的优化实现版本, 用法与测试在本文件最后ascon_test里 */


/**
 * @file
 * 64-bit optimised implementation of Ascon128 AEAD cipher.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include "ascon.h"
#include "ascon_aead.h"

/**
 * @internal
 * Simplistic clone of memcpy for small arrays.
 *
 * It should work faster than memcpy for very small amounts of bytes given
 * the reduced overhead.
 *
 * Initially implemented with a while-loop, but it triggers a
 * `-Werror=stringop-overflow=` warning in GCC v11. Replaced it with a for-loop
 * that does the exact same thing instead to make it work without deactivating
 * the warning. We instead let the optimiser figure out the best way to make it
 * as fast as possible.
 */
inline static void
small_cpy(uint8_t* const dst, const uint8_t* const src, const size_t amount)
{
    for (uint_fast8_t i = 0U; i < amount; i++)
    {
        dst[i] = src[i];
    }
}

ASCON_INLINE uint64_t
bigendian_decode_u64(const uint8_t* const bytes)
{
    uint64_t value = 0;
    value |= ((uint64_t) bytes[0]) << 56U;
    value |= ((uint64_t) bytes[1]) << 48U;
    value |= ((uint64_t) bytes[2]) << 40U;
    value |= ((uint64_t) bytes[3]) << 32U;
    value |= ((uint64_t) bytes[4]) << 24U;
    value |= ((uint64_t) bytes[5]) << 16U;
    value |= ((uint64_t) bytes[6]) << 8U;
    value |= ((uint64_t) bytes[7]);
    return value;
}

ASCON_INLINE void
bigendian_encode_u64(uint8_t* const bytes, const uint64_t value)
{
    bytes[0] = (uint8_t) (value >> 56U);
    bytes[1] = (uint8_t) (value >> 48U);
    bytes[2] = (uint8_t) (value >> 40U);
    bytes[3] = (uint8_t) (value >> 32U);
    bytes[4] = (uint8_t) (value >> 24U);
    bytes[5] = (uint8_t) (value >> 16U);
    bytes[6] = (uint8_t) (value >> 8U);
    bytes[7] = (uint8_t) (value);
}

ASCON_INLINE uint64_t
bigendian_decode_varlen(const uint8_t* const bytes, const uint_fast8_t n)
{
    uint64_t x = 0;
    // Unsigned int should be the fastest unsigned on the machine.
    // Using it to avoid warnings about <<-operator with signed value.
    for (unsigned int i = 0; i < n; i++)
    {
        x |= ((uint64_t) bytes[i]) << (56U - 8U * i);
    }
    return x;
}

ASCON_INLINE void
bigendian_encode_varlen(uint8_t* const bytes, const uint64_t x, const uint_fast8_t n)
{
    // Unsigned int should be the fastest unsigned on the machine.
    // Using it to avoid warnings about <<-operator with signed value.
    for (unsigned int i = 0; i < n; i++)
    {
        bytes[i] = (uint8_t) (x >> (56U - 8U * i));
    }
}

uint64_t
mask_most_signif_bytes(uint_fast8_t n)
{
    uint64_t x = 0;
    // Unsigned int should be the fastest unsigned on the machine.
    // Using it to avoid warnings about <<-operator with signed value.
    for (unsigned int i = 0; i < n; i++)
    {
        x |= 0xFFULL << (56U - 8U * i);
    }
    return x;
}

size_t
buffered_accumulation(ascon_bufstate_t* const ctx,
                      uint8_t* data_out,
                      const uint8_t* data_in,
                      absorb_fptr absorb,
                      size_t data_in_len,
                      const uint8_t rate)
{
    size_t fresh_out_bytes = 0;
    if (ctx->buffer_len > 0)
    {
        // There is data in the buffer already.
        // Place as much as possible of the new data into the buffer.
        const uint_fast8_t space_in_buf = (uint_fast8_t) (rate - ctx->buffer_len);
        const uint_fast8_t into_buffer = (uint_fast8_t) MIN(space_in_buf, data_in_len);
        small_cpy(&ctx->buffer[ctx->buffer_len], data_in, into_buffer);
        ctx->buffer_len = (uint8_t) (ctx->buffer_len + into_buffer);
        data_in += into_buffer;
        data_in_len -= into_buffer;
        if (ctx->buffer_len == rate)
        {
            // The buffer was filled completely, thus absorb it.
            absorb(&ctx->sponge, data_out, ctx->buffer);
            ctx->buffer_len = 0;
            data_out += rate;
            fresh_out_bytes += rate;
        }
        else
        {
            // Do nothing.
            // The buffer contains some data, but it's not full yet
            // and there is no more data in this update call.
            // Keep it cached for the next update call or the digest call.
        }
    }
    else
    {
        // Do nothing.
        // The buffer contains no data, because this is the first update call
        // or because the last update had no less-than-a-block trailing data.
    }
    // Absorb remaining data (if any) one block at the time.
    while (data_in_len >= rate)
    {
        absorb(&ctx->sponge, data_out, data_in);
        data_out += rate;
        data_in += rate;
        data_in_len -= rate;
        fresh_out_bytes += rate;
    }
    // If there is any remaining less-than-a-block data to be absorbed,
    // cache it into the buffer for the next update call or digest call.
    if (data_in_len > 0)
    {
        small_cpy(ctx->buffer, data_in, data_in_len);
        ctx->buffer_len = (uint8_t) data_in_len;
    }
    return fresh_out_bytes;
}

void
ascon_aead_init(ascon_aead_ctx_t* const ctx,
                const uint8_t* const key,
                const uint8_t* const nonce,
                const uint64_t iv)
{
    // Store the key in the context as it's required in the final step.
    ctx->k0 = bigendian_decode_u64(key);
    ctx->k1 = bigendian_decode_u64(key + sizeof(uint64_t));
    ctx->bufstate.sponge.x0 = iv;
    ctx->bufstate.sponge.x1 = ctx->k0;
    ctx->bufstate.sponge.x2 = ctx->k1;
    ctx->bufstate.sponge.x3 = bigendian_decode_u64(nonce);
    ctx->bufstate.sponge.x4 = bigendian_decode_u64(nonce + sizeof(uint64_t));
    ascon_permutation_12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    ctx->bufstate.buffer_len = 0;
}

void
ascon_aead128_80pq_finalise_assoc_data(ascon_aead_ctx_t* const ctx)
{
    // If there was at least some associated data obtained so far,
    // pad it and absorb any content of the buffer.
    // Note: this step is performed even if the buffer is now empty because
    // a state permutation is required if there was at least some associated
    // data absorbed beforehand.
    if (ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED)
    {
        ctx->bufstate.sponge.x0 ^= bigendian_decode_varlen(ctx->bufstate.buffer,
                                                           ctx->bufstate.buffer_len);
        ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
        ascon_permutation_6(&ctx->bufstate.sponge);
    }
    // Application of a constant at end of associated data for domain
    // separation. Done always, regardless if there was some associated
    // data or not.
    ctx->bufstate.sponge.x4 ^= 1U;
    ctx->bufstate.buffer_len = 0;
}

void
ascon_aead_generate_tag(ascon_aead_ctx_t* const ctx,
                        uint8_t* tag,
                        size_t tag_len)
{
    while (tag_len > ASCON_AEAD_TAG_MIN_SECURE_LEN)
    {
        // All bytes before the last 16
        // Note: converting the sponge uint64_t to bytes to then check them as
        // uint64_t is required, as the conversion to bytes ensures the
        // proper byte order regardless of the platform native endianness.
        bigendian_encode_u64(tag, ctx->bufstate.sponge.x3);
        bigendian_encode_u64(tag + sizeof(uint64_t), ctx->bufstate.sponge.x4);
        ascon_permutation_12(&ctx->bufstate.sponge);
        tag_len -= ASCON_AEAD_TAG_MIN_SECURE_LEN;
        tag += ASCON_AEAD_TAG_MIN_SECURE_LEN;
    }
    // The last 16 or fewer bytes (also 0)
    uint_fast8_t remaining = (uint_fast8_t) MIN(sizeof(uint64_t), tag_len);
    bigendian_encode_varlen(tag, ctx->bufstate.sponge.x3, remaining);
    tag += remaining;
    // The last 8 or fewer bytes (also 0)
    tag_len -= remaining;
    bigendian_encode_varlen(tag, ctx->bufstate.sponge.x4, (uint_fast8_t) tag_len);
}

bool
ascon_aead_is_tag_valid(ascon_aead_ctx_t* const ctx,
                        const uint8_t* expected_tag,
                        size_t expected_tag_len)
{
    uint64_t expected_tag_chunk;
    bool tags_differ = false;
    while (expected_tag_len > ASCON_AEAD_TAG_MIN_SECURE_LEN)
    {
        // Note: converting the expected tag from uint8_t[] to uint64_t
        // for a faster comparison. It has to be decoded explicitly to ensure
        // it works the same on all platforms, regardless of endianness.
        // Type-punning like `*(uint64_t*) expected_tag` is NOT portable.
        //
        // Constant time comparison expected vs computed digest chunk, part 1
        expected_tag_chunk = bigendian_decode_u64(expected_tag);
        tags_differ |= (expected_tag_chunk ^ ctx->bufstate.sponge.x3);
        expected_tag += sizeof(expected_tag_chunk);
        expected_tag_len -= sizeof(expected_tag_chunk);
        // Constant time comparison expected vs computed digest chunk, part 2
        expected_tag_chunk = bigendian_decode_u64(expected_tag);
        tags_differ |= (expected_tag_chunk ^ ctx->bufstate.sponge.x4);
        expected_tag += sizeof(expected_tag_chunk);
        expected_tag_len -= sizeof(expected_tag_chunk);
        // Permute and go to next chunk
        ascon_permutation_12(&ctx->bufstate.sponge);
    }
    // Extract the remaining n most significant bytes of expected/computed tags
    size_t remaining = MIN(sizeof(expected_tag_chunk), expected_tag_len);
    uint64_t ms_mask = mask_most_signif_bytes((uint_fast8_t) remaining);
    expected_tag_chunk = bigendian_decode_varlen(expected_tag, (uint_fast8_t) remaining);
    tags_differ |= (expected_tag_chunk ^ (ctx->bufstate.sponge.x3 & ms_mask));
    expected_tag += remaining;
    expected_tag_len -= remaining;
    remaining = MIN(sizeof(expected_tag_chunk), expected_tag_len);
    ms_mask = mask_most_signif_bytes((uint_fast8_t) remaining);
    expected_tag_chunk = bigendian_decode_varlen(expected_tag, (uint_fast8_t) remaining);
    tags_differ |= (expected_tag_chunk ^ (ctx->bufstate.sponge.x4 & ms_mask));
    return !tags_differ; // True if they are equal
}

/**
 * @internal
 * Performs one permutation round on the Ascon sponge for the given round
 * constant.
 *
 * Although this function is never used outside this file,
 * it is NOT marked as static, as it is generally inline in the functions
 * using it to increase the performance. Inlining static functions into
 * functions used outside this file leads to compilation errors:
 * "error: static function 'ascon_round' is used in an inline function with
 * external linkage `[-Werror,-Wstatic-in-inline]`".
 */
ASCON_INLINE void
ascon_round(ascon_sponge_t* sponge,
            const uint_fast8_t round_const)
{
    // addition of round constant
    sponge->x2 ^= round_const;
    // substitution layer
    sponge->x0 ^= sponge->x4;
    sponge->x4 ^= sponge->x3;
    sponge->x2 ^= sponge->x1;
    // start of keccak s-box
    const ascon_sponge_t temp = {
            .x0 = (~sponge->x0) & sponge->x1,
            .x1 = (~sponge->x1) & sponge->x2,
            .x2 = (~sponge->x2) & sponge->x3,
            .x3 = (~sponge->x3) & sponge->x4,
            .x4 = (~sponge->x4) & sponge->x0,
    };
    sponge->x0 ^= temp.x1;
    sponge->x1 ^= temp.x2;
    sponge->x2 ^= temp.x3;
    sponge->x3 ^= temp.x4;
    sponge->x4 ^= temp.x0;
    // end of keccak s-box
    sponge->x1 ^= sponge->x0;
    sponge->x0 ^= sponge->x4;
    sponge->x3 ^= sponge->x2;
    sponge->x2 = ~sponge->x2;
    // linear diffusion layer
    sponge->x0 ^= ASCON_ROTR64(sponge->x0, 19) ^ ASCON_ROTR64(sponge->x0, 28);
    sponge->x1 ^= ASCON_ROTR64(sponge->x1, 61) ^ ASCON_ROTR64(sponge->x1, 39);
    sponge->x2 ^= ASCON_ROTR64(sponge->x2, 1) ^ ASCON_ROTR64(sponge->x2, 6);
    sponge->x3 ^= ASCON_ROTR64(sponge->x3, 10) ^ ASCON_ROTR64(sponge->x3, 17);
    sponge->x4 ^= ASCON_ROTR64(sponge->x4, 7) ^ ASCON_ROTR64(sponge->x4, 41);
}

ASCON_INLINE void
ascon_permutation_12(ascon_sponge_t* const sponge)
{
    ascon_round(sponge, ROUND_CONSTANT_01);
    ascon_round(sponge, ROUND_CONSTANT_02);
    ascon_round(sponge, ROUND_CONSTANT_03);
    ascon_round(sponge, ROUND_CONSTANT_04);
    ascon_round(sponge, ROUND_CONSTANT_05);
    ascon_round(sponge, ROUND_CONSTANT_06);
    ascon_round(sponge, ROUND_CONSTANT_07);
    ascon_round(sponge, ROUND_CONSTANT_08);
    ascon_round(sponge, ROUND_CONSTANT_09);
    ascon_round(sponge, ROUND_CONSTANT_10);
    ascon_round(sponge, ROUND_CONSTANT_11);
    ascon_round(sponge, ROUND_CONSTANT_12);
}

ASCON_INLINE void
ascon_permutation_8(ascon_sponge_t* const sponge)
{
    ascon_round(sponge, ROUND_CONSTANT_05);
    ascon_round(sponge, ROUND_CONSTANT_06);
    ascon_round(sponge, ROUND_CONSTANT_07);
    ascon_round(sponge, ROUND_CONSTANT_08);
    ascon_round(sponge, ROUND_CONSTANT_09);
    ascon_round(sponge, ROUND_CONSTANT_10);
    ascon_round(sponge, ROUND_CONSTANT_11);
    ascon_round(sponge, ROUND_CONSTANT_12);
}

ASCON_INLINE void
ascon_permutation_6(ascon_sponge_t* const sponge)
{
    ascon_round(sponge, ROUND_CONSTANT_07);
    ascon_round(sponge, ROUND_CONSTANT_08);
    ascon_round(sponge, ROUND_CONSTANT_09);
    ascon_round(sponge, ROUND_CONSTANT_10);
    ascon_round(sponge, ROUND_CONSTANT_11);
    ascon_round(sponge, ROUND_CONSTANT_12);
}

ASCON_API void
ascon_aead_cleanup(ascon_aead_ctx_t* const ctx)
{
    ASCON_ASSERT(ctx != NULL);
    // Manual cleanup using volatile pointers to have more assurance the
    // cleanup will not be removed by the optimiser.
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.sponge.x0 = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.sponge.x1 = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.sponge.x2 = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.sponge.x3 = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.sponge.x4 = 0U;
    for (uint_fast8_t i = 0; i < ASCON_DOUBLE_RATE; i++)
    {
        ((volatile ascon_aead_ctx_t*) ctx)->bufstate.buffer[i] = 0U;
    }
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.buffer_len = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.flow_state = ASCON_FLOW_CLEANED;
    // Clearing also the padding to set the whole context to be all-zeros.
    // Makes it easier to check for initialisation and provides a known
    // state after cleanup, initialising all memory.
    for (uint_fast8_t i = 0U; i < 6U; i++)
    {
        ((volatile ascon_aead_ctx_t*) ctx)->bufstate.pad[i] = 0U;
    }
    ((volatile ascon_aead_ctx_t*) ctx)->k0 = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->k1 = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->k2 = 0U;
}

ASCON_API void
ascon_aead128_encrypt(uint8_t* ciphertext,
                      uint8_t* tag,
                      const uint8_t key[ASCON_AEAD128_KEY_LEN],
                      const uint8_t nonce[ASCON_AEAD_NONCE_LEN],
                      const uint8_t* assoc_data,
                      const uint8_t* plaintext,
                      size_t assoc_data_len,
                      size_t plaintext_len,
                      size_t tag_len)
{
    ASCON_ASSERT(plaintext_len == 0 || ciphertext != NULL);
    ASCON_ASSERT(tag_len != 0 || tag != NULL);
    ASCON_ASSERT(key != NULL);
    ASCON_ASSERT(nonce != NULL);
    ASCON_ASSERT(assoc_data_len == 0 || assoc_data != NULL);
    ASCON_ASSERT(plaintext_len == 0 || plaintext != NULL);
    ascon_aead_ctx_t ctx;
    ascon_aead128_init(&ctx, key, nonce);
    ascon_aead128_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_ct_bytes = ascon_aead128_encrypt_update(&ctx, ciphertext,
                                                             plaintext,
                                                             plaintext_len);
    ascon_aead128_encrypt_final(&ctx, ciphertext + new_ct_bytes,
                                tag, tag_len);
}

ASCON_API bool
ascon_aead128_decrypt(uint8_t* plaintext,
                      const uint8_t key[ASCON_AEAD128_KEY_LEN],
                      const uint8_t nonce[ASCON_AEAD_NONCE_LEN],
                      const uint8_t* assoc_data,
                      const uint8_t* ciphertext,
                      const uint8_t* expected_tag,
                      size_t assoc_data_len,
                      size_t ciphertext_len,
                      size_t expected_tag_len)
{
    ASCON_ASSERT(ciphertext_len == 0 || plaintext != NULL);
    ASCON_ASSERT(key != NULL);
    ASCON_ASSERT(nonce != NULL);
    ASCON_ASSERT(assoc_data_len == 0 || assoc_data != NULL);
    ASCON_ASSERT(ciphertext_len == 0 || ciphertext != NULL);
    ASCON_ASSERT(expected_tag_len != 0 || expected_tag != NULL);
    ascon_aead_ctx_t ctx;
    bool is_tag_valid;
    ascon_aead128_init(&ctx, key, nonce);
    ascon_aead128_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_pt_bytes = ascon_aead128_decrypt_update(&ctx,
                                                             plaintext,
                                                             ciphertext,
                                                             ciphertext_len);
    ascon_aead128_decrypt_final(&ctx, plaintext + new_pt_bytes,
                                &is_tag_valid, expected_tag, expected_tag_len);
    return is_tag_valid;
}

ASCON_API void
ascon_aead128_init(ascon_aead_ctx_t* const ctx,
                   const uint8_t key[ASCON_AEAD128_KEY_LEN],
                   const uint8_t nonce[ASCON_AEAD_NONCE_LEN])
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(key != NULL);
    ASCON_ASSERT(nonce != NULL);
    ascon_aead_init(ctx, key, nonce, ASCON_IV_AEAD128);
    ctx->bufstate.flow_state = ASCON_FLOW_AEAD128_80pq_INITIALISED;
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb the associated data to
 * be authenticated, both during encryption and decryption.
 */
static void
absorb_assoc_data(ascon_sponge_t* sponge,
                  uint8_t* const data_out,
                  const uint8_t* const data)
{
    (void) data_out;
    sponge->x0 ^= bigendian_decode_u64(data);
    ascon_permutation_6(sponge);
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb the ciphertext
 * and squeeze out plaintext during decryption.
 */
static void
absorb_ciphertext(ascon_sponge_t* const sponge,
                  uint8_t* const plaintext,
                  const uint8_t* const ciphertext)
{
    // Absorb the ciphertext.
    const uint64_t c_0 = bigendian_decode_u64(ciphertext);
    // Squeeze out some plaintext
    bigendian_encode_u64(plaintext, sponge->x0 ^ c_0);
    sponge->x0 = c_0;
    // Permute the state
    ascon_permutation_6(sponge);
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb the plaintext
 * and squeeze out ciphertext during encryption.
 */
static void
absorb_plaintext(ascon_sponge_t* const sponge,
                 uint8_t* const ciphertext,
                 const uint8_t* const plaintext)
{
    // Absorb the plaintext.
    sponge->x0 ^= bigendian_decode_u64(plaintext);
    // Squeeze out some ciphertext
    bigendian_encode_u64(ciphertext, sponge->x0);
    // Permute the state
    ascon_permutation_6(sponge);
}

ASCON_API void
ascon_aead128_assoc_data_update(ascon_aead_ctx_t* const ctx,
                                const uint8_t* assoc_data,
                                size_t assoc_data_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(assoc_data_len == 0 || assoc_data != NULL);
    ASCON_ASSERT(ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_INITIALISED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED);
    if (assoc_data_len > 0)
    {
        ctx->bufstate.flow_state = ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED;
        buffered_accumulation(&ctx->bufstate, NULL, assoc_data,
                              absorb_assoc_data, assoc_data_len, ASCON_RATE);
    }
}

ASCON_API size_t
ascon_aead128_encrypt_update(ascon_aead_ctx_t* const ctx,
                             uint8_t* ciphertext,
                             const uint8_t* plaintext,
                             size_t plaintext_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(plaintext_len == 0 || plaintext != NULL);
    ASCON_ASSERT(plaintext_len == 0 || ciphertext != NULL);
    ASCON_ASSERT(ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_INITIALISED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED);
    if (ctx->bufstate.flow_state != ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED)
    {
        // Finalise the associated data if not already done sos.
        ascon_aead128_80pq_finalise_assoc_data(ctx);
    }
    ctx->bufstate.flow_state = ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED;
    // Start absorbing plaintext and simultaneously squeezing out ciphertext
    return buffered_accumulation(&ctx->bufstate, ciphertext, plaintext,
                                 absorb_plaintext, plaintext_len, ASCON_RATE);
}

ASCON_API size_t
ascon_aead128_encrypt_final(ascon_aead_ctx_t* const ctx,
                            uint8_t* const ciphertext,
                            uint8_t* tag,
                            size_t tag_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(ciphertext != NULL);
    ASCON_ASSERT(tag_len == 0 || tag != NULL);
    ASCON_ASSERT(ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_INITIALISED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED);
    if (ctx->bufstate.flow_state != ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED)
    {
        // Finalise the associated data if not already done sos.
        ascon_aead128_80pq_finalise_assoc_data(ctx);
    }
    size_t freshly_generated_ciphertext_len = 0;
    // If there is any remaining less-than-a-block plaintext to be absorbed
    // cached in the buffer, pad it and absorb it.
    ctx->bufstate.sponge.x0 ^= bigendian_decode_varlen(ctx->bufstate.buffer,
                                                       ctx->bufstate.buffer_len);
    ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
    // Squeeze out last ciphertext bytes, if any.
    bigendian_encode_varlen(ciphertext, ctx->bufstate.sponge.x0, ctx->bufstate.buffer_len);
    freshly_generated_ciphertext_len += ctx->bufstate.buffer_len;
    // End of encryption, start of tag generation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->bufstate.sponge.x1 ^= ctx->k0;
    ctx->bufstate.sponge.x2 ^= ctx->k1;
    ascon_permutation_12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    // Squeeze out tag into its buffer.
    ascon_aead_generate_tag(ctx, tag, tag_len);
    // Final security cleanup of the internal state, key and buffer.
    ascon_aead_cleanup(ctx);
    return freshly_generated_ciphertext_len;
}

ASCON_API size_t
ascon_aead128_decrypt_update(ascon_aead_ctx_t* const ctx,
                             uint8_t* plaintext,
                             const uint8_t* ciphertext,
                             size_t ciphertext_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(ciphertext_len == 0 || ciphertext != NULL);
    ASCON_ASSERT(ciphertext_len == 0 || plaintext != NULL);
    ASCON_ASSERT(ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_INITIALISED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED
                 || ctx->bufstate.flow_state == ASCON_FLOW_AEAD128_80pq_DECRYPT_UPDATED);
    if (ctx->bufstate.flow_state != ASCON_FLOW_AEAD128_80pq_DECRYPT_UPDATED)
    {
        // Finalise the associated data if not already done sos.
        ascon_aead128_80pq_finalise_assoc_data(ctx);
    }
    ctx->bufstate.flow_state = ASCON_FLOW_AEAD128_80pq_DECRYPT_UPDATED;
    // Start absorbing ciphertext and simultaneously squeezing out plaintext
    return buffered_accumulation(&ctx->bufstate, plaintext, ciphertext,
                                 absorb_ciphertext, ciphertext_len, ASCON_RATE);
}

ASCON_API size_t
ascon_aead128_decrypt_final(ascon_aead_ctx_t* const ctx,
                            uint8_t* plaintext,
                            bool* const is_tag_valid,
                            const uint8_t* const expected_tag,
                            size_t expected_tag_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(plaintext != NULL);
    ASCON_ASSERT(expected_tag_len == 0 || expected_tag != NULL);
    ASCON_ASSERT(is_tag_valid != NULL);
    if (ctx->bufstate.flow_state != ASCON_FLOW_AEAD128_80pq_DECRYPT_UPDATED)
    {
        // Finalise the associated data if not already done sos.
        ascon_aead128_80pq_finalise_assoc_data(ctx);
    }
    size_t freshly_generated_plaintext_len = 0;
    // If there is any remaining less-than-a-block ciphertext to be absorbed
    // cached in the buffer, pad it and absorb it.
    const uint64_t c_0 = bigendian_decode_varlen(ctx->bufstate.buffer,
                                                 ctx->bufstate.buffer_len);
    // Squeeze out last plaintext bytes, if any.
    bigendian_encode_varlen(plaintext, ctx->bufstate.sponge.x0 ^ c_0,
                            ctx->bufstate.buffer_len);
    freshly_generated_plaintext_len += ctx->bufstate.buffer_len;
    // Final state changes at decryption's end
    ctx->bufstate.sponge.x0 &= ~mask_most_signif_bytes(ctx->bufstate.buffer_len);
    ctx->bufstate.sponge.x0 |= c_0;
    ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
    // End of decryption, start of tag validation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->bufstate.sponge.x1 ^= ctx->k0;
    ctx->bufstate.sponge.x2 ^= ctx->k1;
    ascon_permutation_12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    // Validate tag with variable len
    *is_tag_valid = ascon_aead_is_tag_valid(ctx, expected_tag, expected_tag_len);
    // Final security cleanup of the internal state and key.
    ascon_aead_cleanup(ctx);
    return freshly_generated_plaintext_len;
}

/*

int ascon_test() 
{
    // We need the key and the nonce, both 128 bits.

    // 突然忘了大多数AEAD还需要个nonce作为initial state, 不过这个也好解决, 就是得多一些操作和数据
    const uint8_t secret_key[ASCON_AEAD128_KEY_LEN] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
    };
    const uint8_t unique_nonce[ASCON_AEAD_NONCE_LEN] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
    };

    const char associated_data[] = "1 contiguous message will follow.";
    const char plaintext[] = "Hello, I'm a secret message and I should be encrypted!";

    uint8_t buffer[100];
    uint8_t tag[42];
    // To showcase the LibAscon extensions, we will generate an arbitrary-length
    // tag. Here is 42 bytes, but shorter-than-default (16) tags are also
    // possible e.g. 12 bytes for systems with heavy limitations.

    // 这直接用就成, 不用管什么init update那些, 那些感觉是团队针对流式数据设计的.
    ascon_aead128_encrypt(buffer,
                        tag,
                        secret_key,
                        unique_nonce,
                        (uint8_t*) associated_data,
                        (uint8_t*) plaintext,
                        strlen(associated_data),
                        strlen(plaintext),
                        sizeof(tag));
    // The function zeroes out the context automatically.

    // The decryption looks almost the same. Just for fun, we will again
    // reuse the same buffer where the ciphertext is to write the plaintext into.
    bool is_tag_valid = ascon_aead128_decrypt(buffer, // Output plaintext
                                            secret_key,
                                            unique_nonce,
                                            (uint8_t*) associated_data,
                                            (uint8_t*) buffer, // Input ciphertext,
                                            tag, // Expected tag the ciphertext comes with
                                            strlen(associated_data),
                                            strlen(plaintext),
                                            sizeof(tag));
    // This time we get a boolean as a return value, which is true when
    // the tag is OK. To avoid confusion, it can also be compared to
    // two handy macros
    if (is_tag_valid == ASCON_TAG_OK) {
        puts("Correct decryption!");
    } else { // ASCON_TAG_INVALID
        puts("Something went wrong!");
    }
    // The function zeroes out the context automatically.
    return 0;
}

*/