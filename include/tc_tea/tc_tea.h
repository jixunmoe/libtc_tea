#pragma once

#include <stddef.h>
#include <stdint.h>

#include "tc_tea/api.h"

typedef enum {
    TC_TEA_OK = 0,
    TC_TEA_ERR_BUFFER_TOO_SMALL = 1,
    TC_TEA_ERR_WRONG_CIPHER_LENGTH = 2,
    TC_TEA_ERR_ZERO_PADDING_VERIFY_FAILED = 3,
} tc_tea_status_t;

/** @hide */
#define TC_TEA_ECB_BLOCK_SIZE (8)

/** @hide */
#define PRIVATE_TC_TEA_CBC_FIXED_SALT (2)
/** @hide */
#define PRIVATE_TC_TEA_CBC_ZERO_PAD (7)

/**
 * Convert key for use in tc_tea.
 * @param dest Destination of parsed key, `uint32_t[4]`
 * @param key Key in bytes, `uint8_t[16]`
 */
static inline void tc_tea_parse_key(uint32_t* dest, const uint8_t* key) {
    for (int i = 0; i < 0x10; i += 4) {
        *dest++ = ((uint32_t)(key[i]) << 0x18)         //
                  | ((uint32_t)(key[i + 1]) << 0x10)   //
                  | ((uint32_t)(key[i + 2]) << 0x08)   //
                  | ((uint32_t)(key[i + 3]) << 0x00);  //
    }
}

/**
 * Get cipher buffer length by plain text length.
 * @param plain_text_length
 * @return Calculated cipher buffer length
 */
static inline size_t tc_tea_cbc_get_cipher_len(size_t plain_text_length) {
    // padded input: pad_marker || FIXED_SALT || SALT_PADDING || PLAIN_TEXT || ZERO
    size_t len = 1 /* pad marker */ + PRIVATE_TC_TEA_CBC_FIXED_SALT + PRIVATE_TC_TEA_CBC_ZERO_PAD;
    len += plain_text_length;

    // padding at the beginning.
    if (len % TC_TEA_ECB_BLOCK_SIZE != 0) {
        len += TC_TEA_ECB_BLOCK_SIZE - (len % TC_TEA_ECB_BLOCK_SIZE);
    }
    return len;
}

TC_TEA_API tc_tea_status_t tc_tea_cbc_decrypt(uint8_t* out_plain,
                                              size_t* in_out_plain_len,
                                              const uint8_t* in_cipher,
                                              size_t in_cipher_len,
                                              const uint32_t* key);

/**
 * Perform tc_tea in cbc mode.
 * @param out_cipher Pointer to the output buffer, need to be at least `plain_len` in size.
 * @param plain Input buffer
 * @param plain_len Input buffer length
 * @param key Encryption key
 * @param salt 10 secure random bytes.
 * @return bytes written to `out_cipher`
 */
TC_TEA_API size_t tc_tea_cbc_encrypt(uint8_t* out_cipher,
                                     const uint8_t* plain,
                                     size_t plain_len,
                                     const uint32_t* key,
                                     const uint8_t* salt);

/**
 * Insecure version of {@link tc_tea_cbc_encrypt}.
 * User will need to initialize random seed via `srand(time(NULL));`.
 * @param cipher Pointer to the output buffer, need to be at least `plain_len` in size.
 * @param plain
 * @param plain_len
 * @param key
 * @return bytes written to `out_cipher`
 */
TC_TEA_API size_t tc_tea_cbc_encrypt_insecure(uint8_t* cipher,
                                              const uint8_t* plain,
                                              size_t plain_len,
                                              const uint32_t* key);
