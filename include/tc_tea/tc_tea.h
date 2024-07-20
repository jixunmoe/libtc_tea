#pragma once

#include <stddef.h>
#include <stdint.h>

#include "tc_tea/api.h"

enum tc_tea_status_t {
  TC_TEA_OK = 0,
  TC_TEA_ERR_BUFFER_TOO_SMALL = 1,
  TC_TEA_ERR_WRONG_CIPHER_LENGTH = 2,
  TC_TEA_ERR_ZERO_PADDING_VERIFY_FAILED = 3,
};

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
  for (int i = 0; i < 4; i++) {
    dest[i] = ((uint32_t)(key[i * sizeof(uint32_t)]) << 0x18)         //
              | ((uint32_t)(key[i * sizeof(uint32_t) + 1]) << 0x10)   //
              | ((uint32_t)(key[i * sizeof(uint32_t) + 2]) << 0x08)   //
              | ((uint32_t)(key[i * sizeof(uint32_t) + 3]) << 0x00);  //
  }
}

/**
 * Decrypt a block (8 bytes)
 * @param block Block of input
 * @param key encryption key, 16-bytes (uint32_t[4]).
 */
TC_TEA_API void tc_tea_ecb_decrypt_block(uint8_t* block, const uint32_t* key);

/**
 * Encrypt a block (8 bytes)
 * @param block Block of input
 * @param key encryption key, 16-bytes (uint32_t[4]).
 */
TC_TEA_API void tc_tea_ecb_encrypt_block(uint8_t* block, const uint32_t* key);

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

// bool CBC_Decrypt(uint8_t *plain, size_t *p_plain_len, const uint8_t *out_cipher, size_t cipher_len, const uint8_t
// *key);

TC_TEA_API enum tc_tea_status_t tc_tea_cbc_decrypt(uint8_t* out_plain,
                                                   size_t* in_out_plain_len,
                                                   const uint8_t* in_cipher,
                                                   size_t in_cipher_len,
                                                   const uint32_t* key);

/**
 * Perform tc_tea in cbc mode.
 * @param out_cipher Output buffer of cipher
 * @param plain Input buffer
 * @param plain_len Input buffer length
 * @param key Encryption key
 * @param salt Salt used to pad, where 2 <= len(salt) <= 9
 * @return bytes written to `out_cipher`
 */
TC_TEA_API size_t tc_tea_cbc_encrypt(uint8_t* out_cipher,
                                     const uint8_t* plain,
                                     size_t plain_len,
                                     const uint32_t* key,
                                     const uint8_t* salt);

#ifdef TC_TEA_BUILD_INSECURE
/**
 * Insecure version of {@link tc_tea_cbc_encrypt}.
 * User will need to initialize random seed via `srand(time(NULL));`.
 * @param cipher
 * @param plain
 * @param plain_len
 * @param key
 * @return
 */
TC_TEA_API void tc_tea_cbc_encrypt_insecure(uint8_t* cipher,
                                            const uint8_t* plain,
                                            size_t plain_len,
                                            const uint32_t* key);
#endif
