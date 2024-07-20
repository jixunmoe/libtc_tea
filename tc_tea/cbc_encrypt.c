#include "tc_tea/tc_tea.h"

#include <assert.h>
#include <memory.h>

#ifdef TC_TEA_BUILD_INSECURE
#include <stdlib.h>
#endif

#define TC_TEA_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define TC_TEA_ALLOW_UNUSED_VARIABLE(v) (void)(v)

static inline void tc_tea_cbc_swap_iv2(uint8_t** iv2, uint8_t** iv2_next) {
  uint8_t* temp = *iv2;
  *iv2 = *iv2_next;
  *iv2_next = temp;
}

static inline void tc_tea_cbc_encrypt_round(uint8_t* cipher,
                                            const uint8_t* plain,
                                            const uint32_t* key,
                                            const uint8_t* iv1,
                                            const uint8_t* iv2,
                                            uint8_t* next_iv2) {
  uint8_t temp[TC_TEA_ECB_BLOCK_SIZE] = {};
  for (int i = 0; i < TC_TEA_ECB_BLOCK_SIZE; i++) {
    temp[i] = plain[i] ^ iv1[i];
  }
  memcpy(next_iv2, temp, TC_TEA_ECB_BLOCK_SIZE);
  tc_tea_ecb_encrypt_block(temp, key);
  for (int i = 0; i < TC_TEA_ECB_BLOCK_SIZE; i++) {
    cipher[i] = temp[i] ^ iv2[i];
  }
}

size_t tc_tea_cbc_encrypt(uint8_t* out_cipher,
                          const uint8_t* plain,
                          size_t plain_len,
                          const uint32_t* key,
                          const uint8_t* salt) {
  uint8_t* cipher_start = out_cipher;
  const uint8_t* plain_end = plain + plain_len;
  TC_TEA_ALLOW_UNUSED_VARIABLE(plain_end);

  size_t cipher_len = tc_tea_cbc_get_cipher_len(plain_len);
  uint8_t* cipher_end = out_cipher + cipher_len;
  size_t total_salt_len = cipher_len - plain_len - PRIVATE_TC_TEA_CBC_ZERO_PAD;
  size_t padding_len = total_salt_len - PRIVATE_TC_TEA_CBC_FIXED_SALT - 1;

  uint8_t header[TC_TEA_ECB_BLOCK_SIZE * 2] = {0};
  uint8_t iv_buffer[TC_TEA_ECB_BLOCK_SIZE * 2] = {0};
  uint8_t* iv1 = iv_buffer;
  uint8_t* iv2 = iv_buffer + TC_TEA_ECB_BLOCK_SIZE;
  uint8_t* iv2_next = iv_buffer;

  size_t initial_plain_len = TC_TEA_MIN(TC_TEA_ECB_BLOCK_SIZE * 2 - total_salt_len, plain_len);
  memcpy(header, salt, total_salt_len);
  memcpy(header + total_salt_len, plain, initial_plain_len);
  plain += initial_plain_len;
  header[0] = (header[0] << 3) | (padding_len);

  // Encrypt first block from initial buffer
  tc_tea_cbc_encrypt_round(out_cipher, header, key, iv1, iv2, iv2_next);
  tc_tea_cbc_swap_iv2(&iv2, &iv2_next);
  out_cipher += TC_TEA_ECB_BLOCK_SIZE;

  // Encrypt second block from initial buffer
  tc_tea_cbc_encrypt_round(out_cipher, header + TC_TEA_ECB_BLOCK_SIZE, key, out_cipher - TC_TEA_ECB_BLOCK_SIZE, iv2,
                           iv2_next);
  tc_tea_cbc_swap_iv2(&iv2, &iv2_next);
  out_cipher += TC_TEA_ECB_BLOCK_SIZE;

  // Are we done yet?
  if (out_cipher < cipher_end) {
    // Last block is special - don't mess with them.
    uint8_t* cipher_before_last_block = cipher_end - TC_TEA_ECB_BLOCK_SIZE;

    while (out_cipher < cipher_before_last_block) {
      assert(plain < plain_end);
      tc_tea_cbc_encrypt_round(out_cipher, plain, key, out_cipher - TC_TEA_ECB_BLOCK_SIZE, iv2, iv2_next);
      tc_tea_cbc_swap_iv2(&iv2, &iv2_next);
      out_cipher += TC_TEA_ECB_BLOCK_SIZE;
      plain += TC_TEA_ECB_BLOCK_SIZE;
    }

    // Process last block - ALL ZEROS except the first byte
    uint8_t last_block[TC_TEA_ECB_BLOCK_SIZE] = {0};
    memcpy(last_block, plain, TC_TEA_ECB_BLOCK_SIZE - PRIVATE_TC_TEA_CBC_ZERO_PAD);
    tc_tea_cbc_encrypt_round(out_cipher, last_block, key, out_cipher - TC_TEA_ECB_BLOCK_SIZE, iv2, iv2_next);
    plain++;
    out_cipher += TC_TEA_ECB_BLOCK_SIZE;
    memset(last_block, 0, sizeof(last_block));
  }

  memset(header, 0, sizeof(header));
  memset(iv_buffer, 0, sizeof(iv_buffer));

  assert(out_cipher == cipher_end);
  assert(plain == plain_end);

  return out_cipher - cipher_start;
}

#ifdef TC_TEA_BUILD_INSECURE
void tc_tea_cbc_encrypt_insecure(uint8_t* cipher, const uint8_t* plain, size_t plain_len, const uint32_t* key) {
  // discard some random digits
  for (int i = (key[2] & 0xff) + 10; i-- > 0;) {
    rand();
  }

  // Generate salt
  uint8_t salt[10];
  for (int i = 0; i < sizeof(salt); i++) {
    salt[i] = rand();
  }

  tc_tea_cbc_encrypt(cipher, plain, plain_len, key, salt);
  memset(salt, 0, sizeof(salt));
}
#endif
