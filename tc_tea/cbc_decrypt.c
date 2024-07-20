#include <tc_tea/tc_tea.h>

#include <memory.h>

#define TC_TEA_MIN(a, b) (((a) < (b)) ? (a) : (b))

static inline void tc_tea_memory_xor(uint8_t* dst, size_t len, const uint8_t* src1, const uint8_t* src2) {
  for (size_t i = 0; i < len; i++) {
    dst[i] = src1[i] ^ src2[i];
  }
}

enum tc_tea_status_t tc_tea_cbc_decrypt(uint8_t* out_plain,
                                        size_t* in_out_plain_len,
                                        const uint8_t* in_cipher,
                                        size_t in_cipher_len,
                                        const uint32_t* key) {
  // It needs to have at least 2 blocks long, due to the nature of the padding scheme used.
  if (in_cipher_len % TC_TEA_ECB_BLOCK_SIZE != 0 || in_cipher_len < TC_TEA_ECB_BLOCK_SIZE * 2) {
    return TC_TEA_ERR_WRONG_CIPHER_LENGTH;
  }

  uint8_t* plain_start = out_plain;
  const uint8_t* cipher_end = in_cipher + in_cipher_len;

  uint8_t block[TC_TEA_ECB_BLOCK_SIZE] = {};
  uint8_t iv[TC_TEA_ECB_BLOCK_SIZE] = {};
  memcpy(block, in_cipher, TC_TEA_ECB_BLOCK_SIZE);
  in_cipher += TC_TEA_ECB_BLOCK_SIZE;
  tc_tea_ecb_decrypt_block(block, key);  // decrypt first block

  size_t padding_len = (size_t)(block[0] & 0x07);
  size_t salt_prefix_len = 1 + PRIVATE_TC_TEA_CBC_FIXED_SALT + padding_len;
  size_t data_len = in_cipher_len - salt_prefix_len - PRIVATE_TC_TEA_CBC_ZERO_PAD;

  // region Check output plain text buffer length
  if (*in_out_plain_len < data_len) {
    *in_out_plain_len = data_len;
    return TC_TEA_ERR_BUFFER_TOO_SMALL;
  }
  *in_out_plain_len = data_len;
  uint8_t* plain_end = out_plain + data_len;
  // endregion

  if (salt_prefix_len > TC_TEA_ECB_BLOCK_SIZE) {
    // Nothing to write in first block, decrypt second block in this case.
    tc_tea_memory_xor(iv, TC_TEA_ECB_BLOCK_SIZE, block, in_cipher);  // init iv here!
    tc_tea_ecb_decrypt_block(iv, key);
    tc_tea_memory_xor(block, TC_TEA_ECB_BLOCK_SIZE, in_cipher - TC_TEA_ECB_BLOCK_SIZE, iv);
    in_cipher += TC_TEA_ECB_BLOCK_SIZE;

    salt_prefix_len -= TC_TEA_ECB_BLOCK_SIZE;
  } else {
    // init iv for the first time
    memcpy(iv, block, TC_TEA_ECB_BLOCK_SIZE);
  }
  size_t write_len = TC_TEA_MIN(TC_TEA_ECB_BLOCK_SIZE - salt_prefix_len, data_len);
  memcpy(out_plain, block + salt_prefix_len, write_len);
  out_plain += write_len;
  data_len -= write_len;

  // Process whole blocks
  while (in_cipher < cipher_end) {
    tc_tea_memory_xor(iv, TC_TEA_ECB_BLOCK_SIZE, iv, in_cipher);
    tc_tea_ecb_decrypt_block(iv, key);
    tc_tea_memory_xor(block, TC_TEA_ECB_BLOCK_SIZE, in_cipher - TC_TEA_ECB_BLOCK_SIZE, iv);
    in_cipher += TC_TEA_ECB_BLOCK_SIZE;

    write_len = TC_TEA_MIN(TC_TEA_ECB_BLOCK_SIZE, data_len);
    memcpy(out_plain, block, write_len);
    out_plain += write_len;
    data_len -= write_len;
  }

  // region Verify block ends with specified number of zeros
  uint8_t verify = {0};
  for (int i = TC_TEA_ECB_BLOCK_SIZE - PRIVATE_TC_TEA_CBC_ZERO_PAD; i < TC_TEA_ECB_BLOCK_SIZE; i++) {
    verify |= block[i];
  }
  if (verify != 0) {
    memset(plain_start, 0, *in_out_plain_len);
    return TC_TEA_ERR_ZERO_PADDING_VERIFY_FAILED;
  }
  // endregion

  return TC_TEA_OK;
}
