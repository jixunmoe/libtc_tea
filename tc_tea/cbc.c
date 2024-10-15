#include "ecb.h"
#include "tc_tea/tc_tea.h"
#include "tea_utils.h"

#include <assert.h>
#include <memory.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

inline static void decrypt_round(uint8_t* p_plain,
                                 const uint8_t* p_cipher,
                                 uint64_t* iv1,
                                 uint64_t* iv2,
                                 const uint32_t* key) {
    uint64_t iv1_next = tc_tea_be_u64_read(p_cipher);
    uint64_t iv2_next = tc_tea_ecb_decrypt_block(iv1_next ^ *iv2, key);
    uint64_t plain = iv2_next ^ *iv1;
    *iv1 = iv1_next;
    *iv2 = iv2_next;
    tc_tea_be_u64_write(p_plain, plain);
}

tc_tea_status_t tc_tea_cbc_decrypt(uint8_t* out_plain,
                                   size_t* in_out_plain_len,
                                   const uint8_t* in_cipher,
                                   size_t in_cipher_len,
                                   const uint32_t* key) {
    // It needs to have at least 2 blocks long, due to the nature of the padding scheme used.
    if (in_cipher_len % TC_TEA_ECB_BLOCK_SIZE != 0 || in_cipher_len < TC_TEA_ECB_BLOCK_SIZE * 2) {
        return TC_TEA_ERR_WRONG_CIPHER_LENGTH;
    }

    uint64_t iv1 = 0;
    uint64_t iv2 = 0;
    uint8_t header[TC_TEA_ECB_BLOCK_SIZE * 2];
    decrypt_round(header, in_cipher, &iv1, &iv2, key);
    in_cipher += TC_TEA_ECB_BLOCK_SIZE;
    decrypt_round(header + TC_TEA_ECB_BLOCK_SIZE, in_cipher, &iv1, &iv2, key);
    in_cipher += TC_TEA_ECB_BLOCK_SIZE;

    size_t hdr_skip_len = 1 + (header[0] & 7) + PRIVATE_TC_TEA_CBC_FIXED_SALT;
    size_t real_plain_len = in_cipher_len - hdr_skip_len - PRIVATE_TC_TEA_CBC_ZERO_PAD;
    if (*in_out_plain_len < real_plain_len) {
        *in_out_plain_len = real_plain_len;
        return TC_TEA_ERR_BUFFER_TOO_SMALL;
    }

    // copy first block of plain text
    uint8_t* p_output = out_plain;
    size_t copy_len = TC_TEA_MIN(sizeof(header) - hdr_skip_len, real_plain_len);
    memcpy(p_output, header + hdr_skip_len, real_plain_len);
    p_output += copy_len;

    if (real_plain_len != copy_len) {
        // Decrypt the rest of the blocks
        for (size_t i = in_cipher_len - TC_TEA_ECB_BLOCK_SIZE * 3; i != 0; i -= TC_TEA_ECB_BLOCK_SIZE) {
            decrypt_round(p_output, in_cipher, &iv1, &iv2, key);
            in_cipher += TC_TEA_ECB_BLOCK_SIZE;
            p_output += TC_TEA_ECB_BLOCK_SIZE;
        }

        decrypt_round(header + TC_TEA_ECB_BLOCK_SIZE, in_cipher, &iv1, &iv2, key);
        p_output[0] = header[TC_TEA_ECB_BLOCK_SIZE];
    }
    // Validate zero padding
    uint8_t verify = {0};
    for (int i = 0; i < PRIVATE_TC_TEA_CBC_ZERO_PAD; i++) {
        verify |= header[TC_TEA_ECB_BLOCK_SIZE + 1 + i];
    }
    if (verify != 0) {
        memset(out_plain, 0, *in_out_plain_len);
        *in_out_plain_len = 0;
        return TC_TEA_ERR_ZERO_PADDING_VERIFY_FAILED;
    }

    *in_out_plain_len = real_plain_len;

    return TC_TEA_OK;
}

size_t tc_tea_cbc_encrypt(uint8_t* out_cipher,
                          const uint8_t* plain,
                          size_t plain_len,
                          const uint32_t* key,
                          const uint8_t* salt) {
    size_t out_len = plain_len + (1 + PRIVATE_TC_TEA_CBC_FIXED_SALT + PRIVATE_TC_TEA_CBC_ZERO_PAD);
    size_t extra_salt_len = (8 - (out_len % 8)) % 8;
    out_len += extra_salt_len;
    size_t header_padding_len = 1 + extra_salt_len + PRIVATE_TC_TEA_CBC_FIXED_SALT;
    memcpy(out_cipher, salt, header_padding_len);
    out_cipher[0] = (salt[0] << 3) | (extra_salt_len & 7);
    memcpy(&out_cipher[header_padding_len], plain, plain_len);
    memset(&out_cipher[header_padding_len + plain_len], 0, PRIVATE_TC_TEA_CBC_ZERO_PAD);

    uint64_t iv1 = 0;
    uint64_t iv2 = 0;
    uint8_t* p_output = out_cipher;
    for (size_t i = out_len; i != 0; i -= 8) {
        uint64_t block = tc_tea_be_u64_read(p_output);
        uint64_t iv2_next = block ^ iv1;
        uint64_t iv1_next = tc_tea_ecb_encrypt_block(iv2_next, key) ^ iv2;
        tc_tea_be_u64_write(p_output, iv1_next);
        p_output += 8;
        iv1 = iv1_next;
        iv2 = iv2_next;
    }
    return out_len;
}

size_t tc_tea_cbc_encrypt_insecure(uint8_t* cipher, const uint8_t* plain, size_t plain_len, const uint32_t* key) {
    // discard some random digits
    uint8_t salt[10];  // get some randomness from the stack

    for (int i = ((key[2] ^ salt[0]) & 0xf0) + 0x10; i != 0; i--) {
        rand();
    }

    // Generate salt
    for (int i = 0; i < sizeof(salt); i++) {
        salt[i] ^= rand();
    }

    size_t result = tc_tea_cbc_encrypt(cipher, plain, plain_len, key, salt);
    memset(salt, 0, sizeof(salt));
    return result;
}
