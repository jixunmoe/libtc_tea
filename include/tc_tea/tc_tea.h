#pragma once

#include <cstddef>
#include <cstdint>

#include <vector>

namespace tc_tea
{

void ECB_DecryptBlock(uint8_t *block, const uint32_t *key);
void ECB_EncryptBlock(uint8_t *block, const uint32_t *key);

bool CBC_Decrypt(std::vector<uint8_t> &plaintext, const uint8_t *cipher, size_t cipher_len, const uint8_t *key);

size_t CBC_GetEncryptedSize(size_t cipher_text_size);

bool CBC_Encrypt(std::vector<uint8_t> &cipher, const uint8_t *plain, size_t cipher_len, const uint8_t *key);

inline std::vector<uint8_t> CBC_Decrypt(const uint8_t *cipher, size_t cipher_len, const uint8_t *key)
{
    std::vector<uint8_t> result;
    CBC_Decrypt(result, cipher, cipher_len, key);
    return result;
}

inline std::vector<uint8_t> CBC_Encrypt(const uint8_t *plain, size_t plain_len, const uint8_t *key)
{
    std::vector<uint8_t> result;
    CBC_Encrypt(result, plain, plain_len, key);
    return result;
}

} // namespace tc_tea
