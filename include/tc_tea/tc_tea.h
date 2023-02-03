#pragma once

#include <cstddef>
#include <cstdint>

#include <vector>

namespace tc_tea
{

void ECB_DecryptBlock(uint8_t *block, const uint32_t *key);
void ECB_EncryptBlock(uint8_t *block, const uint32_t *key);

size_t CBC_GetEncryptedSize(size_t cipher_text_size);

bool CBC_Decrypt(uint8_t *plain, size_t *p_plain_len, const uint8_t *cipher, size_t cipher_len, const uint8_t *key);
bool CBC_Encrypt(uint8_t *cipher, size_t *p_cipher_len, const uint8_t *plain, size_t plain_len, const uint8_t *key);

inline std::vector<uint8_t> CBC_Decrypt(const std::vector<uint8_t> &cipher, const uint8_t *key)
{
    size_t plain_len = cipher.size();
    std::vector<uint8_t> plain(plain_len);
    CBC_Decrypt(plain.data(), &plain_len, cipher.data(), plain_len, key);
    plain.resize(plain_len);
    return plain;
}

inline std::vector<uint8_t> CBC_Encrypt(const std::vector<uint8_t> &plain, const uint8_t *key)
{
    size_t cipher_len = CBC_GetEncryptedSize(plain.size());
    std::vector<uint8_t> cipher(cipher_len);
    CBC_Encrypt(cipher.data(), &cipher_len, plain.data(), plain.size(), key);
    cipher.resize(cipher_len);
    return cipher;
}

} // namespace tc_tea
