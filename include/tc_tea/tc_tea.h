#pragma once

#include <cstddef>
#include <cstdint>

#include <span>
#include <vector>

namespace tc_tea {
void ECB_DecryptBlock(std::span<uint8_t, 8> block, std::span<const uint32_t, 4> key);
void ECB_EncryptBlock(std::span<uint8_t, 8> block, std::span<const uint32_t, 4> key);

bool CBC_Decrypt(std::vector<uint8_t>& plaintext, std::span<const uint8_t> cipher, std::span<const uint8_t, 16> key);

std::size_t CBC_GetEncryptedSize(std::size_t cipher_text_size);

bool CBC_Encrypt(std::vector<uint8_t>& cipher, std::span<const uint8_t> plain, std::span<const uint8_t, 16> key);

inline std::vector<uint8_t> CBC_Decrypt(std::span<const uint8_t> cipher, std::span<const uint8_t, 16> key) {
    std::vector<uint8_t> result;
    CBC_Decrypt(result, cipher, key);
    return result;
}

inline std::vector<uint8_t> CBC_Encrypt(std::span<const uint8_t> plain, std::span<const uint8_t, 16> key) {
    std::vector<uint8_t> result;
    CBC_Encrypt(result, plain, key);
    return result;
}

}  // namespace tc_tea
