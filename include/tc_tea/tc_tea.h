#pragma once

#include <cstddef>
#include <cstdint>

#include <span>
#include <vector>

namespace tc_tea {
void ECB_DecryptBlock(std::span<std::byte, 8> block, std::span<const uint32_t, 4> key);
void ECB_EncryptBlock(std::span<std::byte, 8> block, std::span<const uint32_t, 4> key);

bool CBC_Decrypt(std::vector<std::byte>& plaintext,
                 std::span<const std::byte> cipher,
                 std::span<const std::byte, 16> key);

std::size_t CBC_GetEncryptedSize(std::size_t cipher_text_size);

bool CBC_Encrypt(std::vector<std::byte>& cipher, std::span<const std::byte> plain, std::span<const std::byte, 16> key);

inline std::vector<std::byte> CBC_Decrypt(std::span<const std::byte> cipher, std::span<const std::byte, 16> key) {
    std::vector<std::byte> result;
    CBC_Decrypt(result, cipher, key);
    return result;
}

inline std::vector<std::byte> CBC_Encrypt(std::span<const std::byte> plain, std::span<const std::byte, 16> key) {
    std::vector<std::byte> result;
    CBC_Encrypt(result, plain, key);
    return result;
}

}  // namespace tc_tea
