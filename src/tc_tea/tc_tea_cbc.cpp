#include "tc_tea/tc_tea.h"

#include "utils/EndianHelper.h"
#include "utils/utils.h"

#include <cstddef>

#include <algorithm>
#include <array>

namespace tc_tea {
constexpr std::size_t TEA_SALT_SIZE = 2;
constexpr std::size_t TEA_PADDING_ZERO_SIZE = 7;
constexpr std::size_t TEA_MIN_CIPHER_TEXT_SIZE = 1 + TEA_SALT_SIZE + TEA_PADDING_ZERO_SIZE;

bool CBC_Decrypt(std::vector<uint8_t>& plain, std::span<const uint8_t> cipher, std::span<const uint8_t, 16> key) {
    plain.resize(0);

    std::array<uint32_t, 4> k;
    utils::ParseBigEndianKey(k, key);

    if (cipher.size() < TEA_MIN_CIPHER_TEXT_SIZE || cipher.size() % 8 != 0) {
        return false;
    }

    plain.assign(cipher.begin(), cipher.end());
    auto p_plain = std::span{plain};
    auto cipher_size = cipher.size();

    // decrypt first block
    ECB_DecryptBlock(std::span<uint8_t, 8>{&p_plain[0], 8}, k);
    for (std::size_t i = 8; i < cipher_size; i += 8) {
        // xor with previous block first

        utils::XorRange<8>(&p_plain[i], &p_plain[i - 8]);
        ECB_DecryptBlock(std::span<uint8_t, 8>{&p_plain[i], 8}, k);
    }

    // Hint compiler that we are XOR block of 8.
    for (std::size_t i = 8; i < cipher_size; i += 8) {
        utils::XorRange<8>(&p_plain[i], &cipher[i - 8]);
    }

    auto pad_size = static_cast<std::size_t>(p_plain[0] & uint8_t{0b0111});
    std::size_t start_loc = std::size_t{1} + pad_size + TEA_SALT_SIZE;
    std::size_t end_loc = cipher_size - TEA_PADDING_ZERO_SIZE;

    // Constant time zero check
    auto zero_padding_validation = uint8_t{0};
    for (std::size_t i = 0; i < TEA_PADDING_ZERO_SIZE; i++) {
        zero_padding_validation |= p_plain[end_loc + i];
    }

    if (zero_padding_validation == uint8_t{0}) {
        plain.erase(plain.begin() + end_loc, plain.end());
        plain.erase(plain.begin(), plain.begin() + start_loc);
        return true;
    } else {
        plain.resize(0);
        return false;
    }
}

std::size_t CBC_GetEncryptedSize(std::size_t size) {
    std::size_t len = TEA_MIN_CIPHER_TEXT_SIZE + size;
    std::size_t pad_len = (8 - (len & 0b0111)) & 0b0111;
    return len + pad_len;
}

bool CBC_Encrypt(std::vector<uint8_t>& cipher, std::span<const uint8_t> plain, std::span<const uint8_t, 16> key) {
    std::array<uint32_t, 4> k;
    utils::ParseBigEndianKey(k, key);

    std::size_t len = TEA_MIN_CIPHER_TEXT_SIZE + plain.size();
    std::size_t pad_len = (8 - (len & 0b0111)) & 0b0111;
    len += pad_len;
    cipher.resize(len);
    auto p_cipher = std::span{cipher};

    std::size_t header_size = 1 + pad_len + TEA_SALT_SIZE;

    utils::GenerateRandomBytes(std::span{p_cipher.data(), header_size});

    p_cipher[0] = (p_cipher[0] & uint8_t{0b1111'1000}) | static_cast<uint8_t>(pad_len & 0b0000'0111);
    std::ranges::copy(plain.begin(), plain.end(), &p_cipher[header_size]);

    // Process first block
    std::array<uint8_t, 8> iv2;
    std::array<uint8_t, 8> next_iv2;

    std::copy_n(&p_cipher[0], 8, iv2.begin());
    ECB_EncryptBlock(std::span<uint8_t, 8>(&p_cipher[0], 8), k);

    for (std::size_t i = 8; i < len; i += 8) {
        // XOR previous cipher block
        utils::XorRange<8>(&p_cipher[i], &p_cipher[i - 8]);

        // store iv2
        std::copy_n(&p_cipher[i], 8, next_iv2.begin());

        // TEA ECB
        ECB_EncryptBlock(std::span<uint8_t, 8>(&p_cipher[i], 8), k);

        // XOR iv2
        utils::XorRange<8>(&p_cipher[i], &iv2[0]);

        iv2 = next_iv2;
    }

    return true;
}

}  // namespace tc_tea
