#include "tc_tea/tc_tea.h"

#include "utils/EndianHelper.h"
#include "utils/utils.h"

#include <cstddef>

#include <algorithm>
#include <array>

namespace tc_tea
{

constexpr size_t TEA_SALT_SIZE = 2;
constexpr size_t TEA_PADDING_ZERO_SIZE = 7;
constexpr size_t TEA_MIN_CIPHER_TEXT_SIZE = 1 + TEA_SALT_SIZE + TEA_PADDING_ZERO_SIZE;

bool CBC_Decrypt(std::vector<uint8_t> &plain, const uint8_t *cipher, size_t cipher_len, const uint8_t *key)
{
    plain.resize(0);

    std::array<uint32_t, 4> k;
    utils::ParseBigEndianKey(&k[0], key);

    if (cipher_len < TEA_MIN_CIPHER_TEXT_SIZE || cipher_len % 8 != 0)
    {
        return false;
    }

    plain.assign(cipher, cipher + cipher_len);

    // decrypt first block
    ECB_DecryptBlock(&plain[0], &k[0]);
    for (size_t i = 8; i < cipher_len; i += 8)
    {
        // xor with previous block first
        utils::XorRange<8>(&plain[i], &plain[i - 8]);
        ECB_DecryptBlock(&plain[i], &k[0]);
    }

    // Hint compiler that we are XOR block of 8.
    for (size_t i = 8; i < cipher_len; i += 8)
    {
        utils::XorRange<8>(&plain[i], &cipher[i - 8]);
    }

    auto pad_size = static_cast<size_t>(plain[0] & uint8_t{0b0111});
    size_t start_loc = size_t{1} + pad_size + TEA_SALT_SIZE;
    size_t end_loc = cipher_len - TEA_PADDING_ZERO_SIZE;

    // Constant time zero check
    auto zero_padding_validation = uint8_t{0};
    for (size_t i = 0; i < TEA_PADDING_ZERO_SIZE; i++)
    {
        zero_padding_validation |= plain[end_loc + i];
    }

    if (zero_padding_validation == uint8_t{0})
    {
        plain.erase(plain.begin() + end_loc, plain.end());
        plain.erase(plain.begin(), plain.begin() + start_loc);
        return true;
    }
    else
    {
        plain.resize(0);
        return false;
    }
}

size_t CBC_GetEncryptedSize(size_t size)
{
    size_t len = TEA_MIN_CIPHER_TEXT_SIZE + size;
    size_t pad_len = (8 - (len & 0b0111)) & 0b0111;
    return len + pad_len;
}

bool CBC_Encrypt(std::vector<uint8_t> &cipher, const uint8_t *plain, size_t plain_len, const uint8_t *key)
{
    std::array<uint32_t, 4> k;
    utils::ParseBigEndianKey(&k[0], key);

    size_t len = TEA_MIN_CIPHER_TEXT_SIZE + plain_len;
    size_t pad_len = (8 - (len & 0b0111)) & 0b0111;
    len += pad_len;
    cipher.resize(len);

    size_t header_size = 1 + pad_len + TEA_SALT_SIZE;

    utils::GenerateRandomBytes(cipher.data(), header_size);

    cipher[0] = (cipher[0] & uint8_t{0b1111'1000}) | static_cast<uint8_t>(pad_len & 0b0000'0111);
    std::copy_n(plain, plain_len, &cipher[header_size]);

    // Process first block
    std::array<uint8_t, 8> iv2;
    std::array<uint8_t, 8> next_iv2;

    std::copy_n(&cipher[0], 8, iv2.begin());
    ECB_EncryptBlock(&cipher[0], &k[0]);

    for (size_t i = 8; i < len; i += 8)
    {
        // XOR previous cipher block
        utils::XorRange<8>(&cipher[i], &cipher[i - 8]);

        // store iv2
        std::copy_n(&cipher[i], 8, next_iv2.begin());

        // TEA ECB
        ECB_EncryptBlock(&cipher[i], &k[0]);

        // XOR iv2
        utils::XorRange<8>(&cipher[i], &iv2[0]);

        iv2 = next_iv2;
    }

    return true;
}

} // namespace tc_tea
