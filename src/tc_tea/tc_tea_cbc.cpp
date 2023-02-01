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

inline size_t CBC_GetPaddingSize(size_t plain_size)
{
    size_t len = TEA_MIN_CIPHER_TEXT_SIZE + plain_size;
    return (8 - (len & 0b0111)) & 0b0111;
}

size_t CBC_GetEncryptedSize(size_t plain_size)
{
    size_t len = TEA_MIN_CIPHER_TEXT_SIZE + plain_size;
    size_t pad_len = CBC_GetPaddingSize(plain_size);
    return len + pad_len;
}

bool CBC_Decrypt(uint8_t *plain, size_t *p_plain_len, const uint8_t *cipher, size_t cipher_len, const uint8_t *key)
{
    std::array<uint32_t, 4> k;
    ParseBigEndianKey(&k[0], key);

    if (cipher_len < TEA_MIN_CIPHER_TEXT_SIZE || *p_plain_len < cipher_len || cipher_len % 8 != 0)
    {
        return false;
    }

    // decrypt first block
    std::array<uint8_t, 8> block;
    std::copy_n(cipher, 8, block.begin());

    auto p_plain = plain;
    auto p_cipher = cipher;
    auto p_cipher_end = &cipher[cipher_len];

    ECB_DecryptBlock(&block[0], &k[0]);
    p_cipher += 8;

    auto pad_size = static_cast<size_t>(block[0] & uint8_t{0b0111});
    size_t start_loc = size_t{1} + pad_size + TEA_SALT_SIZE;
    size_t end_loc = cipher_len - TEA_PADDING_ZERO_SIZE;

    auto decrypt_next_tea_block = [&](size_t copy_n) {
        XorRange<8>(&block[0], &p_cipher[0], &block[0]);
        ECB_DecryptBlock(&block[0], &k[0]);

        size_t offset = 8 - copy_n;
        XorRange<8>(p_plain, &block[offset], &p_cipher[-8 + offset]);

        p_cipher += 8;
        p_plain += copy_n;
    };

    if (start_loc > 8)
    {
        size_t copy_n = 16 - start_loc;
        decrypt_next_tea_block(copy_n);
    }
    else
    {
        size_t copy_n = 8 - start_loc;
        std::copy_n(&block[start_loc], copy_n, p_plain);
        p_plain += copy_n;
    }

    while (p_cipher < p_cipher_end)
    {
        decrypt_next_tea_block(8);
    }

    // Constant time zero check
    auto zero_padding_validation = uint8_t{0};
    for (size_t i = 0; i < TEA_PADDING_ZERO_SIZE; i++)
    {
        zero_padding_validation |= plain[end_loc + i];
    }

    if (zero_padding_validation == uint8_t{0})
    {
        *p_plain_len = cipher_len - TEA_PADDING_ZERO_SIZE - start_loc;
        return true;
    }
    else
    {
        *p_plain_len = 0;
        return false;
    }
}

bool CBC_Encrypt(uint8_t *cipher, size_t *p_cipher_len, const uint8_t *plain, size_t plain_len, const uint8_t *key)
{
    std::array<uint32_t, 4> k;
    ParseBigEndianKey(&k[0], key);

    size_t pad_len = CBC_GetPaddingSize(plain_len);
    size_t cipher_len = CBC_GetEncryptedSize(plain_len);
    if (cipher_len > *p_cipher_len)
    {
        *p_cipher_len = cipher_len;
        return false;
    }

    *p_cipher_len = cipher_len;
    size_t header_size = 1 + pad_len + TEA_SALT_SIZE;

    GenerateRandomBytes(cipher, header_size);

    cipher[0] = (cipher[0] & uint8_t{0b1111'1000}) | static_cast<uint8_t>(pad_len & 0b0000'0111);
    std::copy_n(plain, plain_len, &cipher[header_size]);

    // Process first block
    std::array<uint8_t, 8> iv2;
    std::array<uint8_t, 8> next_iv2;

    std::copy_n(&cipher[0], 8, iv2.begin());
    ECB_EncryptBlock(&cipher[0], &k[0]);

    for (size_t i = 8; i < cipher_len; i += 8)
    {
        // XOR previous cipher block
        XorRange<8>(&cipher[i], &cipher[i - 8]);

        // store iv2
        std::copy_n(&cipher[i], 8, next_iv2.begin());

        // TEA ECB
        ECB_EncryptBlock(&cipher[i], &k[0]);

        // XOR iv2
        XorRange<8>(&cipher[i], &iv2[0]);

        iv2 = next_iv2;
    }

    return true;
}

} // namespace tc_tea
