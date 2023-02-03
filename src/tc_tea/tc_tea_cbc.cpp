#include "tc_tea/tc_tea.h"

#include "utils/EndianHelper.h"
#include "utils/utils.h"

#include <cstddef>
#include <cstdint>

#include <algorithm>
#include <array>

namespace tc_tea
{

constexpr size_t kTeaBlockSize = sizeof(uint32_t) * 2;
constexpr size_t TEA_SALT_SIZE = 2;
constexpr size_t TEA_PADDING_ZERO_SIZE = 7;
constexpr size_t TEA_MIN_CIPHER_TEXT_SIZE = 1 + TEA_SALT_SIZE + TEA_PADDING_ZERO_SIZE;

inline size_t CBC_GetPaddingSize(size_t cipher_text_size)
{
    size_t len = TEA_MIN_CIPHER_TEXT_SIZE + cipher_text_size;
    if (len % kTeaBlockSize == 0)
    {
        return 0;
    }
    return kTeaBlockSize - (len % kTeaBlockSize);
}

size_t CBC_GetEncryptedSize(size_t cipher_text_size)
{
    size_t len = TEA_MIN_CIPHER_TEXT_SIZE + cipher_text_size;
    size_t pad_len = CBC_GetPaddingSize(cipher_text_size);
    return len + pad_len;
}

bool CBC_Decrypt(uint8_t *plain, size_t *p_plain_len, const uint8_t *cipher, size_t cipher_len, const uint8_t *key)
{
    std::array<uint32_t, 4> key_be{};
    ParseBigEndianKey(key_be.data(), key);

    if (cipher_len < TEA_MIN_CIPHER_TEXT_SIZE || *p_plain_len < cipher_len || cipher_len % 8 != 0)
    {
        *p_plain_len = 0;
        return false;
    }

    // decrypt first block
    std::array<uint8_t, kTeaBlockSize> block{};
    std::copy_n(cipher, kTeaBlockSize, block.begin());

    auto *p_plain = plain;
    const auto *p_cipher = cipher;
    const auto *p_cipher_end = &cipher[cipher_len];

    ECB_DecryptBlock(block.data(), key_be.data());
    p_cipher += kTeaBlockSize;

    auto pad_size = static_cast<size_t>(block[0] & uint8_t{0b0111}); // NOLINT(*-magic-numbers)
    size_t start_loc = size_t{1} + pad_size + TEA_SALT_SIZE;

    auto tea_decrypt_next_block = [&](size_t copy_n) {
        XorTeaBlock(block.data(), p_cipher, block.data());
        ECB_DecryptBlock(block.data(), key_be.data());

        size_t offset = kTeaBlockSize - copy_n;
        XorTeaBlock(p_plain, &block[offset], &p_cipher[-kTeaBlockSize + offset]);

        p_cipher += kTeaBlockSize;
        p_plain += copy_n;
    };

    if (start_loc > kTeaBlockSize)
    {
        size_t copy_n = kTeaBlockSize * 2 - start_loc;
        tea_decrypt_next_block(copy_n);
    }
    else
    {
        size_t copy_n = kTeaBlockSize - start_loc;
        std::copy_n(&block[start_loc], copy_n, p_plain);
        p_plain += copy_n;
    }

    while (p_cipher < p_cipher_end)
    {
        tea_decrypt_next_block(kTeaBlockSize);
    }
    p_plain -= TEA_PADDING_ZERO_SIZE;

    // Constant time zero check
    uint8_t zero_padding_validation{};
    for (size_t i = 0; i < TEA_PADDING_ZERO_SIZE; i++)
    {
        zero_padding_validation |= p_plain[i];
    }

    if (zero_padding_validation != uint8_t{0})
    {
        *p_plain_len = 0;
        return false;
    }

    *p_plain_len = p_plain - plain;
    return true;
}

bool CBC_Encrypt(uint8_t *cipher, size_t *p_cipher_len, const uint8_t *plain, size_t plain_len, const uint8_t *key)
{
    std::array<uint32_t, 4> key_be{};
    ParseBigEndianKey(key_be.data(), key);

    size_t cipher_len = CBC_GetEncryptedSize(plain_len);
    if (cipher_len > *p_cipher_len)
    {
        *p_cipher_len = cipher_len;
        return false;
    }

    *p_cipher_len = cipher_len;

    size_t pad_len = CBC_GetPaddingSize(plain_len);
    size_t header_len = 1 + pad_len + TEA_SALT_SIZE;

    // Clear the first 2 blocks.
    std::fill_n(cipher, kTeaBlockSize * 2, 0);

    // Begin header generation
    GenerateRandomBytes(cipher, header_len);
    cipher[0] = (cipher[0] & uint8_t{0b1111'1000})             // NOLINT(*-magic-numbers)
                | static_cast<uint8_t>(pad_len & 0b0000'0111); // NOLINT(*-magic-numbers)

    std::array<uint8_t, kTeaBlockSize> iv2{};
    std::array<uint8_t, kTeaBlockSize> next_iv2{};

    auto *p_cipher = cipher;
    const auto *p_plain = plain;
    const auto *p_plain_end = plain + plain_len - kTeaBlockSize; // we need to stop a block before that

    auto tea_encrypt_next_block = [&](const uint8_t *p_src) {
        // XOR previous cipher block
        XorTeaBlock(p_cipher, p_src, &p_cipher[-kTeaBlockSize]);

        // store iv2 for next iteration
        std::copy_n(p_cipher, kTeaBlockSize, next_iv2.begin());

        // TEA ECB
        ECB_EncryptBlock(p_cipher, key_be.data());

        // XOR iv2 from previous iteration
        XorTeaBlock(p_cipher, iv2.data());

        iv2 = next_iv2;
        p_cipher += kTeaBlockSize;
    };

    // Copy required plain-text to the temp buffer.
    size_t initial_plain_process_len = std::min(kTeaBlockSize * 2 - header_len, plain_len);
    std::copy_n(plain, initial_plain_process_len, &cipher[header_len]);
    p_plain += initial_plain_process_len;

    // Preserve iv2
    std::copy_n(p_cipher, kTeaBlockSize, iv2.begin());
    ECB_EncryptBlock(p_cipher, key_be.data());
    p_cipher += kTeaBlockSize;

    // Decrypt second block
    tea_encrypt_next_block(p_cipher);

    // Check if there're any more data to encrypt after first 2 blocks.
    if (cipher_len > kTeaBlockSize * 2)
    {
        while (p_plain < p_plain_end)
        {
            tea_encrypt_next_block(p_plain);
            p_plain += kTeaBlockSize;
        }

        std::array<uint8_t, kTeaBlockSize> last_block{};
        std::copy_n(p_plain, kTeaBlockSize - TEA_PADDING_ZERO_SIZE, last_block.begin());
        tea_encrypt_next_block(last_block.data());
    }

    return true;
}

} // namespace tc_tea
