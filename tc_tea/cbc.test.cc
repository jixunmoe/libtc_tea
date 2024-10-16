#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "tc_tea/tc_tea.h"

#include <array>

using ::testing::ElementsAreArray;

TEST(TC_TEA_CBC, EncryptEmptyBuffer) {
    std::array<uint8_t, 100> cipher{};
    std::array<uint8_t, 0> plain = {};
    std::array<uint8_t, 16> salt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    std::array<uint32_t, 4> tea_key{};
    std::array<uint8_t, 16> expected_cipher{
        0x64, 0xe2, 0xa2, 0xa5, 0xcd, 0xa9, 0xdc, 0x59, 0xcc, 0x46, 0x95, 0x86, 0x9a, 0xb4, 0x46, 0x60,
    };
    tc_tea_parse_key(tea_key.data(), (const uint8_t*)"12345678ABCDEFGH");

    size_t cipher_len = tc_tea_cbc_get_cipher_len(plain.size());
    EXPECT_EQ(cipher_len, 16);
    size_t written_len = tc_tea_cbc_encrypt(cipher.data(), plain.data(), plain.size(), tea_key.data(), salt.data());
    EXPECT_EQ(written_len, 16);

    EXPECT_THAT(std::span(cipher.cbegin(), cipher.cbegin() + 16), ElementsAreArray(expected_cipher));
}

TEST(TC_TEA_CBC, EncryptionTest) {
    std::array<uint8_t, 100> cipher{};
    std::array<uint8_t, 11> plain = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
    std::array<uint8_t, 16> salt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    std::array<uint32_t, 4> tea_key{};
    std::array<uint8_t, 24> expected_cipher{
        0x1d, 0xb8, 0x4d, 0x45, 0x41, 0x91, 0xc8, 0x1f, 0xea, 0x1f, 0x66, 0x49,
        0x12, 0x82, 0x6c, 0x31, 0x3e, 0xc0, 0xfd, 0x94, 0x97, 0x58, 0x50, 0xdf,
    };
    tc_tea_parse_key(tea_key.data(), (const uint8_t*)"12345678ABCDEFGH");

    size_t cipher_len = tc_tea_cbc_get_cipher_len(plain.size());
    EXPECT_EQ(cipher_len, 24);
    size_t written_len = tc_tea_cbc_encrypt(cipher.data(), plain.data(), plain.size(), tea_key.data(), salt.data());
    EXPECT_EQ(written_len, 24);

    EXPECT_THAT(std::span(cipher.cbegin(), cipher.cbegin() + 24), ElementsAreArray(expected_cipher));
}

TEST(TC_TEA_CBC, LongerEncryption) {
    std::array<uint8_t, 100> cipher{};
    std::vector<uint8_t> plain = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l',
                                  'd', ' ', 'p', 'a', 'r', 'a', 'k', 'e', 'e', 't'};
    std::array<uint8_t, 16> salt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    std::array<uint32_t, 4> tea_key{};
    std::array<uint8_t, 32> expected_cipher{
        0xDC, 0x5B, 0xD4, 0x95, 0x97, 0x6E, 0xE0, 0xCE, 0x54, 0x15, 0xE3, 0x92, 0x2E, 0xEB, 0xCF, 0x1A,
        0x88, 0x10, 0x85, 0x83, 0xC7, 0xBE, 0x4F, 0xE0, 0x17, 0x79, 0x64, 0x19, 0xEF, 0x99, 0x13, 0x21,
    };
    tc_tea_parse_key(tea_key.data(), (const uint8_t*)"12345678ABCDEFGH");

    size_t cipher_len = tc_tea_cbc_get_cipher_len(plain.size());
    EXPECT_EQ(cipher_len, expected_cipher.size());
    size_t written_len = tc_tea_cbc_encrypt(cipher.data(), plain.data(), plain.size(), tea_key.data(), salt.data());
    EXPECT_EQ(written_len, expected_cipher.size());

    EXPECT_THAT(std::span(cipher.cbegin(), cipher.cbegin() + expected_cipher.size()),
                ElementsAreArray(expected_cipher));
}

TEST(tc_tea_cbc_decrypt, empty_buffer) {
    std::array<uint8_t, 16> cipher{
        0x64, 0xe2, 0xa2, 0xa5, 0xcd, 0xa9, 0xdc, 0x59, 0xcc, 0x46, 0x95, 0x86, 0x9a, 0xb4, 0x46, 0x60,
    };
    std::array<uint8_t, 100> plain{};
    std::array<uint32_t, 4> tea_key{};
    tc_tea_parse_key(tea_key.data(), (const uint8_t*)"12345678ABCDEFGH");

    size_t plain_len = plain.size();
    uint8_t* p_result = plain.data();
    auto status = tc_tea_cbc_decrypt(p_result, &plain_len, cipher.data(), cipher.size(), tea_key.data());
    EXPECT_EQ(status, TC_TEA_OK);
    EXPECT_EQ(plain_len, 0);
}

TEST(tc_tea_cbc_decrypt, happy_path) {
    std::array<uint8_t, 24> cipher{
        0x1d, 0xb8, 0x4d, 0x45, 0x41, 0x91, 0xc8, 0x1f, 0xea, 0x1f, 0x66, 0x49,
        0x12, 0x82, 0x6c, 0x31, 0x3e, 0xc0, 0xfd, 0x94, 0x97, 0x58, 0x50, 0xdf,
    };
    std::array<uint8_t, 100> plain{};
    std::array<uint8_t, 11> explained_plain = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
    std::array<uint32_t, 4> tea_key{};
    tc_tea_parse_key(tea_key.data(), (const uint8_t*)"12345678ABCDEFGH");

    size_t plain_len = plain.size();
    uint8_t* p_result = plain.data();
    auto status = tc_tea_cbc_decrypt(p_result, &plain_len, cipher.data(), cipher.size(), tea_key.data());
    EXPECT_EQ(status, TC_TEA_OK);
    EXPECT_EQ(plain_len, 11);

    EXPECT_THAT(std::span(p_result, p_result + plain_len), ElementsAreArray(explained_plain));
}

TEST(tc_tea_cbc_decrypt, sad_path_small_buffer) {
    std::array<uint8_t, 24> cipher{
        0x1d, 0xb8, 0x4d, 0x45, 0x41, 0x91, 0xc8, 0x1f, 0xea, 0x1f, 0x66, 0x49,
        0x12, 0x82, 0x6c, 0x31, 0x3e, 0xc0, 0xfd, 0x94, 0x97, 0x58, 0x50, 0xdf,
    };
    std::array<uint8_t, 10> plain{};
    std::array<uint32_t, 4> tea_key{};
    tc_tea_parse_key(tea_key.data(), (const uint8_t*)"12345678ABCDEFGH");

    size_t plain_len = plain.size();
    uint8_t* p_result = plain.data();
    auto status = tc_tea_cbc_decrypt(p_result, &plain_len, cipher.data(), cipher.size(), tea_key.data());
    EXPECT_EQ(status, TC_TEA_ERR_BUFFER_TOO_SMALL);
    EXPECT_EQ(plain_len, 11);
}

TEST(tc_tea_cbc_decrypt, sad_path_wrong_buffer_len) {
    std::vector<uint8_t> cipher(17);
    std::array<uint8_t, 100> plain{};
    std::array<uint32_t, 4> tea_key{};
    tc_tea_parse_key(tea_key.data(), (const uint8_t*)"12345678ABCDEFGH");

    {
        size_t plain_len = plain.size();
        uint8_t* p_result = plain.data();
        auto status = tc_tea_cbc_decrypt(p_result, &plain_len, cipher.data(), cipher.size(), tea_key.data());
        EXPECT_EQ(status, TC_TEA_ERR_WRONG_CIPHER_LENGTH);
    }

    {
        cipher.resize(8);
        size_t plain_len = plain.size();
        uint8_t* p_result = plain.data();
        auto status = tc_tea_cbc_decrypt(p_result, &plain_len, cipher.data(), cipher.size(), tea_key.data());
        EXPECT_EQ(status, TC_TEA_ERR_WRONG_CIPHER_LENGTH);
    }
}

TEST(tc_tea_cbc_decrypt, sad_path_verification) {
    std::vector<uint8_t> cipher{
        0x1d, 0xb8, 0x4d, 0x45, 0x41, 0x91, 0xc8, 0x1f, 0xea, 0x1f, 0x66, 0x49,
        0x12, 0x82, 0x6c, 0x31, 0x3e, 0xc0, 0xfd, 0x94, 0x97, 0x58, 0x50, 0x00,
    };
    std::array<uint8_t, 100> plain{};
    std::array<uint32_t, 4> tea_key{};
    tc_tea_parse_key(tea_key.data(), (const uint8_t*)"12345678ABCDEFGH");

    size_t plain_len = plain.size();
    uint8_t* p_result = plain.data();
    auto status = tc_tea_cbc_decrypt(p_result, &plain_len, cipher.data(), cipher.size(), tea_key.data());
    EXPECT_EQ(status, TC_TEA_ERR_ZERO_PADDING_VERIFY_FAILED);
}
