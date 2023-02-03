#include <algorithm>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "tc_tea/tc_tea.h"

#include <array>
#include <vector>

using ::testing::ElementsAreArray;

// NOLINTBEGIN(*-avoid-magic-numbers)

TEST(TC_TEA_CBC, BasicDecryptionTest)
{
    std::vector<uint8_t> cipher = {0x91, 0x09, 0x51, 0x62, 0xe3, 0xf5, 0xb6, 0xdc, 0x6b, 0x41, 0x4b, 0x50,
                                   0xd1, 0xa5, 0xb8, 0x4e, 0xc5, 0x0d, 0x0c, 0x1b, 0x11, 0x96, 0xfd, 0x3c};
    uint8_t key[] = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    uint8_t expected_plain[] = {1, 2, 3, 4, 5, 6, 7, 8};

    auto decrypted = tc_tea::CBC_Decrypt(cipher, &key[0]);
    ASSERT_THAT(decrypted, ElementsAreArray(expected_plain)) << "tc_tea_cbc test decryption failed: data mismatch";
}

TEST(TC_TEA_CBC, BasicEncryptionTest)
{
    std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    std::vector<uint8_t> plain = {1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 17, 18};

    auto cipher = tc_tea::CBC_Encrypt(plain, &key[0]);
    ASSERT_EQ(cipher.size(), 32);

    auto actual_decrypted = tc_tea::CBC_Decrypt(cipher, &key[0]);
    ASSERT_THAT(actual_decrypted, ElementsAreArray(plain))
        << "tc_tea_cbc test encryption/decryption failed: data mismatch";
}

TEST(TC_TEA_CBC, BasicEncryptionTestWithLongData)
{
    std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    std::vector<uint8_t> plain = {1,  2,  3,  4,  5,  6,  7,  8,  //
                                  11, 12, 13, 14, 15, 16, 17, 18, //
                                  31, 32, 33, 34, 35, 36, 37, 38};

    auto cipher = tc_tea::CBC_Encrypt(plain, &key[0]);
    auto actual_decrypted = tc_tea::CBC_Decrypt(cipher, &key[0]);
    ASSERT_THAT(actual_decrypted, ElementsAreArray(plain))
        << "tc_tea_cbc test encryption/decryption failed: data mismatch";
}

TEST(TC_TEA_CBC, BasicEncryptionTestWithShortPadding)
{
    std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    std::vector<uint8_t> plain = {0xff, 0x66, 0xff};

    auto cipher = tc_tea::CBC_Encrypt(plain, &key[0]);
    ASSERT_EQ(cipher.size(), 16);

    auto actual_decrypted = tc_tea::CBC_Decrypt(cipher, &key[0]);
    ASSERT_THAT(actual_decrypted, ElementsAreArray(plain))
        << "tc_tea_cbc test encryption/decryption failed: data mismatch";
}

TEST(TC_TEA_CBC, DecryptWithDirtyBuffer)
{
    std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    std::vector<uint8_t> plain = {0x11, 0x66, 0x22};
    std::vector<uint8_t> cipher(16, 0xff);

    size_t cipher_len = cipher.size();
    tc_tea::CBC_Encrypt(cipher.data(), &cipher_len, plain.data(), plain.size(), key.data());
    cipher.resize(cipher_len);
    ASSERT_EQ(cipher.size(), 16);

    auto actual_decrypted = tc_tea::CBC_Decrypt(cipher, key.data());
    ASSERT_THAT(actual_decrypted, ElementsAreArray(plain))
        << "tc_tea_cbc test encryption/decryption failed: data mismatch";
}

TEST(TC_TEA_CBC, DecryptWithLargeDirtyBuffer)
{
    std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    std::vector<uint8_t> plain(100, 0xff);
    std::vector<uint8_t> cipher(116, 0xff);

    size_t cipher_len = cipher.size();
    tc_tea::CBC_Encrypt(cipher.data(), &cipher_len, plain.data(), plain.size(), key.data());
    ASSERT_EQ(cipher_len, 112);

    cipher.resize(cipher_len + 100);
    std::fill(cipher.begin() + cipher_len, cipher.end(), 0xcc);

    auto actually_decrypted = cipher;
    size_t plain_len = cipher_len;
    tc_tea::CBC_Decrypt(actually_decrypted.data(), &plain_len, cipher.data(), cipher_len, key.data());
    ASSERT_EQ(plain_len, 100);
    actually_decrypted.resize(plain_len);

    ASSERT_THAT(actually_decrypted, ElementsAreArray(plain))
        << "tc_tea_cbc test encryption/decryption failed: data mismatch";
}

TEST(TC_TEA_CBC, ShouldWorkWithoutPadding)
{
    std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    std::vector<uint8_t> plain = {'1', '2', '3', '4', '5', '6'};

    auto cipher = tc_tea::CBC_Encrypt(plain, key.data());
    ASSERT_EQ(cipher.size(), 16);

    auto actual_decrypted = tc_tea::CBC_Decrypt(cipher, key.data());
    ASSERT_THAT(actual_decrypted, ElementsAreArray(plain))
        << "tc_tea_cbc test encryption/decryption failed: data mismatch";
}

TEST(TC_TEA_CBC, ShouldRejectIfCipherBufferTooSmall)
{
    std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    std::vector<uint8_t> plain = {'1', '2', '3', '4', '5', '6'};
    std::vector<uint8_t> cipher(10);

    size_t cipher_len = cipher.size();
    auto ok = tc_tea::CBC_Encrypt(cipher.data(), &cipher_len, plain.data(), plain.size(), key.data());

    ASSERT_EQ(ok, false);
    ASSERT_EQ(cipher_len, 16);
}

TEST(TC_TEA_CBC, ShouldRejectIfSizeMismatch)
{
    std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    std::vector<uint8_t> plain = {'1', '2', '3', '4', '5', '6'};

    auto cipher = tc_tea::CBC_Encrypt(plain, key.data());
    ASSERT_EQ(cipher.size(), 16);
    cipher.pop_back();

    ASSERT_EQ(tc_tea::CBC_Decrypt(cipher, key.data()).size(), 0);
}

TEST(TC_TEA_CBC, ShouldRejectIfZeroCheckFailed)
{
    std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    std::vector<uint8_t> plain = {'1', '2', '3', '4', '5', '6'};

    auto cipher = tc_tea::CBC_Encrypt(plain, key.data());
    ASSERT_EQ(cipher.size(), 16);
    cipher[15] ^= 1;

    ASSERT_EQ(tc_tea::CBC_Decrypt(cipher, key.data()).size(), 0);
}

TEST(TC_TEA_CBC, ShouldWorkEncryptingSingleByte)
{
    std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    std::vector<uint8_t> plain = {'1'};

    auto cipher = tc_tea::CBC_Encrypt(plain, key.data());
    ASSERT_EQ(cipher.size(), 16);
    auto actually_decrypted = tc_tea::CBC_Decrypt(cipher, key.data());
    ASSERT_THAT(actually_decrypted, ElementsAreArray(plain));
}

TEST(TC_TEA_CBC, ShouldWorkEncryptingEmptyBuffer)
{
    std::vector<uint8_t> key = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    std::vector<uint8_t> plain = {};

    auto cipher = tc_tea::CBC_Encrypt(plain, key.data());
    ASSERT_EQ(cipher.size(), 16);
    auto actually_decrypted = tc_tea::CBC_Decrypt(cipher, key.data());
    ASSERT_THAT(actually_decrypted, ElementsAreArray(plain));
}

// NOLINTEND(*-avoid-magic-numbers)
