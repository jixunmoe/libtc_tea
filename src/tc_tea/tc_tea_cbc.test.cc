#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "tc_tea/tc_tea.h"

#include <array>
#include <vector>

using ::testing::ElementsAreArray;

TEST(TC_TEA_CBC, BasicDecryptionTest)
{
    std::array<uint8_t, 24> cipher = {0x91, 0x09, 0x51, 0x62, 0xe3, 0xf5, 0xb6, 0xdc, 0x6b, 0x41, 0x4b, 0x50,
                                      0xd1, 0xa5, 0xb8, 0x4e, 0xc5, 0x0d, 0x0c, 0x1b, 0x11, 0x96, 0xfd, 0x3c};
    std::array<uint8_t, 16> key = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    std::array<uint8_t, 8> expected_plain = {1, 2, 3, 4, 5, 6, 7, 8};

    auto decrypted = tc_tea::CBC_Decrypt(&cipher[0], cipher.size(), &key[0]);
    ASSERT_THAT(decrypted, ElementsAreArray(expected_plain)) << "tc_tea_cbc test decryption failed: data mismatch";
}

TEST(TC_TEA_CBC, BasicEncryptionTest)
{
    std::array<uint8_t, 16> key = {'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    std::array<uint8_t, 16> plain = {1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 17, 18};

    auto cipher = tc_tea::CBC_Encrypt(&plain[0], plain.size(), &key[0]);
    ASSERT_EQ(cipher.size(), 32);

    auto actual_decrypted = tc_tea::CBC_Decrypt(&cipher[0], cipher.size(), &key[0]);
    ASSERT_THAT(actual_decrypted, ElementsAreArray(plain))
        << "tc_tea_cbc test encryption/decryption failed: data mismatch";
}
