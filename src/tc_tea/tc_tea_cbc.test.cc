#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "tc_tea/tc_tea.h"

#include <array>
#include <vector>

using ::testing::ElementsAreArray;

TEST(TC_TEA_CBC, BasicDecryptionTest) {
    auto cipher = std::bit_cast<std::array<uint8_t, 24>>(
        std::to_array<uint8_t>({0x91, 0x09, 0x51, 0x62, 0xe3, 0xf5, 0xb6, 0xdc, 0x6b, 0x41, 0x4b, 0x50,
                                0xd1, 0xa5, 0xb8, 0x4e, 0xc5, 0x0d, 0x0c, 0x1b, 0x11, 0x96, 0xfd, 0x3c}));
    auto key = std::bit_cast<std::array<uint8_t, 16>>(
        std::to_array<uint8_t>({'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'}));
    auto expected_plain = std::bit_cast<std::array<uint8_t, 8>>(std::to_array<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8}));

    auto decrypted = tc_tea::CBC_Decrypt(cipher, key);
    ASSERT_THAT(decrypted, ElementsAreArray(expected_plain)) << "tc_tea_cbc test decryption failed: data mismatch";
}

TEST(TC_TEA_CBC, BasicEncryptionTest) {
    auto key = std::bit_cast<std::array<uint8_t, 16>>(
        std::to_array<uint8_t>({'1', '2', '3', '4', '5', '6', '7', '8', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'}));
    auto plain = std::bit_cast<std::array<uint8_t, 16>>(
        std::to_array<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 17, 18}));

    auto cipher = tc_tea::CBC_Encrypt(plain, key);
    ASSERT_EQ(cipher.size(), 32);

    auto actual_decrypted = tc_tea::CBC_Decrypt(cipher, key);
    ASSERT_THAT(actual_decrypted, ElementsAreArray(plain))
        << "tc_tea_cbc test encryption/decryption failed: data mismatch";
}
