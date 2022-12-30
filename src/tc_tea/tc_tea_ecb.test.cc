#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "tc_tea/tc_tea.h"

#include <array>
#include <vector>

using ::testing::ElementsAreArray;

TEST(TC_TEA_ECB, BasicDecryptionTest) {
    auto cipher = std::to_array<uint8_t>({0x56, 0x27, 0x6b, 0xa9, 0x80, 0xb9, 0xec, 0x16});
    auto key = std::to_array<uint32_t>({0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f00});
    auto expected_plain = std::to_array<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8});

    auto decrypted = cipher;
    tc_tea::ECB_DecryptBlock(decrypted, key);
    ASSERT_THAT(decrypted, ElementsAreArray(expected_plain)) << "tc_tea_ecb test decryption failed: data mismatch";
}

TEST(TC_TEA_ECB, BasicEncryptionTest) {
    auto key = std::to_array<uint32_t>({0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f00});
    auto plain = std::to_array<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8});

    auto cipher = plain;
    tc_tea::ECB_EncryptBlock(cipher, key);

    auto actual_decrypted = cipher;
    tc_tea::ECB_DecryptBlock(actual_decrypted, key);
    ASSERT_THAT(actual_decrypted, ElementsAreArray(plain))
        << "tc_tea_ecb test encryption/decryption failed: data mismatch";
}
