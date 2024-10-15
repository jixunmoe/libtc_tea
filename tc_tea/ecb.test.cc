#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ecb.h"
#include "tea_utils.h"

#include <array>

using ::testing::ElementsAreArray;

TEST(TC_TEA_ECB, BasicDecryptionTest) {
    std::array<uint8_t, 8> cipher = {0x56, 0x27, 0x6b, 0xa9, 0x80, 0xb9, 0xec, 0x16};
    std::array<uint32_t, 4> key = {0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f00};
    std::array<uint8_t, 8> expected_plain = {1, 2, 3, 4, 5, 6, 7, 8};

    auto decrypted = cipher;
    auto result = tc_tea_ecb_decrypt_block(tc_tea_be_u64_read(decrypted.data()), key.data());
    tc_tea_be_u64_write(decrypted.data(), result);
    EXPECT_THAT(decrypted, ElementsAreArray(expected_plain))
        << "tc_tea_ecb_decrypt_block test decryption failed: data mismatch";
}

TEST(TC_TEA_ECB, BasicEncryptionTest) {
    std::array<uint32_t, 4> key = {0x7ffffff1, 0x7ffffff2, 0x7ffffff3, 0x7ffffff4};
    std::array<uint8_t, 8> plain = {0x7f, 1, 2, 3, 0x80, 4, 5, 6};
    std::array<uint8_t, 8> expected_cipher = {0x59, 0x6a, 0x9d, 0x4c, 0x5c, 0xf8, 0x66, 0x24};

    auto result = tc_tea_ecb_encrypt_block(tc_tea_be_u64_read(plain.data()), key.data());
    tc_tea_be_u64_write(plain.data(), result);

    EXPECT_THAT(expected_cipher, ElementsAreArray(plain)) << "tc_tea_ecb_decrypt_block test failed: data mismatch";
}
