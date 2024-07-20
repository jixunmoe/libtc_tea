#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "tc_tea/tc_tea.h"

#include <array>

using ::testing::ElementsAreArray;

TEST(TC_TEA_ECB, BasicDecryptionTest) {
  std::array<uint8_t, 8> cipher = {0x56, 0x27, 0x6b, 0xa9, 0x80, 0xb9, 0xec, 0x16};
  std::array<uint32_t, 4> key = {0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f00};
  std::array<uint8_t, 8> expected_plain = {1, 2, 3, 4, 5, 6, 7, 8};

  auto decrypted = cipher;
  tc_tea_ecb_decrypt_block(&decrypted[0], &key[0]);
  EXPECT_THAT(decrypted, ElementsAreArray(expected_plain))
      << "tc_tea_ecb_decrypt_block test decryption failed: data mismatch";
}

TEST(TC_TEA_ECB, BasicEncryptionTest) {
  std::array<uint32_t, 4> key = {0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f00};
  std::array<uint8_t, 8> plain = {1, 2, 3, 4, 5, 6, 7, 8};

  auto cipher = plain;
  tc_tea_ecb_encrypt_block(&cipher[0], &key[0]);

  auto actual_decrypted = cipher;
  tc_tea_ecb_decrypt_block(&actual_decrypted[0], &key[0]);
  EXPECT_THAT(actual_decrypted, ElementsAreArray(plain))
      << "tc_tea_ecb_{decrypt,decrypt}_block test failed: data mismatch";
}
