#include "tc_tea/tc_tea.h"

#define TEA_ROUNDS (16)
#define TEA_ROUND_DELTA (0x9e3779b9)
#define TEA_EXPECTED_SUM ((uint32_t)(TEA_ROUNDS * TEA_ROUND_DELTA))

static inline uint32_t tc_tea_read_u32_be(const uint8_t* src) {
  return ((uint32_t)(src[0]) << 0x18)     //
         | ((uint32_t)(src[1]) << 0x10)   //
         | ((uint32_t)(src[2]) << 0x08)   //
         | ((uint32_t)(src[3]) << 0x00);  //
}

static inline void tc_tea_write_u32_be(uint8_t* dest, uint32_t value) {
  dest[0] = (uint8_t)((value & 0xFF000000) >> 0x18);
  dest[1] = (uint8_t)((value & 0x00FF0000) >> 0x10);
  dest[2] = (uint8_t)((value & 0x0000FF00) >> 0x08);
  dest[3] = (uint8_t)((value & 0x000000FF) >> 0x00);
}

static inline uint32_t tc_tea_single_round(uint32_t value, uint32_t sum, uint32_t key1, uint32_t key2) {
  return ((value << 4) + key1) ^ (value + sum) ^ ((value >> 5) + key2);
}

void tc_tea_ecb_decrypt_block(uint8_t* block, const uint32_t* key) {
  uint32_t y = tc_tea_read_u32_be(&block[0]);
  uint32_t z = tc_tea_read_u32_be(&block[4]);
  uint32_t sum = {TEA_EXPECTED_SUM};

  for (size_t i = 0; i < TEA_ROUNDS; i++) {
    z -= tc_tea_single_round(y, sum, key[2], key[3]);
    y -= tc_tea_single_round(z, sum, key[0], key[1]);
    sum -= TEA_ROUND_DELTA;
  }

  tc_tea_write_u32_be(&block[0], y);
  tc_tea_write_u32_be(&block[4], z);
}

void tc_tea_ecb_encrypt_block(uint8_t* block, const uint32_t* key) {
  uint32_t y = tc_tea_read_u32_be(&block[0]);
  uint32_t z = tc_tea_read_u32_be(&block[4]);
  uint32_t sum = {0};

  for (size_t i = 0; i < TEA_ROUNDS; i++) {
    sum += TEA_ROUND_DELTA;
    y += tc_tea_single_round(z, sum, key[0], key[1]);
    z += tc_tea_single_round(y, sum, key[2], key[3]);
  }

  tc_tea_write_u32_be(&block[0], y);
  tc_tea_write_u32_be(&block[4], z);
}
