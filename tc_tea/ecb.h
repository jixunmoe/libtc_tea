#include <stddef.h>
#include <stdint.h>

#define TEA_ROUNDS (16)
#define TEA_ROUND_DELTA (0x9e3779b9)
#define TEA_EXPECTED_SUM ((uint32_t)(TEA_ROUNDS * TEA_ROUND_DELTA))

static inline uint32_t tc_tea_single_round(uint32_t value, uint32_t sum, uint32_t key1, uint32_t key2) {
    return ((value << 4) + key1) ^ (value + sum) ^ ((value >> 5) + key2);
}

static inline uint64_t tc_tea_ecb_decrypt_block(uint64_t value, const uint32_t* key) {
    uint32_t y = (uint32_t)(value >> 32);
    uint32_t z = (uint32_t)(value);
    uint32_t sum = {TEA_EXPECTED_SUM};

    for (size_t i = 0; i < TEA_ROUNDS; i++) {
        z -= tc_tea_single_round(y, sum, key[2], key[3]);
        y -= tc_tea_single_round(z, sum, key[0], key[1]);
        sum -= TEA_ROUND_DELTA;
    }

    return ((uint64_t)(y) << 32) | (uint64_t)(z);
}

static inline uint64_t tc_tea_ecb_encrypt_block(uint64_t value, const uint32_t* key) {
    uint32_t y = (uint32_t)(value >> 32);
    uint32_t z = (uint32_t)(value);
    uint32_t sum = {0};

    for (size_t i = 0; i < TEA_ROUNDS; i++) {
        sum += TEA_ROUND_DELTA;
        y += tc_tea_single_round(z, sum, key[0], key[1]);
        z += tc_tea_single_round(y, sum, key[2], key[3]);
    }

    return ((uint64_t)(y) << 32) | (uint64_t)(z);
}
