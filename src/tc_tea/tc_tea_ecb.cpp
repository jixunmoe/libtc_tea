#include "tc_tea/tc_tea.h"

#include "utils/EndianHelper.h"

#include <algorithm>

namespace tc_tea
{

constexpr uint32_t TEA_ECB_ROUNDS = 16;
constexpr uint32_t TEA_ECB_DELTA = 0x9e3779b9;

inline auto single_round_tea(uint32_t value, uint32_t sum, uint32_t key1, uint32_t key2) -> uint32_t
{
    return ((value << 4) + key1) ^ (value + sum) ^ ((value >> 5) + key2);
}

void ECB_DecryptBlock(uint8_t *block, const uint32_t *key)
{
    uint32_t y = BigEndianToU32(&block[0]);
    uint32_t z = BigEndianToU32(&block[4]);
    uint32_t sum = TEA_ECB_DELTA * TEA_ECB_ROUNDS;

    for (int i = 0; i < TEA_ECB_ROUNDS; i++)
    {
        z -= single_round_tea(y, sum, key[2], key[3]);
        y -= single_round_tea(z, sum, key[0], key[1]);
        sum -= TEA_ECB_DELTA;
    }

    U32ToBigEndian(&block[0], y);
    U32ToBigEndian(&block[4], z);
}

void ECB_EncryptBlock(uint8_t *block, const uint32_t *key)
{
    uint32_t y = BigEndianToU32(&block[0]);
    uint32_t z = BigEndianToU32(&block[4]);
    uint32_t sum = 0;

    for (int i = 0; i < TEA_ECB_ROUNDS; i++)
    {
        sum += TEA_ECB_DELTA;

        y += single_round_tea(z, sum, key[0], key[1]);
        z += single_round_tea(y, sum, key[2], key[3]);
    }

    U32ToBigEndian(&block[0], y);
    U32ToBigEndian(&block[4], z);
}

} // namespace tc_tea
