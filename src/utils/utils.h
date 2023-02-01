#pragma once

#include "EndianHelper.h"

#include <cstddef>
#include <cstdint>

#include <algorithm>
#include <random>

namespace tc_tea
{

inline void XorTeaBlock(uint8_t *dst, const uint8_t *src1, const uint8_t *src2)
{
    *reinterpret_cast<uint64_t *>(dst) =
        *reinterpret_cast<const uint64_t *>(src1) ^ *reinterpret_cast<const uint64_t *>(src2);
}

inline void XorTeaBlock(uint8_t *dst, const uint8_t *src)
{
    *reinterpret_cast<uint64_t *>(dst) ^= *reinterpret_cast<const uint64_t *>(src);
}

inline void ParseBigEndianKey(uint32_t *result, const uint8_t *key)
{
    for (int i = 0; i < 4; i++)
    {
        result[i] = BigEndianToU32(&key[i * sizeof(uint32_t)]);
    }
}

inline void GenerateRandomBytes(uint8_t *data, size_t n)
{
    using random_bytes_engine =
        std::independent_bits_engine<std::default_random_engine, std::numeric_limits<uint8_t>::digits, unsigned short>;

    std::random_device rd;
    random_bytes_engine rbe(rd());
    for (size_t i = 0; i < n; i++)
    {
        data[i] = rbe();
    }
}

} // namespace tc_tea
