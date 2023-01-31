#pragma once

#include <cstddef>
#include <cstdint>

#include <algorithm>
#include <random>

namespace tc_tea::utils {

template <size_t N>
inline void XorRange(uint8_t* dst, const uint8_t* src) {
    if constexpr (N == 8) {
        *reinterpret_cast<uint64_t*>(dst) ^= *reinterpret_cast<const uint64_t*>(src);
    } else {
        for (size_t i = 0; i < N; i++) {
            dst[i] ^= src[i];
        }
    }
}

inline void ParseBigEndianKey(uint32_t* result, const uint8_t* key) {
    for (int i = 0; i < 4; i++) {
        result[i] = utils::BigEndianToU32(&key[i * sizeof(uint32_t)]);
    }
}

inline void GenerateRandomBytes(uint8_t* data, size_t n) {
    using random_bytes_engine =
        std::independent_bits_engine<std::default_random_engine, std::numeric_limits<uint8_t>::digits, unsigned short>;

    std::random_device rd;
    random_bytes_engine rbe(rd());
    for (size_t i = 0; i < n; i++) {
        data[i] = rbe();
    }
}

}  // namespace tc_tea::utils
