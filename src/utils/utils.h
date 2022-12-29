#pragma once

#include <cstddef>
#include <cstdint>

#include <algorithm>
#include <random>
#include <span>

namespace tc_tea::utils {

template <std::size_t N>
inline void XorRange(std::byte* dst, const std::byte* src) {
    if constexpr (N == 8) {
        *reinterpret_cast<uint64_t*>(dst) ^= *reinterpret_cast<const uint64_t*>(src);
    } else {
        for (std::size_t i = 0; i < N; i++) {
            dst[i] ^= src[i];
        }
    }
}

inline void ParseBigEndianKey(std::span<uint32_t, 4> result, std::span<const std::byte, 16> key) {
    for (int i = 0; i < 4; i++) {
        result[i] = utils::BigEndianToU32(std::span<const std::byte, 4>(&key[i * sizeof(uint32_t)], 4));
    }
}

inline void GenerateRandomBytes(std::span<std::byte> data) {
    using random_bytes_engine =
        std::independent_bits_engine<std::default_random_engine, std::numeric_limits<uint8_t>::digits, uint8_t>;

    std::random_device rd;
    random_bytes_engine rbe(rd());
    std::ranges::generate(data.begin(), data.end(), [&rbe]() {
        // Get next byte
        return static_cast<std::byte>(rbe());
    });
}

}  // namespace tc_tea::utils
