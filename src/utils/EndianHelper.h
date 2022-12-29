#pragma once

#include <cstdint>

#include <span>

namespace tc_tea::utils {

inline uint32_t BigEndianToU32(std::span<const uint8_t, 4> bytes) {
    return (static_cast<uint32_t>(bytes[0]) << 0x18) | (static_cast<uint32_t>(bytes[1]) << 0x10) |
           (static_cast<uint32_t>(bytes[2]) << 0x08) | (static_cast<uint32_t>(bytes[3]) << 0x00);
}

inline void U32ToBigEndian(std::span<uint8_t, 4> bytes, uint32_t value) {
    bytes[0] = static_cast<uint8_t>(value >> 0x18);
    bytes[1] = static_cast<uint8_t>(value >> 0x10);
    bytes[2] = static_cast<uint8_t>(value >> 0x08);
    bytes[3] = static_cast<uint8_t>(value >> 0x00);
}

}  // namespace tc_tea::utils
