#pragma once

#include <stdint.h>

#define TC_TEA_MIN(a, b) ((a) < (b) ? (a) : (b))

static inline uint32_t tc_tea_be_u32_read(const uint8_t* src) {
    return ((uint32_t)(src[0]) << 0x18)     //
           | ((uint32_t)(src[1]) << 0x10)   //
           | ((uint32_t)(src[2]) << 0x08)   //
           | ((uint32_t)(src[3]) << 0x00);  //
}

static inline void tc_tea_be_u32_write(uint8_t* dest, uint32_t value) {
    dest[0] = (uint8_t)((value & 0xFF000000) >> 0x18);
    dest[1] = (uint8_t)((value & 0x00FF0000) >> 0x10);
    dest[2] = (uint8_t)((value & 0x0000FF00) >> 0x08);
    dest[3] = (uint8_t)((value & 0x000000FF) >> 0x00);
}

static inline uint64_t tc_tea_be_u64_read(const uint8_t* src) {
    return ((uint64_t)(src[0]) << 0x38)    //
           | ((uint64_t)(src[1]) << 0x30)  //
           | ((uint64_t)(src[2]) << 0x28)  //
           | ((uint64_t)(src[3]) << 0x20)  //
           | ((uint64_t)(src[4]) << 0x18)  //
           | ((uint64_t)(src[5]) << 0x10)  //
           | ((uint64_t)(src[6]) << 0x08)  //
           | ((uint64_t)(src[7]) << 0x00)  //
        ;
}

static inline void tc_tea_be_u64_write(uint8_t* dest, uint64_t value) {
    dest[0] = (uint8_t)(value >> 0x38);
    dest[1] = (uint8_t)(value >> 0x30);
    dest[2] = (uint8_t)(value >> 0x28);
    dest[3] = (uint8_t)(value >> 0x20);
    dest[4] = (uint8_t)(value >> 0x18);
    dest[5] = (uint8_t)(value >> 0x10);
    dest[6] = (uint8_t)(value >> 0x08);
    dest[7] = (uint8_t)(value >> 0x00);
}
