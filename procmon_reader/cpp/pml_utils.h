/*
 * pml_utils.h — Little-endian integer readers and UTF-16LE → UTF-8 conversion.
 */

#pragma once

#include <cstdint>
#include <string>


/* ================================================================
 * Inline: Little-endian field readers (unaligned, portable)
 * ================================================================ */

inline uint16_t rd_u16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0]) |
           (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t rd_u32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0])        |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t rd_u64(const uint8_t *p) {
    return static_cast<uint64_t>(rd_u32(p)) |
           (static_cast<uint64_t>(rd_u32(p + 4)) << 32);
}

inline uint64_t read_header_field(const uint8_t *evt, int off, int sz) {
    switch (sz) {
        case 2:  return rd_u16(evt + off);
        case 4:  return rd_u32(evt + off);
        case 8:  return rd_u64(evt + off);
        default: return 0;
    }
}


/* ================================================================
 * UTF-16LE to UTF-8 conversion
 * ================================================================ */

inline std::string utf16le_to_utf8(const uint8_t *data, int char_count) {
    std::string result;
    result.reserve(static_cast<size_t>(char_count));

    for (int i = 0; i < char_count; i++) {
        uint16_t c = rd_u16(data + i * 2);
        if (c == 0) break;

        if (c < 0x80) {
            result.push_back(static_cast<char>(c));
        } else if (c < 0x800) {
            result.push_back(static_cast<char>(0xC0 | (c >> 6)));
            result.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            if (c >= 0xD800 && c <= 0xDBFF && i + 1 < char_count) {
                uint16_t c2 = rd_u16(data + (i + 1) * 2);
                if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
                    uint32_t cp = 0x10000u +
                        ((static_cast<uint32_t>(c) - 0xD800u) << 10) +
                        (static_cast<uint32_t>(c2) - 0xDC00u);
                    result.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                    result.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                    result.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    result.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                    i++;
                    continue;
                }
            }
            result.push_back(static_cast<char>(0xE0 | (c >> 12)));
            result.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    return result;
}


/* ================================================================
 * Fixed-size UTF-16LE string reader (for PML header fields)
 * ================================================================ */

inline std::string read_utf16le_fixed(const uint8_t *data, int max_bytes) {
    int max_chars = max_bytes / 2;
    int len = 0;
    for (int i = 0; i < max_chars; i++) {
        if (rd_u16(data + i * 2) == 0) break;
        len = i + 1;
    }
    return utf16le_to_utf8(data, len);
}


/* ================================================================
 * Bounded UTF-16LE string reader (null-terminated within bounds)
 * ================================================================ */

inline std::string read_utf16le_bounded(const uint8_t *data, int byte_count) {
    if (byte_count <= 0) return {};
    int char_count = byte_count / 2;
    int len = char_count;
    for (int i = 0; i < char_count; i++) {
        if (rd_u16(data + i * 2) == 0) {
            len = i;
            break;
        }
    }
    return utf16le_to_utf8(data, len);
}
