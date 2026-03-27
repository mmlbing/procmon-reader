/*
 * pml_detail_common.h — Shared utilities for PML event detail extraction.
 *
 * DetailReader (stream-like binary reader with bounds checking),
 * JsonBuilder (lightweight JSON object builder), and common
 * formatting functions used by detail extraction modules.
 *
 * Header-only; safe to include from multiple translation units.
 */

#pragma once

#include "pml_utils.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>


/* ================================================================
 * Read a PML string from detail data
 * ================================================================ */
inline std::string read_pml_string(const uint8_t *data, int offset, int max_bytes,
                                   bool is_ascii, int char_count) {
    if (char_count <= 0) return {};
    int needed = is_ascii ? char_count : char_count * 2;
    if (offset + needed > max_bytes) return {};

    if (is_ascii) {
        const char *s = reinterpret_cast<const char *>(data + offset);
        int len = char_count;
        while (len > 0 && s[len - 1] == '\0') len--;
        return std::string(s, static_cast<size_t>(len));
    }
    std::string r = utf16le_to_utf8(data + offset, char_count);
    while (!r.empty() && r.back() == '\0') r.pop_back();
    return r;
}


/* ================================================================
 * DetailReader — Stream-like reader with bounds checking
 * ================================================================ */
struct DetailReader {
    const uint8_t *data;
    int size;
    int pos;

    DetailReader(const uint8_t *d, int s) : data(d), size(s), pos(0) {}
    bool has(int n) const { return pos + n <= size; }
    void skip(int n) { pos = std::min(pos + n, size); }
    uint8_t  u8()  { if (!has(1)) return 0; return data[pos++]; }
    uint16_t u16() { if (!has(2)) return 0; uint16_t v = rd_u16(data+pos); pos += 2; return v; }
    uint32_t u32() { if (!has(4)) return 0; uint32_t v = rd_u32(data+pos); pos += 4; return v; }
    uint64_t u64() { if (!has(8)) return 0; uint64_t v = rd_u64(data+pos); pos += 8; return v; }
    int64_t  i64() { if (!has(8)) return 0; int64_t v; std::memcpy(&v, data+pos, 8); pos += 8; return v; }

    std::string pml_string() {
        if (!has(2)) return {};
        uint16_t info = u16();
        bool is_ascii = (info >> 15) == 1;
        int count = info & 0x7FFF;
        if (count == 0) return {};
        int needed = is_ascii ? count : count * 2;
        if (!has(needed)) return {};
        std::string result;
        if (is_ascii) {
            result = std::string(reinterpret_cast<const char*>(data+pos), static_cast<size_t>(count));
            pos += count;
        } else {
            result = utf16le_to_utf8(data+pos, count);
            pos += count * 2;
        }
        while (!result.empty() && result.back() == '\0') result.pop_back();
        return result;
    }

    void read_path_info(uint16_t &out_info) {
        out_info = has(2) ? u16() : 0;
    }

    void skip_pml_string_data(uint16_t info) {
        bool is_ascii = (info >> 15) == 1;
        int count = info & 0x7FFF;
        skip(is_ascii ? count : count * 2);
    }

    std::string read_pml_string_data(uint16_t info) {
        bool is_ascii = (info >> 15) == 1;
        int count = info & 0x7FFF;
        if (count == 0) return {};
        return read_pml_string(data, pos, size, is_ascii, count);
    }
};


/* ================================================================
 * JsonBuilder — Lightweight JSON object builder
 * ================================================================ */
struct JsonBuilder {
    std::string buf;
    int count;

    JsonBuilder() : count(0) {}

    void add_str(const char *key, const std::string &val) {
        _sep(); buf += '"'; buf += key; buf += "\": \""; _esc(val); buf += '"';
    }
    void add_int(const char *key, int64_t val) {
        _sep(); buf += '"'; buf += key; buf += "\": "; buf += std::to_string(val);
    }
    void add_uint(const char *key, uint64_t val) {
        _sep(); buf += '"'; buf += key; buf += "\": "; buf += std::to_string(val);
    }
    void add_hex(const char *key, uint64_t val) {
        char tmp[32]; std::snprintf(tmp, sizeof(tmp), "0x%llx", (unsigned long long)val);
        _sep(); buf += '"'; buf += key; buf += "\": \""; buf += tmp; buf += '"';
    }
    void add_bool_str(const char *key, bool val) {
        _sep(); buf += '"'; buf += key; buf += "\": \""; buf += (val ? "True" : "False"); buf += '"';
    }
    void add_str_list(const char *key, const std::vector<std::string> &vals) {
        _sep(); buf += '"'; buf += key; buf += "\": [";
        for (size_t i = 0; i < vals.size(); i++) {
            if (i) buf += ", ";
            buf += '"'; _esc(vals[i]); buf += '"';
        }
        buf += ']';
    }

    bool empty() const { return count == 0; }
    std::string build() const { return "{" + buf + "}"; }

private:
    void _sep() { if (count++ > 0) buf += ", "; }
    void _esc(const std::string &s) {
        for (char c : s) {
            switch (c) {
                case '"':  buf += "\\\""; break;
                case '\\': buf += "\\\\"; break;
                case '\n': buf += "\\n"; break;
                case '\r': buf += "\\r"; break;
                case '\t': buf += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char tmp[8];
                        std::snprintf(tmp, sizeof(tmp), "\\u%04x",
                                      static_cast<unsigned>(static_cast<unsigned char>(c)));
                        buf += tmp;
                    } else {
                        buf += c;
                    }
                    break;
            }
        }
    }
};


/* ================================================================
 * Time and duration formatting
 * ================================================================ */

/* Convert a FILETIME (100ns ticks since 1601-01-01 UTC) to
 * Procmon display format: "M/D/YYYY H:MM:SS AM/PM" in local time.
 * If allow_epoch is true, ft==0 is formatted as the epoch date/time;
 * otherwise ft==0 returns "n/a". */
inline std::string format_filetime_local(uint64_t ft, int tz_offset_seconds,
                                         bool allow_epoch = false) {
    if (ft == 0 && !allow_epoch) return "n/a";
    static const int64_t FT_TO_UNIX_OFFSET_100NS = 116444736000000000LL;
    int64_t unix_100ns = static_cast<int64_t>(ft) - FT_TO_UNIX_OFFSET_100NS;
    int64_t unix_secs;
    if (unix_100ns >= 0)
        unix_secs = unix_100ns / 10000000LL;
    else
        unix_secs = (unix_100ns - 9999999LL) / 10000000LL;
    int64_t local_secs = unix_secs + tz_offset_seconds;
    int64_t days = local_secs / 86400LL;
    int sod = (int)(local_secs % 86400LL);
    if (sod < 0) { sod += 86400; days--; }
    int64_t z = days + 719468LL;
    int64_t era = (z >= 0 ? z : z - 146096LL) / 146097LL;
    int64_t doe = z - era * 146097LL;
    int64_t yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    int64_t y = yoe + era * 400LL;
    int64_t doy = doe - (365*yoe + yoe/4 - yoe/100);
    int64_t mp = (5*doy + 2) / 153;
    int d = (int)(doy - (153*mp+2)/5 + 1);
    int m = (int)(mp < 10 ? mp + 3 : mp - 9);
    if (m <= 2) y++;
    int year = (int)y;
    int hour = sod / 3600;
    int minute = (sod % 3600) / 60;
    int second = sod % 60;
    const char *ampm = (hour < 12) ? "AM" : "PM";
    int hour12 = hour % 12;
    if (hour12 == 0) hour12 = 12;
    char buf[64];  // 64 bytes: year as int can be up to 11 chars, prevents -Wformat-truncation
    std::snprintf(buf, sizeof(buf), "%d/%d/%d %d:%02d:%02d %s",
                  m, d, year, hour12, minute, second, ampm);
    return buf;
}

inline std::string format_duration_ticks(uint64_t ticks) {
    uint64_t secs_total = ticks / 10000000ULL;
    uint64_t frac = ticks % 10000000ULL;
    uint64_t mins_total = secs_total / 60;
    uint64_t secs = secs_total % 60;
    uint64_t hours = mins_total / 60;
    uint64_t mins = mins_total % 60;
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%llu:%02llu:%02llu.%07llu",
                  (unsigned long long)hours, (unsigned long long)mins,
                  (unsigned long long)secs, (unsigned long long)frac);
    return buf;
}

/* Format CPU ticks (100ns units) as "s.fffffff" */
inline std::string format_cpu_ticks(uint64_t ticks) {
    uint64_t secs = ticks / 10000000ULL;
    uint64_t frac = ticks % 10000000ULL;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llu.%07llu",
                  (unsigned long long)secs, (unsigned long long)frac);
    return buf;
}

/* Same as format_cpu_ticks but appends " seconds" for Process Profiling events. */
inline std::string format_profiling_ticks(uint64_t ticks) {
    return format_cpu_ticks(ticks) + " seconds";
}
