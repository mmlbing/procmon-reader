/*
 * pml_detail_network.cpp — Network and Profiling event detail extraction.
 */

#include "pml_detail.h"
#include "pml_detail_common.h"

#include <cstdint>
#include <string>


/* ================================================================
 * Public: extract_network_detail_json
 * ================================================================ */

std::string extract_network_detail_json(
    const uint8_t *detail_data, int detail_size, uint16_t operation)
{
    if (detail_size < 8) return "{}";
    JsonBuilder jb;
    /* Offset 4: u32 Length */
    uint32_t length = rd_u32(detail_data + 4);
    jb.add_uint("Length", length);
    /* Offset 44: UTF-16LE key-value pair strings */
    static const int KV_OFFSET = 44;
    if (detail_size > KV_OFFSET) {
        const uint8_t *p = detail_data + KV_OFFSET;
        int remaining = detail_size - KV_OFFSET;
        while (remaining >= 2) {
            /* Read a null-terminated UTF-16LE string */
            int end = 0;
            while (end + 1 < remaining) {
                uint16_t cu = rd_u16(p + end);
                if (cu == 0) break;
                end += 2;
            }
            if (end == 0 && rd_u16(p) == 0) {
                break;
            }
            std::string key = utf16le_to_utf8(p, end / 2);
            p += end + 2; remaining -= end + 2;
            /* Read value string */
            end = 0;
            while (end + 1 < remaining) {
                uint16_t cu = rd_u16(p + end);
                if (cu == 0) break;
                end += 2;
            }
            if (remaining < 2) break;
            std::string val = utf16le_to_utf8(p, end / 2);
            p += end + 2; remaining -= end + 2;
            if (!key.empty()) {
                /* TCP Connect/Accept: Procmon omits sndwinscale, seqnum, connid */
                if ((operation == 5 || operation == 4) &&
                    (key == "sndwinscale" || key == "seqnum" || key == "connid"))
                    continue;
                /* Try to parse val as a decimal integer */
                bool is_digit = !val.empty();
                for (char c : val) { if (c < '0' || c > '9') { is_digit = false; break; } }
                if (is_digit) {
                    uint64_t n = 0;
                    for (char c : val) n = n * 10 + (c - '0');
                    jb.add_uint(key.c_str(), n);
                } else {
                    jb.add_str(key.c_str(), val);
                }
            }
        }
    }
    return jb.build();
}


/* ================================================================
 * Public: extract_profiling_detail_json
 * ================================================================ */

std::string extract_profiling_detail_json(
    const uint8_t *detail_data, int detail_size)
{
    if (detail_size < 32) return "{}";
    DetailReader dr(detail_data, detail_size);
    uint64_t user_ticks    = dr.u64();
    uint64_t kernel_ticks  = dr.u64();
    uint64_t working_set   = dr.u64();
    uint64_t private_bytes = dr.u64();
    JsonBuilder jb;
    jb.add_str("User Time",     format_profiling_ticks(user_ticks));
    jb.add_str("Kernel Time",   format_profiling_ticks(kernel_ticks));
    jb.add_str("Private Bytes", std::to_string(private_bytes));
    jb.add_str("Working Set",   std::to_string(working_set));
    return jb.build();
}
