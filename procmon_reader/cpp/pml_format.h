/*
 * pml_format.h — Output value formatting for PML events.
 *
 * Timestamps, operation names, NTSTATUS codes, duration,
 * event class, and authentication ID formatting.
 */

#pragma once

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>
#include <unordered_map>


namespace pml_fmt {

/* FILETIME epoch: 1601-01-01 in 100ns ticks since Unix epoch 1970-01-01 */
constexpr int64_t EPOCH_AS_FILETIME = 116444736000000000LL;
constexpr int64_t TICKS_PER_SECOND  = 10000000LL;


/* ----------------------------------------------------------------
 * Timestamp: FILETIME → "YYYY-MM-DDTHH:MM:SS.ttttttt"
 * ---------------------------------------------------------------- */
inline std::string format_timestamp(uint64_t filetime, int tz_offset_seconds) {
    if (filetime <= static_cast<uint64_t>(EPOCH_AS_FILETIME))
        return std::to_string(filetime);

    int64_t ft = static_cast<int64_t>(filetime);
    int64_t unix_secs = (ft - EPOCH_AS_FILETIME) / TICKS_PER_SECOND;
    int64_t ticks = ft % TICKS_PER_SECOND;

    /* Apply timezone offset */
    unix_secs += tz_offset_seconds;

    /* Break into components using gmtime (we already applied tz offset) */
    time_t t = static_cast<time_t>(unix_secs);
    struct tm tm_buf;
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif

    char buf[64];
    std::snprintf(buf, sizeof(buf),
        "%04d-%02d-%02dT%02d:%02d:%02d.%07lld",
        tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
        tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
        static_cast<long long>(ticks));
    return std::string(buf);
}


/* ----------------------------------------------------------------
 * Event class → display name
 * ---------------------------------------------------------------- */
inline std::string format_event_class(uint32_t ec) {
    switch (ec) {
        case 0: return "Unknown";
        case 1: return "Process";
        case 2: return "Registry";
        case 3: return "File System";
        case 4: return "Profiling";
        case 5: return "Network";
        default: return std::to_string(ec);
    }
}


/* ----------------------------------------------------------------
 * Operation → display name (with sub-op and network protocol)
 * ---------------------------------------------------------------- */
inline std::string format_operation(
    uint32_t event_class, uint16_t operation,
    int sub_operation,       /* -1 if not applicable */
    bool op_has_sub_ops,     /* true when this op has a sub-operation table */
    const std::string *network_protocol,  /* nullptr if not applicable */
    const std::unordered_map<uint32_t, std::string> &op_lut,
    const std::unordered_map<uint32_t, std::string> &sub_op_lut)
{
    /* Try sub-operation first (for filesystem events with sub-ops) */
    std::string name;
    if (sub_operation >= 0) {
        uint32_t sub_key = (static_cast<uint32_t>(operation) << 16) |
                           static_cast<uint32_t>(sub_operation);
        auto it = sub_op_lut.find(sub_key);
        if (it != sub_op_lut.end()) {
            name = it->second;
        } else if (sub_operation != 0 && op_has_sub_ops) {
            /* Sub-op is non-zero but not in the table for an op that does
               have a sub-op table: Procmon displays "<Unknown>". */
            name = "<Unknown>";
        }
        /* Otherwise (no sub-op table for this op, or sub_op==0) fall
           through to the main operation name below. */
    }

    /* Fall back to main operation */
    if (name.empty()) {
        uint32_t key = (event_class << 16) | static_cast<uint32_t>(operation);
        auto it = op_lut.find(key);
        if (it != op_lut.end())
            name = it->second;
        else
            name = "<Unknown: " + std::to_string(operation) + ">";
    }

    /* Prepend network protocol */
    if (network_protocol && !network_protocol->empty())
        return *network_protocol + " " + name;

    return name;
}


/* ----------------------------------------------------------------
 * Result → NTSTATUS display name
 * ---------------------------------------------------------------- */
inline std::string format_result(
    uint32_t result_code,
    const std::unordered_map<uint32_t, std::string> &err_lut)
{
    auto it = err_lut.find(result_code);
    if (it != err_lut.end())
        return it->second;
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%X", result_code);
    return std::string(buf);
}


/* ----------------------------------------------------------------
 * Duration → "0.0000000" (seconds with 7 decimal places)
 * Returns "" when result is pending (err_lut maps to empty string).
 * ---------------------------------------------------------------- */
inline std::string format_duration(
    uint64_t duration_ticks, uint32_t result_code,
    const std::unordered_map<uint32_t, std::string> &err_lut)
{
    /* Check if result is "pending" — error LUT maps to empty string */
    auto it = err_lut.find(result_code);
    if (it != err_lut.end() && it->second.empty())
        return "";

    double secs = static_cast<double>(duration_ticks) / static_cast<double>(TICKS_PER_SECOND);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.7f", secs);
    return std::string(buf);
}


/* ----------------------------------------------------------------
 * Authentication ID → "xxxxxxxx:xxxxxxxx" (LUID format)
 * ---------------------------------------------------------------- */
inline std::string format_auth_id(uint64_t auth_id) {
    char buf[24];
    uint32_t high = static_cast<uint32_t>(auth_id >> 32);
    uint32_t low  = static_cast<uint32_t>(auth_id & 0xFFFFFFFF);
    std::snprintf(buf, sizeof(buf), "%08x:%08x", high, low);
    return std::string(buf);
}


} /* namespace pml_fmt */
