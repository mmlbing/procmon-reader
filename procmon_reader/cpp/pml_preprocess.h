/*
 * pml_preprocess.h — Filter preprocessing types and field metadata.
 *
 * Field IDs, operator parsing, value conversion
 * (ISO timestamp → FILETIME, duration → ticks, etc.).
 *
 * Field name and operator alias resolution is handled by Python (filters.py);
 * C++ receives only canonical field names and operator strings.
 */

#pragma once

#include "pml_format.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace pml_pre {


/* ================================================================
 * Field IDs — must match Python FieldId enum values exactly
 * ================================================================ */
enum FieldId : int {
    FID_EVENT_INDEX      = 0,
    FID_EVENT_CLASS      = 1,
    FID_OPERATION_EXACT  = 2,
    FID_OPERATION_REGEX  = 3,
    FID_DURATION         = 4,
    FID_TIMESTAMP        = 5,
    FID_RESULT_EXACT     = 6,
    FID_RESULT_REGEX     = 7,
    FID_TID              = 8,

    FID_PROCESS_INDEX    = 20,
    FID_PROCESS_NAME     = 21,
    FID_PID              = 22,
    FID_PARENT_PID       = 23,
    FID_IMAGE_PATH       = 24,
    FID_COMMAND_LINE     = 25,
    FID_USER             = 26,
    FID_COMPANY          = 27,
    FID_VERSION          = 28,
    FID_DESCRIPTION      = 29,
    FID_INTEGRITY        = 30,
    FID_SESSION          = 31,
    FID_AUTHENTICATION_ID = 32,
    FID_VIRTUALIZED      = 33,
    FID_IS_64_BIT        = 34,

    FID_PATH             = 40,
    FID_CATEGORY         = 41,
    FID_DETAIL           = 42,

    FID_STACKTRACE       = 50,
};


/* ================================================================
 * Field categories
 * ================================================================ */
enum FieldCategory : int {
    CAT_DIRECT_HEADER = 0,
    CAT_PROCESS       = 1,
    CAT_DETAIL        = 2,
    CAT_STACKTRACE    = 3,
};

inline FieldCategory get_field_category(int fid) {
    switch (fid) {
        case FID_EVENT_INDEX: case FID_EVENT_CLASS:
        case FID_OPERATION_EXACT: case FID_OPERATION_REGEX:
        case FID_DURATION: case FID_TIMESTAMP:
        case FID_RESULT_EXACT: case FID_RESULT_REGEX: case FID_TID:
            return CAT_DIRECT_HEADER;
        case FID_PROCESS_INDEX: case FID_PROCESS_NAME: case FID_PID:
        case FID_PARENT_PID: case FID_IMAGE_PATH: case FID_COMMAND_LINE:
        case FID_USER: case FID_COMPANY: case FID_VERSION:
        case FID_DESCRIPTION: case FID_INTEGRITY: case FID_SESSION:
        case FID_AUTHENTICATION_ID: case FID_VIRTUALIZED: case FID_IS_64_BIT:
            return CAT_PROCESS;
        case FID_PATH: case FID_CATEGORY: case FID_DETAIL:
            return CAT_DETAIL;
        default:
            return CAT_STACKTRACE;
    }
}


/* ================================================================
 * Operator IDs
 * ================================================================ */
enum OpId : int {
    OP_ID_EQ    = 0,
    OP_ID_NE    = 1,
    OP_ID_LT    = 2,
    OP_ID_LE    = 3,
    OP_ID_GE    = 4,
    OP_ID_GT    = 5,
    OP_ID_REGEX = 6,
};


/* ================================================================
 * Field metadata
 * ================================================================ */
struct FieldMeta {
    int field_id;            /* FieldId for select_fields / output */
    bool filterable;
    bool allows_comparison;  /* ==, !=, <, <=, >=, > */
    bool allows_regex;
};


/* ================================================================
 * Static lookup tables
 * ================================================================ */

/* Canonical field name → FieldMeta (field names are pre-normalized by Python) */
inline const std::unordered_map<std::string, FieldMeta> &field_registry() {
    static const std::unordered_map<std::string, FieldMeta> m = {
        {"event_index",       {FID_EVENT_INDEX,      true,  true,  false}},
        {"event_class",       {FID_EVENT_CLASS,      true,  true,  false}},
        {"operation",         {FID_OPERATION_REGEX,  true,  false, true}},
        {"duration",          {FID_DURATION,         true,  true,  false}},
        {"timestamp",         {FID_TIMESTAMP,        true,  true,  false}},
        {"result",            {FID_RESULT_REGEX,     true,  false, true}},
        {"tid",               {FID_TID,              true,  true,  false}},
        {"process_index",     {FID_PROCESS_INDEX,    false, false, false}},
        {"process_name",      {FID_PROCESS_NAME,     true,  false, true}},
        {"pid",               {FID_PID,              true,  true,  false}},
        {"parent_pid",        {FID_PARENT_PID,       true,  true,  false}},
        {"image_path",        {FID_IMAGE_PATH,       true,  false, true}},
        {"command_line",      {FID_COMMAND_LINE,     true,  false, true}},
        {"user",              {FID_USER,             true,  false, true}},
        {"company",           {FID_COMPANY,          true,  false, true}},
        {"version",           {FID_VERSION,          true,  false, true}},
        {"description",       {FID_DESCRIPTION,      true,  false, true}},
        {"integrity",         {FID_INTEGRITY,        true,  false, true}},
        {"session",           {FID_SESSION,          true,  true,  false}},
        {"authentication_id", {FID_AUTHENTICATION_ID,true,  true,  false}},
        {"virtualized",       {FID_VIRTUALIZED,      true,  true,  false}},
        {"is_64_bit",         {FID_IS_64_BIT,        true,  true,  false}},
        {"path",              {FID_PATH,             true,  false, true}},
        {"category",          {FID_CATEGORY,         true,  false, true}},
        {"detail",            {FID_DETAIL,           true,  false, true}},
        {"stacktrace",        {FID_STACKTRACE,       false, false, false}},
    };
    return m;
}


/* ================================================================
 * Normalization helpers
 * ================================================================ */

/* Trim leading/trailing whitespace */
inline std::string trim(const std::string &s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

/* Convert string to uppercase */
inline std::string to_upper(const std::string &s) {
    std::string r = s;
    for (char &c : r)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return r;
}


/* Parse canonical operator string to OpId.
 * Python pre-normalizes all aliases; only canonical forms reach C++.
 * Returns -1 if unknown. */
inline int parse_operator(const std::string &op) {
    if (op == "==")    return OP_ID_EQ;
    if (op == "!=")    return OP_ID_NE;
    if (op == "<")     return OP_ID_LT;
    if (op == "<=")    return OP_ID_LE;
    if (op == ">=")    return OP_ID_GE;
    if (op == ">")     return OP_ID_GT;
    if (op == "regex") return OP_ID_REGEX;
    return -1;
}


/* Resolve canonical field name to FieldMeta. Returns nullptr if unknown. */
inline const FieldMeta *get_field_meta(const std::string &canonical) {
    auto it = field_registry().find(canonical);
    return (it != field_registry().end()) ? &it->second : nullptr;
}


/* ================================================================
 * Exact regex detection
 * ================================================================ */

/* Check if regex pattern is ^LiteralName$ (no special regex chars).
 * Returns the literal string if exact, nullopt otherwise. */
inline std::optional<std::string> is_exact_regex(const std::string &pattern) {
    if (pattern.size() < 3 || pattern.front() != '^' || pattern.back() != '$')
        return std::nullopt;
    std::string inner = pattern.substr(1, pattern.size() - 2);
    /* Only allow alphanumeric, underscore, space */
    for (char c : inner) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != ' ')
            return std::nullopt;
    }
    return inner;
}

/* Check if regex is ^A$|^B$|^C$ (multi-exact alternation).
 * Returns the list of literal strings, nullopt otherwise. */
inline std::optional<std::vector<std::string>> is_multi_exact_regex(const std::string &pattern) {
    if (pattern.size() < 3) return std::nullopt;
    /* Split on | first, then check each part is ^literal$ */
    std::vector<std::string> parts;
    std::string cur;
    for (size_t i = 0; i < pattern.size(); i++) {
        if (pattern[i] == '|') {
            if (cur.empty()) return std::nullopt;
            parts.push_back(std::move(cur));
            cur.clear();
        } else {
            cur += pattern[i];
        }
    }
    if (cur.empty()) return std::nullopt;
    parts.push_back(std::move(cur));
    if (parts.size() < 2) return std::nullopt;  /* single → use is_exact_regex */
    /* Validate each part is ^literal$ */
    std::vector<std::string> result;
    result.reserve(parts.size());
    for (auto &p : parts) {
        auto ex = is_exact_regex(p);
        if (!ex) return std::nullopt;
        result.push_back(std::move(*ex));
    }
    return result;
}


/* Try to decompose a regex pattern into plain substrings.
 * Handles both single literals ("SUCCESS") and alternations ("NOT|DENIED|LOCKED").
 * Returns nullopt if any part contains regex metacharacters. */
inline std::optional<std::vector<std::string>> is_multi_substring(const std::string &pattern) {
    if (pattern.empty()) return std::nullopt;
    std::vector<std::string> parts;
    std::string cur;
    for (char c : pattern) {
        if (c == '|') {
            if (cur.empty()) return std::nullopt;   /* empty alternative */
            parts.push_back(std::move(cur));
            cur.clear();
        } else {
            switch (c) {
                case '.': case '*': case '+': case '?':
                case '[': case ']': case '(': case ')':
                case '{': case '}': case '\\':
                case '^': case '$':
                    return std::nullopt;
                default:
                    cur += c;
                    break;
            }
        }
    }
    if (cur.empty()) return std::nullopt;           /* trailing '|' */
    parts.push_back(std::move(cur));
    return parts;
}

/* Case-insensitive substring search ("contains").
 * Returns true if needle is found within haystack, ignoring case. */
inline bool ci_contains(const std::string &haystack, const std::string &needle) {
    if (needle.empty()) return true;
    if (needle.size() > haystack.size()) return false;
    auto it = std::search(haystack.begin(), haystack.end(),
                          needle.begin(), needle.end(),
                          [](char a, char b) {
                              return std::tolower(static_cast<unsigned char>(a)) ==
                                     std::tolower(static_cast<unsigned char>(b));
                          });
    return it != haystack.end();
}

/* Case-insensitive check: does haystack contain ANY of the needles? */
inline bool ci_contains_any(const std::string &haystack,
                            const std::vector<std::string> &needles) {
    for (const auto &n : needles) {
        if (ci_contains(haystack, n)) return true;
    }
    return false;
}


/* ================================================================
 * Event class name → value conversion
 * (Python pre-normalizes aliases; only canonical names reach C++)
 * ================================================================ */
inline const std::unordered_map<std::string, int> &event_class_name_to_value() {
    static const std::unordered_map<std::string, int> m = {
        {"Unknown",     0},
        {"Process",     1},
        {"Registry",    2},
        {"File System", 3},
        {"Profiling",   4},
        {"Network",     5},
    };
    return m;
}


/* ================================================================
 * Value conversion helpers
 * ================================================================ */

/* Convert event_class string or int to internal value.
 * Returns -1 on failure. */
inline int convert_event_class(const std::string &value) {
    auto it = event_class_name_to_value().find(trim(value));
    if (it != event_class_name_to_value().end())
        return it->second;
    /* Try numeric */
    try {
        return std::stoi(value);
    } catch (...) {
        return -1;
    }
}

/* Convert duration string (seconds) to 100ns ticks.
 * Returns -1 on failure. */
inline int64_t convert_duration_to_ticks(const std::string &value) {
    try {
        double secs = std::stod(value);
        return static_cast<int64_t>(secs * pml_fmt::TICKS_PER_SECOND);
    } catch (...) {
        return -1;
    }
}

/* Parse ISO 8601 timestamp string to FILETIME.
 * tz_offset_seconds: timezone offset applied to naive timestamps.
 * Returns 0 on failure. */
inline uint64_t convert_timestamp_to_filetime(const std::string &value, int tz_offset_seconds) {
    /* Very simple ISO 8601 parser: YYYY-MM-DDTHH:MM:SS[.fractional] */
    int year, month, day, hour, minute, second;
    double frac = 0.0;

    /* Parse YYYY-MM-DDTHH:MM:SS using C++ streams */
    {
        std::istringstream iss(value);
        char sep;
        iss >> year >> sep >> month >> sep >> day >> sep
            >> hour >> sep >> minute >> sep >> second;
        if (iss.fail()) return 0;
    }

    /* Extract fractional part after seconds */
    auto dot_pos = value.find('.', value.find('T'));
    if (dot_pos != std::string::npos) {
        std::string frac_str = "0" + value.substr(dot_pos);
        /* Remove trailing timezone if any */
        for (size_t i = 1; i < frac_str.size(); i++) {
            if (frac_str[i] == '+' || frac_str[i] == '-' || frac_str[i] == 'Z') {
                frac_str = frac_str.substr(0, i);
                break;
            }
        }
        try { frac = std::stod(frac_str); } catch (...) {}
    }

    /* Convert to time_t-like value using a manual calendar calculation */
    struct tm tm_buf = {};
    tm_buf.tm_year = year - 1900;
    tm_buf.tm_mon  = month - 1;
    tm_buf.tm_mday = day;
    tm_buf.tm_hour = hour;
    tm_buf.tm_min  = minute;
    tm_buf.tm_sec  = second;
    tm_buf.tm_isdst = 0;

    /* Use _mkgmtime on Windows, timegm on Unix */
#ifdef _WIN32
    time_t t = _mkgmtime(&tm_buf);
#else
    time_t t = timegm(&tm_buf);
#endif
    if (t == static_cast<time_t>(-1)) return 0;

    /* Subtract timezone offset (input is in local time, convert to UTC) */
    int64_t unix_secs = static_cast<int64_t>(t) - tz_offset_seconds;
    int64_t ticks = static_cast<int64_t>(frac * pml_fmt::TICKS_PER_SECOND);

    return static_cast<uint64_t>(unix_secs * pml_fmt::TICKS_PER_SECOND +
                                  ticks + pml_fmt::EPOCH_AS_FILETIME);
}

/* Convert an integer string (decimal or hex). Returns -1 on failure. */
inline int64_t convert_int(const std::string &value) {
    std::string v = trim(value);
    try {
        if (v.size() > 2 && (v[0] == '0') && (v[1] == 'x' || v[1] == 'X'))
            return static_cast<int64_t>(std::stoull(v, nullptr, 16));
        return std::stoll(v);
    } catch (...) {
        return -1;
    }
}

/* Convert authentication_id (LUID "XXXXXXXX:XXXXXXXX" or int). */
inline int64_t convert_authentication_id(const std::string &value) {
    std::string v = trim(value);
    auto colon = v.find(':');
    if (colon != std::string::npos) {
        try {
            uint64_t high = std::stoull(v.substr(0, colon), nullptr, 16);
            uint64_t low  = std::stoull(v.substr(colon + 1), nullptr, 16);
            return static_cast<int64_t>((high << 32) | low);
        } catch (...) {
            return -1;
        }
    }
    return convert_int(v);
}

/* Convert bool string. Returns -1 on failure, 0 or 1 on success. */
inline int convert_bool(const std::string &value) {
    std::string v = to_upper(trim(value));
    if (v == "TRUE" || v == "1") return 1;
    if (v == "FALSE" || v == "0") return 0;
    return -1;
}


/* ================================================================
 * Build reverse lookup maps from forward LUTs (for exact-match)
 * ================================================================ */

/* Build operation name → (event_class, operation_value) map */
inline std::unordered_map<std::string, std::pair<uint32_t, uint32_t>>
build_op_name_to_value(const std::unordered_map<uint32_t, std::string> &op_lut) {
    std::unordered_map<std::string, std::pair<uint32_t, uint32_t>> result;
    for (auto &[key, name] : op_lut) {
        uint32_t ec = key >> 16;
        uint32_t op = key & 0xFFFF;
        std::string upper_name = to_upper(name);
        result[upper_name] = {ec, op};
        /* Also add underscore variant */
        std::string under_name = upper_name;
        std::replace(under_name.begin(), under_name.end(), ' ', '_');
        if (under_name != upper_name)
            result[under_name] = {ec, op};
    }
    return result;
}

/* Build result name → NTSTATUS code map */
inline std::unordered_map<std::string, uint32_t>
build_result_name_to_code(const std::unordered_map<uint32_t, std::string> &err_lut) {
    std::unordered_map<std::string, uint32_t> result;
    for (auto &[code, name] : err_lut) {
        if (!name.empty()) {
            std::string upper_name = to_upper(name);
            result[upper_name] = code;
        }
    }
    return result;
}


} /* namespace pml_pre */
