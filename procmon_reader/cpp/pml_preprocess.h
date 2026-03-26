/*
 * pml_preprocess.h — Filter preprocessing types and field metadata.
 *
 * Field IDs, name normalization, operator parsing, value conversion
 * (ISO timestamp → FILETIME, duration → ticks, etc.).
 */

#pragma once

#include "pml_format.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>


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
    OP_ID_LE    = 2,
    OP_ID_GE    = 3,
    OP_ID_REGEX = 4,
};


/* ================================================================
 * Field metadata
 * ================================================================ */
struct FieldMeta {
    int field_id;            /* FieldId for select_fields / output */
    bool filterable;
    bool allows_comparison;  /* ==, !=, <=, >= */
    bool allows_regex;
};


/* ================================================================
 * Static lookup tables
 * ================================================================ */

/* Case-insensitive string hasher/comparator for unordered_map */
struct CaseInsensitiveHash {
    size_t operator()(const std::string &s) const {
        size_t h = 0;
        for (char c : s)
            h = h * 31 + static_cast<size_t>(std::tolower(static_cast<unsigned char>(c)));
        return h;
    }
};
struct CaseInsensitiveEqual {
    bool operator()(const std::string &a, const std::string &b) const {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); i++)
            if (std::tolower(static_cast<unsigned char>(a[i])) !=
                std::tolower(static_cast<unsigned char>(b[i])))
                return false;
        return true;
    }
};

using CIMap = std::unordered_map<std::string, int, CaseInsensitiveHash, CaseInsensitiveEqual>;
using CIMetaMap = std::unordered_map<std::string, FieldMeta, CaseInsensitiveHash, CaseInsensitiveEqual>;
using CIStrMap = std::unordered_map<std::string, std::string, CaseInsensitiveHash, CaseInsensitiveEqual>;


/* ----------------------------------------------------------------
 * Field name → canonical name
 * ---------------------------------------------------------------- */
inline const CIStrMap &field_name_aliases() {
    static const CIStrMap m = {
        {"event_index", "event_index"},
        {"event class", "event_class"}, {"eventclass", "event_class"},
        {"event_class", "event_class"},
        {"operation", "operation"},
        {"duration", "duration"},
        {"timestamp", "timestamp"}, {"date_filetime", "timestamp"},
        {"date", "timestamp"}, {"time", "timestamp"},
        {"datetime", "timestamp"}, {"date and time", "timestamp"},
        {"date_and_time", "timestamp"},
        {"result", "result"},
        {"tid", "tid"}, {"thread_id", "tid"}, {"thread id", "tid"},
        {"process_index", "process_index"},
        {"process_name", "process_name"}, {"processname", "process_name"},
        {"process name", "process_name"},
        {"pid", "pid"}, {"process_id", "pid"},
        {"parent_pid", "parent_pid"}, {"parent pid", "parent_pid"},
        {"parentpid", "parent_pid"},
        {"image_path", "image_path"}, {"imagepath", "image_path"},
        {"image path", "image_path"},
        {"command_line", "command_line"}, {"commandline", "command_line"},
        {"command line", "command_line"},
        {"user", "user"}, {"company", "company"},
        {"version", "version"}, {"description", "description"},
        {"integrity", "integrity"}, {"session", "session"},
        {"authentication_id", "authentication_id"},
        {"authenticationid", "authentication_id"},
        {"authentication id", "authentication_id"},
        {"virtualized", "virtualized"},
        {"is_64_bit", "is_64_bit"}, {"is_process_64bit", "is_64_bit"},
        {"architecture", "is_64_bit"},
        {"path", "path"}, {"category", "category"},
        {"detail", "detail"}, {"details", "detail"},
        {"stacktrace", "stacktrace"}, {"stack trace", "stacktrace"},
    };
    return m;
}


/* ----------------------------------------------------------------
 * Canonical field name → FieldMeta
 * ---------------------------------------------------------------- */
inline const CIMetaMap &field_registry() {
    static const CIMetaMap m = {
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


/* ----------------------------------------------------------------
 * FieldId → canonical user-facing name
 * ---------------------------------------------------------------- */
inline const std::unordered_map<int, std::string> &field_id_to_name() {
    static const std::unordered_map<int, std::string> m = {
        {FID_EVENT_INDEX,      "event_index"},
        {FID_EVENT_CLASS,      "event_class"},
        {FID_OPERATION_EXACT,  "operation"},
        {FID_OPERATION_REGEX,  "operation"},
        {FID_DURATION,         "duration"},
        {FID_TIMESTAMP,        "timestamp"},
        {FID_RESULT_EXACT,     "result"},
        {FID_RESULT_REGEX,     "result"},
        {FID_TID,              "tid"},
        {FID_PROCESS_INDEX,    "process_index"},
        {FID_PROCESS_NAME,     "process_name"},
        {FID_PID,              "pid"},
        {FID_PARENT_PID,       "parent_pid"},
        {FID_IMAGE_PATH,       "image_path"},
        {FID_COMMAND_LINE,     "command_line"},
        {FID_USER,             "user"},
        {FID_COMPANY,          "company"},
        {FID_VERSION,          "version"},
        {FID_DESCRIPTION,      "description"},
        {FID_INTEGRITY,        "integrity"},
        {FID_SESSION,          "session"},
        {FID_AUTHENTICATION_ID,"authentication_id"},
        {FID_VIRTUALIZED,      "virtualized"},
        {FID_IS_64_BIT,        "is_64_bit"},
        {FID_PATH,             "path"},
        {FID_CATEGORY,         "category"},
        {FID_DETAIL,           "detail"},
        {FID_STACKTRACE,       "stacktrace"},
    };
    return m;
}


/* ----------------------------------------------------------------
 * Operator string → OpId
 * ---------------------------------------------------------------- */
inline const CIMap &operator_aliases() {
    static const CIMap m = {
        {"==", OP_ID_EQ}, {"is", OP_ID_EQ}, {"equals", OP_ID_EQ},
        {"!=", OP_ID_NE}, {"is_not", OP_ID_NE}, {"not_equals", OP_ID_NE},
        {"<=", OP_ID_LE}, {"le", OP_ID_LE}, {"less_equal", OP_ID_LE},
        {">=", OP_ID_GE}, {"ge", OP_ID_GE}, {"more_equal", OP_ID_GE},
        {"regex", OP_ID_REGEX},
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


/* ----------------------------------------------------------------
 * Normalize a user field name to canonical form
 * Returns empty string if unknown.
 * ---------------------------------------------------------------- */
inline std::string normalize_field_name(const std::string &name) {
    std::string key = trim(name);
    /* lowercase for lookup */
    for (char &c : key)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    auto it = field_name_aliases().find(key);
    return (it != field_name_aliases().end()) ? it->second : "";
}


/* ----------------------------------------------------------------
 * Parse operator string to OpId. Returns -1 if unknown.
 * ---------------------------------------------------------------- */
inline int parse_operator(const std::string &op) {
    std::string key = trim(op);
    for (char &c : key)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    auto it = operator_aliases().find(key);
    return (it != operator_aliases().end()) ? it->second : -1;
}


/* ----------------------------------------------------------------
 * Resolve canonical field name to FieldMeta. Returns nullptr if unknown.
 * ---------------------------------------------------------------- */
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


/* Check if regex pattern is a plain substring (no regex metacharacters).
 * Returns the literal substring if plain, nullopt otherwise.
 * This allows replacing std::regex_search with string::find for simple
 * "contains" style matching. */
inline std::optional<std::string> is_plain_substring(const std::string &pattern) {
    if (pattern.empty()) return std::nullopt;
    for (char c : pattern) {
        switch (c) {
            case '.': case '*': case '+': case '?':
            case '[': case ']': case '(': case ')':
            case '{': case '}': case '|': case '\\':
            case '^': case '$':
                return std::nullopt;
            default:
                break;
        }
    }
    return pattern;
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


/* ================================================================
 * Event class name → value conversion
 * ================================================================ */
inline const CIMap &event_class_name_to_value() {
    static const CIMap m = {
        {"UNKNOWN", 0},
        {"PROCESS", 1},
        {"REGISTRY", 2},
        {"FILE SYSTEM", 3}, {"FILE_SYSTEM", 3},
        {"PROFILING", 4},
        {"NETWORK", 5},
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
