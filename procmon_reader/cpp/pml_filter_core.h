/*
 * pml_filter_core.h — Multi-threaded PML event filter engine.
 *
 * AND/OR/NOT filter tree evaluation, path/detail extraction,
 * and operation/result/category name resolution.
 */

#pragma once

#include "pml_utils.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <regex>
#include <unordered_map>


/* ================================================================
 * Constants: PML Event Header Layout (PML v9, 52 bytes)
 * ================================================================ */

constexpr int EVT_PROCESS_INDEX        = 0x00;  /* u32 */
constexpr int EVT_THREAD_ID            = 0x04;  /* u32 */
constexpr int EVT_EVENT_CLASS          = 0x08;  /* u32 */
constexpr int EVT_OPERATION            = 0x0C;  /* u16 */
constexpr int EVT_DURATION             = 0x14;  /* u64 */
constexpr int EVT_DATE_FILETIME        = 0x1C;  /* u64 */
constexpr int EVT_RESULT               = 0x24;  /* u32 */
constexpr int EVT_STACKTRACE_DEPTH     = 0x28;  /* u16 */
constexpr int EVT_DETAILS_SIZE         = 0x2C;  /* u32 */
constexpr int EVT_EXTRA_DETAILS_OFFSET = 0x30;  /* u32 */
constexpr int EVT_HEADER_SIZE          = 0x34;  /* 52 bytes total */

/* Comparison operator IDs */
constexpr int OP_EQ    = 0;
constexpr int OP_NE    = 1;
constexpr int OP_LE    = 2;
constexpr int OP_GE    = 3;
constexpr int OP_REGEX = 4;

/* Event class values */
constexpr uint32_t EC_PROCESS     = 1;
constexpr uint32_t EC_REGISTRY    = 2;
constexpr uint32_t EC_FILE_SYSTEM = 3;
constexpr uint32_t EC_PROFILING   = 4;
constexpr uint32_t EC_NETWORK     = 5;

/* Filesystem operations with sub-operations */
constexpr uint16_t FS_QueryInformationFile   = 25;
constexpr uint16_t FS_SetInformationFile     = 26;
constexpr uint16_t FS_QueryVolumeInformation = 30;
constexpr uint16_t FS_SetVolumeInformation   = 31;
constexpr uint16_t FS_DirectoryControl       = 32;
constexpr uint16_t FS_LockUnlockFile         = 37;
constexpr uint16_t FS_PlugAndPlay            = 47;

constexpr int MAX_THREADS = 64;
constexpr int MIN_EVENTS_PER_THREAD = 200000;

/* Rule types for tree mode */
constexpr int RT_HEADER_CMP     = 0;
constexpr int RT_PROCESS_MASK   = 1;
constexpr int RT_OP_REGEX       = 2;
constexpr int RT_RESULT_REGEX   = 3;
constexpr int RT_PATH_REGEX     = 4;
constexpr int RT_ALWAYS_TRUE    = 5;
constexpr int RT_CATEGORY_REGEX = 6;
constexpr int RT_DETAIL_REGEX   = 7;

/* Tree node types */
constexpr int NT_AND  = 0;
constexpr int NT_OR   = 1;
constexpr int NT_LEAF = 2;
constexpr int NT_NOT  = 3;

/* Field flag bits for read_events_batch */
constexpr int BATCH_PATH       = 0x01;
constexpr int BATCH_DETAIL     = 0x02;
constexpr int BATCH_CATEGORY   = 0x04;
constexpr int BATCH_STACKTRACE = 0x08;


/* ================================================================
 * Inline helpers
 * ================================================================ */

inline bool fs_has_sub_op(uint16_t op) {
    return op == FS_QueryInformationFile || op == FS_SetInformationFile ||
           op == FS_QueryVolumeInformation || op == FS_SetVolumeInformation ||
           op == FS_DirectoryControl || op == FS_LockUnlockFile ||
           op == FS_PlugAndPlay;
}


/* ================================================================
 * Core types
 * ================================================================ */

/* Shared scan context (read-only across threads) */
struct ScanContext {
    const uint8_t   *buf;
    int64_t          buf_len;
    const int64_t   *offsets;
    const uint8_t   *proc_mask;
    int64_t          proc_mask_len;
    const std::unordered_map<uint32_t, std::string> *op_lut;
    const std::unordered_map<uint32_t, std::string> *sub_op_lut;
    const std::unordered_map<uint32_t, std::string> *err_lut;
    const std::unordered_map<uint32_t, std::string> *category_lut;
    int pvoid_size;
    int tz_offset_seconds;
};

/* Filter tree rule */
struct TreeRule {
    int type;
    int field_offset;
    int field_size;
    int op_id;
    uint64_t int_value;
    std::regex regex;
    bool has_regex;
    bool is_substr;              /* plain substring → use ci_contains() */
    std::string plain_substr;    /* the literal substring (original case) */
    std::vector<uint8_t> proc_mask_data;

    TreeRule() : type(RT_ALWAYS_TRUE), field_offset(0), field_size(0),
                 op_id(0), int_value(0), has_regex(false), is_substr(false) {}
};

/* Filter tree node */
struct TreeNode {
    int type;
    int rule_idx;
    std::vector<int> children;
};

/* Per-event lazy-evaluated data (mutable for caching within const evaluation) */
struct EventData {
    int64_t event_index;
    const uint8_t *evt;
    int64_t event_offset;
    uint32_t proc_idx;
    uint32_t event_class;
    uint16_t operation;
    uint32_t result_code;
    uint16_t stacktrace_depth;
    uint32_t details_size;
    uint32_t tid;
    mutable bool op_name_resolved;
    mutable std::string op_name;
    mutable bool result_name_resolved;
    mutable std::string result_name;
    mutable bool path_resolved;
    mutable std::string path;
    mutable bool category_resolved;
    mutable std::string category;
    mutable bool detail_resolved;
    mutable std::string detail_json;
};

/* Worker result for multi-threaded filtering */
struct WorkerResult {
    int64_t lo;
    int64_t hi;
    std::vector<int64_t> results;
};


/* ================================================================
 * Public API — Filter engine
 * ================================================================ */

/* Run filter tree evaluation on a range of events (single thread). */
void worker_tree(
    const ScanContext &ctx,
    const std::vector<TreeNode> &nodes,
    const std::vector<TreeRule> &rules,
    int root_idx,
    WorkerResult &wr);

/* Determine optimal thread count for a given range size. */
int compute_thread_count(int64_t range_size, int requested);


/* ================================================================
 * Public API — Path extraction
 * ================================================================ */

/* Extract the path string from a PML event's detail section. */
std::string extract_path(
    const uint8_t *buf, int64_t buf_len,
    int64_t event_offset, uint32_t event_class, uint16_t operation,
    uint16_t stacktrace_depth, uint32_t details_size, int pvoid_size);

/* Extract network path with hostname/port resolution for display. */
std::string extract_network_path_resolved(
    const uint8_t *detail, int detail_size,
    const std::unordered_map<std::string, std::string> *hostname_lut,
    const std::unordered_map<uint32_t, std::string> *port_lut);


/* ================================================================
 * Public API — Detail extraction
 * ================================================================ */

/* Extract event detail as a JSON string. */
std::string extract_detail_json(
    const uint8_t *buf, int64_t buf_len,
    int64_t event_offset,
    uint32_t event_class, uint16_t operation, uint32_t tid,
    uint16_t stacktrace_depth, uint32_t details_size,
    int pvoid_size, int tz_offset_seconds);


/* ================================================================
 * Public API — Name resolution
 * ================================================================ */

/* Resolve category string, with detail-based refinement. */
std::string resolve_category_detailed(
    const ScanContext &ctx,
    const uint8_t *buf, int64_t buf_len,
    int64_t event_offset,
    uint32_t event_class, uint16_t operation,
    uint16_t stacktrace_depth, uint32_t details_size,
    uint32_t extra_details_offset);
