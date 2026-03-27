/*
 * procmon_reader.h — High-level ProcmonReader C++ class.
 *
 * Wraps PmlReader + filter engine. Callers pass raw strings;
 * preprocessing and output formatting are handled internally.
 */

#pragma once

#include "pml_reader.h"
#include "pml_filter_core.h"
#include "pml_preprocess.h"

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>


/* ================================================================
 * Intermediate filter tree (string-based, from Python)
 * ================================================================ */
struct RawFilterNode {
    enum Type { AND, OR, NOT, LEAF };
    Type type;
    std::vector<RawFilterNode> children;  /* AND / OR / NOT */
    /* LEAF data */
    std::string field_name;
    std::string op;
    std::string value_str;
    /* For numeric values passed directly (not as string) */
    double value_num = 0.0;
    bool value_is_num = false;
    bool value_is_bool = false;
    bool value_bool = false;
};


/* ================================================================
 * Output value: string | int64 | bool | list<uint64>
 * ================================================================ */
using OutputValue = std::variant<
    std::string,              /* most formatted fields */
    int64_t,                  /* pid, tid, session, event_index */
    bool,                     /* virtualized, is_64_bit */
    std::vector<uint64_t>     /* stacktrace */
>;

/* A single event's output fields */
using EventOutput = std::vector<std::pair<std::string, OutputValue>>;


class ProcmonReader {
public:
    explicit ProcmonReader(const std::string &file_path);

    ~ProcmonReader() = default;

    ProcmonReader(const ProcmonReader &) = delete;
    ProcmonReader &operator=(const ProcmonReader &) = delete;

    void close();

    /* --- System details (from header) --- */
    std::unordered_map<std::string, std::string> system_details() const;

    /* --- PML file overview --- */
    uint32_t event_count() const;
    uint32_t process_count() const;
    bool is_64bit() const;
    int pvoid_size() const;

    /* --- Process table access --- */
    const std::unordered_map<uint32_t, PmlProcessInfo> &process_table() const;

    /* --- filter_events (all_cpp.md API) ---
     * Accepts a string-based filter tree. Internally does:
     *   field name normalization, value conversion, exact regex detection,
     *   process mask building, timestamp range narrowing,
     *   multi-threaded tree evaluation.
     * Returns matched event indices.
     */
    std::vector<int64_t> filter_events(
        const RawFilterNode *filter_tree,
        int tz_offset_seconds,
        int num_threads = 0) const;

    /* --- read_events_batch (all_cpp.md API) ---
     * Accepts event indices and string field names.
     * Returns fully formatted output values.
     */
    std::vector<EventOutput> read_events_batch(
        const std::vector<int64_t> &indices,
        const std::vector<std::string> &select_fields,
        int tz_offset_seconds) const;

private:
    /* --- Internal: old-style filter dispatch --- */
    std::vector<int64_t> run_filter(
        const std::vector<TreeRule> &rules,
        const std::vector<TreeNode> &nodes,
        int root_index,
        int64_t lo, int64_t hi,
        int num_threads,
        int tz_offset_seconds) const;

    /* --- Internal: timestamp binary search --- */
    uint64_t get_event_timestamp(int64_t index) const;
    int64_t bisect_ge_timestamp(int64_t lo, int64_t hi, uint64_t threshold) const;
    int64_t bisect_gt_timestamp(int64_t lo, int64_t hi, uint64_t threshold) const;

    /* --- Internal: process mask building --- */
    std::vector<uint8_t> build_process_mask(int field_id, int op_id,
        const std::string &str_value, int64_t int_value, bool is_regex) const;

    /* --- Internal: tree conversion --- */
    struct PreprocessedLeaf {
        int field_id;
        int op_id;
        int64_t int_value;             /* scalar value for OP_NE / OP_LE / OP_GE comparisons */

        /* Exact-match integer codes (single ^A$ or multi ^A$|^B$|^C$).
         * Each name is reverse-looked-up to its integer code and stored here.
         * At eval time the header field is compared against these directly,
         * bypassing string resolution and regex_search. */
        std::vector<int64_t> int_values;

        /* Parallel to int_values: the event_class each code belongs to.
         * Prevents cross-class false matches (e.g. RegQueryValue op=5 vs
         * Load Image op=5).  Only consulted when check_event_class is true. */
        std::vector<uint32_t> ec_values;

        /* Whether ec_values should be tested during evaluation.
         * true for operation exact matches, false for result and others. */
        bool check_event_class;

        std::string str_value;
        std::regex regex;
        bool has_regex;
    };

    void convert_tree(
        const RawFilterNode &node,
        int tz_offset_seconds,
        std::vector<TreeRule> &rules_out,
        std::vector<TreeNode> &nodes_out,
        std::vector<PreprocessedLeaf> &leaves) const;

    int convert_tree_recursive(
        const RawFilterNode &node,
        int tz_offset_seconds,
        std::vector<TreeRule> &rules_out,
        std::vector<TreeNode> &nodes_out,
        std::vector<PreprocessedLeaf> &leaves) const;

    void preprocess_leaf(
        const RawFilterNode &node,
        int tz_offset_seconds,
        PreprocessedLeaf &leaf) const;

    /* Reverse lookup maps (built once, cached) */
    mutable bool reverse_maps_built_ = false;
    mutable std::unordered_map<std::string, std::pair<uint32_t, uint32_t>> op_name_to_value_;
    mutable std::unordered_map<std::string, uint32_t> result_name_to_code_;
    void ensure_reverse_maps() const;

    std::unique_ptr<PmlReader> reader_;
    std::unordered_map<uint32_t, std::string> op_lut_;
    std::unordered_map<uint32_t, std::string> sub_op_lut_;
    std::unordered_map<uint32_t, std::string> err_lut_;
    std::unordered_map<uint32_t, std::string> cat_lut_;
};
