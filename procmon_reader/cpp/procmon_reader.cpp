/*
 * procmon_reader.cpp — ProcmonReader implementation.
 */

#include "procmon_reader.h"
#include "pml_consts.h"
#include "pml_format.h"
#include "pml_preprocess.h"

#include <algorithm>
#include <cstdio>
#include <thread>


/* ================================================================
 * Construction / destruction
 * ================================================================ */

ProcmonReader::ProcmonReader(const std::string &file_path)
    : op_lut_(build_operation_lut()),
      sub_op_lut_(build_sub_operation_lut()),
      err_lut_(build_error_lut()),
      cat_lut_(build_category_lut())
{
    reader_ = std::make_unique<PmlReader>(file_path);
}

void ProcmonReader::close() {
    if (reader_) {
        reader_->close();
        reader_.reset();
    }
}


/* ================================================================
 * System details
 * ================================================================ */

std::unordered_map<std::string, std::string>
ProcmonReader::system_details() const {
    if (!reader_) return {};
    const PmlHeader &h = reader_->header();

    /* OS name */
    std::string os_name;
    if (h.windows_major_number == 6 && h.windows_minor_number == 0)
        os_name = "Windows Vista";
    else if (h.windows_major_number == 6 && h.windows_minor_number == 1)
        os_name = "Windows 7";
    else if (h.windows_major_number == 6 && h.windows_minor_number == 2)
        os_name = "Windows 8";
    else if (h.windows_major_number == 6 && h.windows_minor_number == 3)
        os_name = "Windows 8.1";
    else if (h.windows_major_number == 10 && h.windows_minor_number == 0) {
        os_name = (h.windows_build_number >= 22000) ? "Windows 11" : "Windows 10";
    } else {
        os_name = "Windows " + std::to_string(h.windows_major_number) +
                  "." + std::to_string(h.windows_minor_number);
    }

    if (!h.service_pack_name.empty())
        os_name += ", " + h.service_pack_name;

    os_name += " (build " + std::to_string(h.windows_build_number) +
               "." + std::to_string(h.windows_build_number_after_decimal) + ")";

    /* RAM */
    double gb = static_cast<double>(h.ram_memory_size) / (1024.0 * 1024.0 * 1024.0);
    /* Truncate to 2 decimal places (match Python: // 0.01 / 100) */
    gb = static_cast<double>(static_cast<int64_t>(gb * 100)) / 100.0;
    char ram_buf[32];
    std::snprintf(ram_buf, sizeof(ram_buf), "%.2g GB", gb);
    /* Remove trailing zeros after decimal for exact Python match */
    std::string ram_str = ram_buf;

    return {
        {"Computer Name", h.computer_name},
        {"Operating System", os_name},
        {"System Root", h.system_root},
        {"Logical Processors", std::to_string(h.number_of_logical_processors)},
        {"Memory (RAM)", ram_str},
        {"System Type", h.is_64bit ? "64-bit" : "32-bit"},
    };
}


/* ================================================================
 * PML overview
 * ================================================================ */

uint32_t ProcmonReader::event_count() const {
    return reader_ ? reader_->event_count() : 0;
}

uint32_t ProcmonReader::process_count() const {
    return reader_ ? static_cast<uint32_t>(reader_->process_table().size()) : 0;
}

bool ProcmonReader::is_64bit() const {
    return reader_ && reader_->is_64bit();
}

int ProcmonReader::pvoid_size() const {
    return reader_ ? reader_->pvoid_size() : 0;
}


/* ================================================================
 * Process table
 * ================================================================ */

const std::unordered_map<uint32_t, PmlProcessInfo> &
ProcmonReader::process_table() const {
    static const std::unordered_map<uint32_t, PmlProcessInfo> empty;
    return reader_ ? reader_->process_table() : empty;
}


/* ================================================================
 * Event timestamp access
 * ================================================================ */

uint64_t ProcmonReader::get_event_timestamp(int64_t index) const {
    if (!reader_ || index < 0 || index >= static_cast<int64_t>(reader_->event_count()))
        return 0;
    int64_t off = reader_->event_offsets()[static_cast<size_t>(index)];
    if (off < 0 || off + EVT_HEADER_SIZE > reader_->mmap_size())
        return 0;
    return rd_u64(reader_->mmap_data() + off + EVT_DATE_FILETIME);
}

int64_t ProcmonReader::bisect_ge_timestamp(
    int64_t lo, int64_t hi, uint64_t threshold) const
{
    if (!reader_) return lo;
    const auto &offsets = reader_->event_offsets();
    const uint8_t *buf = reader_->mmap_data();
    const int64_t buf_len = reader_->mmap_size();

    while (lo < hi) {
        int64_t mid = lo + (hi - lo) / 2;
        int64_t off = offsets[static_cast<size_t>(mid)];
        if (off < 0 || off + EVT_HEADER_SIZE > buf_len) { lo = mid + 1; continue; }
        uint64_t ts = rd_u64(buf + off + EVT_DATE_FILETIME);
        if (ts < threshold)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

int64_t ProcmonReader::bisect_gt_timestamp(
    int64_t lo, int64_t hi, uint64_t threshold) const
{
    if (!reader_) return lo;
    const auto &offsets = reader_->event_offsets();
    const uint8_t *buf = reader_->mmap_data();
    const int64_t buf_len = reader_->mmap_size();

    while (lo < hi) {
        int64_t mid = lo + (hi - lo) / 2;
        int64_t off = offsets[static_cast<size_t>(mid)];
        if (off < 0 || off + EVT_HEADER_SIZE > buf_len) { lo = mid + 1; continue; }
        uint64_t ts = rd_u64(buf + off + EVT_DATE_FILETIME);
        if (ts <= threshold)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}


/* ================================================================
 * Internal: run filter (multi-threaded tree evaluation)
 * ================================================================ */

std::vector<int64_t> ProcmonReader::run_filter(
    const std::vector<TreeRule> &rules,
    const std::vector<TreeNode> &nodes,
    int root_index,
    int64_t lo, int64_t hi,
    int num_threads,
    int tz_offset_seconds) const
{
    if (!reader_) return {};

    lo = std::max<int64_t>(lo, 0);
    hi = std::min<int64_t>(hi, static_cast<int64_t>(reader_->event_count()));
    if (lo >= hi) return {};

    /* No rules → return all in range */
    if (rules.empty()) {
        std::vector<int64_t> result;
        result.reserve(static_cast<size_t>(hi - lo));
        for (int64_t i = lo; i < hi; i++)
            result.push_back(i);
        return result;
    }

    /* Build scan context */
    ScanContext ctx;
    ctx.buf = reader_->mmap_data();
    ctx.buf_len = reader_->mmap_size();
    ctx.offsets = reader_->event_offsets_data();
    ctx.proc_mask = nullptr;
    ctx.proc_mask_len = 0;
    ctx.op_lut = &op_lut_;
    ctx.sub_op_lut = &sub_op_lut_;
    ctx.err_lut = &err_lut_;
    ctx.category_lut = &cat_lut_;
    ctx.pvoid_size = reader_->pvoid_size();
    ctx.tz_offset_seconds = tz_offset_seconds;

    int64_t range_size = hi - lo;
    int n_threads = compute_thread_count(range_size, num_threads);

    std::vector<WorkerResult> workers(static_cast<size_t>(n_threads));
    int64_t chunk_sz = range_size / n_threads;

    for (int t = 0; t < n_threads; t++) {
        workers[t].lo = lo + static_cast<int64_t>(t) * chunk_sz;
        workers[t].hi = (t == n_threads - 1) ? hi
                        : lo + static_cast<int64_t>(t + 1) * chunk_sz;
    }

    /* Run workers */
    if (n_threads == 1) {
        worker_tree(ctx, nodes, rules, root_index, workers[0]);
    } else {
        std::vector<std::thread> threads;
        threads.reserve(static_cast<size_t>(n_threads));
        for (int t = 0; t < n_threads; t++)
            threads.emplace_back(worker_tree, std::cref(ctx),
                std::cref(nodes), std::cref(rules),
                root_index, std::ref(workers[t]));
        for (auto &th : threads) th.join();
    }

    /* Collect results */
    std::vector<int64_t> result;
    for (int t = 0; t < n_threads; t++)
        for (int64_t idx : workers[t].results)
            result.push_back(idx);

    return result;
}


/* ================================================================
 * Reverse lookup maps (lazy-built)
 * ================================================================ */

void ProcmonReader::ensure_reverse_maps() const {
    if (reverse_maps_built_) return;
    op_name_to_value_ = pml_pre::build_op_name_to_value(op_lut_);
    result_name_to_code_ = pml_pre::build_result_name_to_code(err_lut_);
    reverse_maps_built_ = true;
}


/* ================================================================
 * Internal: process mask building
 * ================================================================ */

static bool is_process_str_field(int fid) {
    using namespace pml_pre;
    return fid == FID_PROCESS_NAME || fid == FID_IMAGE_PATH ||
           fid == FID_COMMAND_LINE || fid == FID_USER ||
           fid == FID_COMPANY || fid == FID_VERSION ||
           fid == FID_DESCRIPTION || fid == FID_INTEGRITY;
}

static std::string get_proc_str(const PmlProcessInfo &pi, int fid) {
    using namespace pml_pre;
    switch (fid) {
        case FID_PROCESS_NAME:  return pi.process_name;
        case FID_IMAGE_PATH:    return pi.image_path;
        case FID_COMMAND_LINE:  return pi.command_line;
        case FID_USER:          return pi.user;
        case FID_COMPANY:       return pi.company;
        case FID_VERSION:       return pi.version;
        case FID_DESCRIPTION:   return pi.description;
        case FID_INTEGRITY:     return pi.integrity;
        default:                return {};
    }
}

static int64_t get_proc_int(const PmlProcessInfo &pi, int fid) {
    using namespace pml_pre;
    switch (fid) {
        case FID_PID:               return pi.process_id;
        case FID_PARENT_PID:        return pi.parent_process_id;
        case FID_SESSION:           return pi.session_number;
        case FID_AUTHENTICATION_ID: return static_cast<int64_t>(pi.authentication_id);
        case FID_VIRTUALIZED:       return pi.is_virtualized;
        case FID_IS_64_BIT:         return pi.is_64bit ? 1 : 0;
        default:                    return 0;
    }
}

std::vector<uint8_t> ProcmonReader::build_process_mask(
    int field_id, int op_id, const std::string &str_value,
    int64_t int_value, bool is_regex) const
{
    const auto &table = process_table();
    if (table.empty()) return {};

    uint32_t max_idx = 0;
    for (auto &[idx, _] : table)
        if (idx > max_idx) max_idx = idx;

    std::vector<uint8_t> mask(max_idx + 1, 0);

    std::regex re;
    if (is_regex)
        re = std::regex(str_value, std::regex::ECMAScript | std::regex::icase);

    for (auto &[idx, pi] : table) {
        bool match = false;

        if (is_regex) {
            std::string sv = get_proc_str(pi, field_id);
            if (sv.empty() && !is_process_str_field(field_id))
                sv = std::to_string(get_proc_int(pi, field_id));
            match = std::regex_search(sv, re);
        } else if (is_process_str_field(field_id)) {
            std::string sv = get_proc_str(pi, field_id);
            switch (op_id) {
                case OP_EQ: match = (sv == str_value); break;
                case OP_NE: match = (sv != str_value); break;
                default: break;
            }
        } else {
            int64_t iv = get_proc_int(pi, field_id);
            switch (op_id) {
                case OP_EQ: match = (iv == int_value); break;
                case OP_NE: match = (iv != int_value); break;
                case OP_LE: match = (iv <= int_value); break;
                case OP_GE: match = (iv >= int_value); break;
                default: break;
            }
        }

        if (match) mask[idx] = 1;
    }
    return mask;
}


/* ================================================================
 * Internal: preprocess a single leaf rule
 * ================================================================ */

void ProcmonReader::preprocess_leaf(
    const RawFilterNode &node,
    int tz_offset_seconds,
    PreprocessedLeaf &leaf) const
{
    using namespace pml_pre;
    ensure_reverse_maps();

    std::string canonical = normalize_field_name(node.field_name);
    if (canonical.empty())
        throw std::invalid_argument("Unknown field: '" + node.field_name + "'");

    const FieldMeta *meta = get_field_meta(canonical);
    if (!meta)
        throw std::invalid_argument("Unknown field: '" + node.field_name + "'");
    if (!meta->filterable)
        throw std::invalid_argument("Field '" + node.field_name + "' is not filterable");

    int op_id = parse_operator(node.op);
    if (op_id < 0)
        throw std::invalid_argument("Unknown operator: '" + node.op + "'");

    /* Validate operator for field */
    bool is_comp = (op_id == OP_ID_EQ || op_id == OP_ID_NE ||
                    op_id == OP_ID_LE || op_id == OP_ID_GE);
    bool is_re   = (op_id == OP_ID_REGEX);
    if (is_comp && !meta->allows_comparison)
        throw std::invalid_argument("Operator '" + node.op + "' not supported for '" + node.field_name + "'");
    if (is_re && !meta->allows_regex)
        throw std::invalid_argument("Operator '" + node.op + "' not supported for '" + node.field_name + "'");

    leaf.field_id = meta->field_id;
    leaf.op_id = op_id;
    leaf.has_regex = false;
    leaf.int_value = 0;
    leaf.check_event_class = false;

    /* Get the string value */
    std::string val_str = node.value_str;
    if (node.value_is_num && val_str.empty())
        val_str = std::to_string(static_cast<int64_t>(node.value_num));

    /* Convert based on field type */
    if (canonical == "event_class") {
        int v = convert_event_class(val_str);
        if (v < 0)
            throw std::invalid_argument("Unknown event_class: '" + val_str + "'");
        leaf.int_value = v;

    } else if (canonical == "operation") {
        /* Check for exact regex match: ^Name$ */
        auto exact = is_exact_regex(val_str);
        if (exact) {
            std::string key = to_upper(*exact);
            auto it = op_name_to_value_.find(key);
            if (it == op_name_to_value_.end()) {
                std::string alt = key;
                std::replace(alt.begin(), alt.end(), ' ', '_');
                it = op_name_to_value_.find(alt);
            }
            if (it != op_name_to_value_.end()) {
                leaf.field_id = FID_OPERATION_EXACT;
                leaf.op_id = OP_ID_EQ;
                leaf.int_values = { static_cast<int64_t>(it->second.second) };
                leaf.ec_values  = { it->second.first };
                leaf.check_event_class = true;
                return;
            }
        }
        /* Check for multi-exact: ^A$|^B$|^C$ */
        auto mexact = is_multi_exact_regex(val_str);
        if (mexact) {
            std::vector<int64_t> codes;
            std::vector<uint32_t> ecs;
            bool all_found = true;
            for (auto &name : *mexact) {
                std::string key = to_upper(name);
                auto it = op_name_to_value_.find(key);
                if (it == op_name_to_value_.end()) {
                    std::string alt = key;
                    std::replace(alt.begin(), alt.end(), ' ', '_');
                    it = op_name_to_value_.find(alt);
                }
                if (it != op_name_to_value_.end()) {
                    codes.push_back(it->second.second);
                    ecs.push_back(it->second.first);
                } else {
                    all_found = false;
                    break;
                }
            }
            if (all_found && !codes.empty()) {
                leaf.field_id = FID_OPERATION_EXACT;
                leaf.op_id = OP_ID_EQ;
                leaf.int_values = std::move(codes);
                leaf.ec_values = std::move(ecs);
                leaf.check_event_class = true;
                return;
            }
        }
        /* General regex */
        leaf.field_id = FID_OPERATION_REGEX;
        leaf.str_value = val_str;
        leaf.regex = std::regex(val_str, std::regex::ECMAScript | std::regex::icase);
        leaf.has_regex = true;

    } else if (canonical == "result") {
        auto exact = is_exact_regex(val_str);
        if (exact) {
            std::string key = to_upper(*exact);
            auto it = result_name_to_code_.find(key);
            if (it != result_name_to_code_.end()) {
                leaf.field_id = FID_RESULT_EXACT;
                leaf.op_id = OP_ID_EQ;
                leaf.int_values = { static_cast<int64_t>(it->second) };
                return;
            }
        }
        /* Check for multi-exact: ^A$|^B$|^C$ */
        auto mexact = is_multi_exact_regex(val_str);
        if (mexact) {
            std::vector<int64_t> codes;
            bool all_found = true;
            for (auto &name : *mexact) {
                std::string key = to_upper(name);
                auto it = result_name_to_code_.find(key);
                if (it != result_name_to_code_.end()) {
                    codes.push_back(it->second);
                } else {
                    all_found = false;
                    break;
                }
            }
            if (all_found && !codes.empty()) {
                leaf.field_id = FID_RESULT_EXACT;
                leaf.op_id = OP_ID_EQ;
                leaf.int_values = std::move(codes);
                return;
            }
        }
        leaf.field_id = FID_RESULT_REGEX;
        leaf.str_value = val_str;
        leaf.regex = std::regex(val_str, std::regex::ECMAScript | std::regex::icase);
        leaf.has_regex = true;

    } else if (canonical == "duration") {
        int64_t ticks;
        if (node.value_is_num)
            ticks = static_cast<int64_t>(node.value_num * pml_fmt::TICKS_PER_SECOND);
        else
            ticks = convert_duration_to_ticks(val_str);
        if (ticks < 0)
            throw std::invalid_argument("Invalid duration: '" + val_str + "'");
        leaf.int_value = ticks;

    } else if (canonical == "timestamp") {
        uint64_t ft = convert_timestamp_to_filetime(val_str, tz_offset_seconds);
        if (ft == 0)
            throw std::invalid_argument("Invalid timestamp: '" + val_str + "'");
        leaf.int_value = static_cast<int64_t>(ft);

    } else if (canonical == "event_index" || canonical == "pid" ||
               canonical == "parent_pid" || canonical == "tid" ||
               canonical == "session") {
        if (node.value_is_num)
            leaf.int_value = static_cast<int64_t>(node.value_num);
        else {
            int64_t v = convert_int(val_str);
            if (v == -1 && val_str != "-1")
                throw std::invalid_argument("Invalid integer for '" + canonical + "': '" + val_str + "'");
            leaf.int_value = v;
        }

    } else if (canonical == "authentication_id") {
        if (node.value_is_num)
            leaf.int_value = static_cast<int64_t>(node.value_num);
        else
            leaf.int_value = convert_authentication_id(val_str);

    } else if (canonical == "virtualized" || canonical == "is_64_bit") {
        if (node.value_is_bool)
            leaf.int_value = node.value_bool ? 1 : 0;
        else if (node.value_is_num)
            leaf.int_value = (node.value_num != 0.0) ? 1 : 0;
        else {
            int bv = convert_bool(val_str);
            if (bv < 0)
                throw std::invalid_argument("Invalid bool for '" + canonical + "': '" + val_str + "'");
            leaf.int_value = bv;
        }

    } else {
        /* String regex fields (process_name, path, category, detail, etc.) */
        leaf.str_value = val_str;
        leaf.regex = std::regex(val_str, std::regex::ECMAScript | std::regex::icase);
        leaf.has_regex = true;
    }
}


/* ================================================================
 * Internal: convert RawFilterNode tree → TreeRule[] + TreeNode[]
 * ================================================================ */

/* Event header field → (offset, size) */
static const std::unordered_map<int, std::pair<int, int>> &header_field_spec() {
    static const std::unordered_map<int, std::pair<int, int>> m = {
        {pml_pre::FID_EVENT_CLASS,      {EVT_EVENT_CLASS,   4}},
        {pml_pre::FID_OPERATION_EXACT,  {EVT_OPERATION,     2}},
        {pml_pre::FID_DURATION,         {EVT_DURATION,      8}},
        {pml_pre::FID_TIMESTAMP,        {EVT_DATE_FILETIME, 8}},
        {pml_pre::FID_RESULT_EXACT,     {EVT_RESULT,        4}},
        {pml_pre::FID_TID,              {EVT_THREAD_ID,     4}},
    };
    return m;
}

int ProcmonReader::convert_tree_recursive(
    const RawFilterNode &node,
    int tz_offset_seconds,
    std::vector<TreeRule> &rules_out,
    std::vector<TreeNode> &nodes_out,
    std::vector<PreprocessedLeaf> &leaves) const
{
    int my_idx = static_cast<int>(nodes_out.size());

    if (node.type == RawFilterNode::LEAF) {
        /* Preprocess the leaf */
        PreprocessedLeaf leaf;
        preprocess_leaf(node, tz_offset_seconds, leaf);
        leaves.push_back(leaf);

        int rule_idx = static_cast<int>(rules_out.size());
        TreeRule rule;
        auto cat = pml_pre::get_field_category(leaf.field_id);

        if (cat == pml_pre::CAT_DIRECT_HEADER && !leaf.has_regex) {
            /* EVENT_INDEX: special — filter by range, not header comparison */
            if (leaf.field_id == pml_pre::FID_EVENT_INDEX) {
                /* Handled by range narrowing; emit ALWAYS_TRUE for the tree */
                rule.type = RT_ALWAYS_TRUE;
            } else {
                auto it = header_field_spec().find(leaf.field_id);
                if (it != header_field_spec().end()) {
                    if (!leaf.int_values.empty()) {
                        rule.type = RT_HEADER_EQ_ANY;
                        rule.field_offset = it->second.first;
                        rule.field_size = it->second.second;
                        for (auto v : leaf.int_values)
                            rule.int_values.push_back(static_cast<uint64_t>(v));
                        rule.ec_values = leaf.ec_values;
                        rule.check_event_class = leaf.check_event_class;
                    } else {
                        rule.type = RT_HEADER_CMP;
                        rule.field_offset = it->second.first;
                        rule.field_size = it->second.second;
                        rule.op_id = leaf.op_id;
                        rule.int_value = static_cast<uint64_t>(leaf.int_value);
                    }
                } else {
                    rule.type = RT_ALWAYS_TRUE;
                }
            }
        } else if (leaf.field_id == pml_pre::FID_OPERATION_REGEX && leaf.has_regex) {
            rule.type = RT_OP_REGEX;
            if (auto ms = pml_pre::is_multi_substring(leaf.str_value)) {
                rule.is_multi_substr = true;
                rule.multi_substrs = std::move(*ms);
            } else {
                rule.regex = leaf.regex;
                rule.has_regex = true;
            }
        } else if (leaf.field_id == pml_pre::FID_RESULT_REGEX && leaf.has_regex) {
            rule.type = RT_RESULT_REGEX;
            if (auto ms = pml_pre::is_multi_substring(leaf.str_value)) {
                rule.is_multi_substr = true;
                rule.multi_substrs = std::move(*ms);
            } else {
                rule.regex = leaf.regex;
                rule.has_regex = true;
            }
        } else if (cat == pml_pre::CAT_PROCESS) {
            /* Build process mask */
            auto mask = build_process_mask(
                leaf.field_id, leaf.op_id,
                leaf.str_value, leaf.int_value, leaf.has_regex);
            rule.type = RT_PROCESS_MASK;
            rule.proc_mask_data = std::move(mask);
        } else if (leaf.field_id == pml_pre::FID_PATH && leaf.has_regex) {
            rule.type = RT_PATH_REGEX;
            if (auto ms = pml_pre::is_multi_substring(leaf.str_value)) {
                rule.is_multi_substr = true;
                rule.multi_substrs = std::move(*ms);
            } else {
                rule.regex = leaf.regex;
                rule.has_regex = true;
            }
        } else if (leaf.field_id == pml_pre::FID_CATEGORY && leaf.has_regex) {
            rule.type = RT_CATEGORY_REGEX;
            if (auto ms = pml_pre::is_multi_substring(leaf.str_value)) {
                rule.is_multi_substr = true;
                rule.multi_substrs = std::move(*ms);
            } else {
                rule.regex = leaf.regex;
                rule.has_regex = true;
            }
        } else if (leaf.field_id == pml_pre::FID_DETAIL && leaf.has_regex) {
            rule.type = RT_DETAIL_REGEX;
            if (auto ms = pml_pre::is_multi_substring(leaf.str_value)) {
                rule.is_multi_substr = true;
                rule.multi_substrs = std::move(*ms);
            } else {
                rule.regex = leaf.regex;
                rule.has_regex = true;
            }
        } else {
            rule.type = RT_ALWAYS_TRUE;
        }

        rules_out.push_back(std::move(rule));

        TreeNode tn;
        tn.type = NT_LEAF;
        tn.rule_idx = rule_idx;
        nodes_out.push_back(tn);
        return my_idx;

    } else if (node.type == RawFilterNode::NOT) {
        nodes_out.push_back(TreeNode{});  /* placeholder */
        int child_idx = convert_tree_recursive(
            node.children[0], tz_offset_seconds, rules_out, nodes_out, leaves);
        nodes_out[my_idx].type = NT_NOT;
        nodes_out[my_idx].children = {child_idx};
        return my_idx;

    } else {
        /* AND or OR */
        nodes_out.push_back(TreeNode{});  /* placeholder */
        std::vector<int> child_indices;
        for (auto &child : node.children) {
            int ci = convert_tree_recursive(
                child, tz_offset_seconds, rules_out, nodes_out, leaves);
            child_indices.push_back(ci);
        }
        nodes_out[my_idx].type = (node.type == RawFilterNode::AND) ? NT_AND : NT_OR;
        nodes_out[my_idx].children = std::move(child_indices);
        return my_idx;
    }
}


/* ================================================================
 * filter_events — high-level API (all_cpp.md)
 * ================================================================ */

std::vector<int64_t> ProcmonReader::filter_events(
    const RawFilterNode *filter_tree,
    int tz_offset_seconds,
    int num_threads) const
{
    if (!reader_) return {};

    int64_t lo = 0;
    int64_t hi = static_cast<int64_t>(reader_->event_count());
    if (lo >= hi) return {};

    /* No filter → return all */
    if (!filter_tree) {
        std::vector<int64_t> all(static_cast<size_t>(hi));
        for (int64_t i = 0; i < hi; i++) all[i] = i;
        return all;
    }

    /* Convert tree and preprocess all leaf rules */
    std::vector<TreeRule> rules;
    std::vector<TreeNode> nodes;
    std::vector<PreprocessedLeaf> leaves;
    int root = convert_tree_recursive(
        *filter_tree, tz_offset_seconds, rules, nodes, leaves);

    /* Range narrowing: timestamp binary search */
    for (auto &lf : leaves) {
        if (lf.field_id == pml_pre::FID_TIMESTAMP) {
            uint64_t val = static_cast<uint64_t>(lf.int_value);
            if (lf.op_id == pml_pre::OP_ID_EQ) {
                lo = bisect_ge_timestamp(lo, hi, val);
                hi = bisect_gt_timestamp(lo, hi, val);
            } else if (lf.op_id == pml_pre::OP_ID_GE) {
                lo = bisect_ge_timestamp(lo, hi, val);
            } else if (lf.op_id == pml_pre::OP_ID_LE) {
                hi = bisect_gt_timestamp(lo, hi, val);
            }
        } else if (lf.field_id == pml_pre::FID_EVENT_INDEX) {
            if (lf.op_id == pml_pre::OP_ID_EQ) {
                lo = std::max(lo, lf.int_value);
                hi = std::min(hi, lf.int_value + 1);
            } else if (lf.op_id == pml_pre::OP_ID_GE) {
                lo = std::max(lo, lf.int_value);
            } else if (lf.op_id == pml_pre::OP_ID_LE) {
                hi = std::min(hi, lf.int_value + 1);
            }
        }
    }

    if (lo >= hi) return {};

    return run_filter(rules, nodes, root, lo, hi, num_threads, tz_offset_seconds);
}


/* ================================================================
 * read_events_batch — high-level API (all_cpp.md)
 * ================================================================ */

std::vector<EventOutput> ProcmonReader::read_events_batch(
    const std::vector<int64_t> &indices,
    const std::vector<std::string> &select_fields,
    int tz_offset_seconds) const
{
    if (!reader_ || indices.empty())
        return {};

    /* Parse field names → (canonical_name, field_id) list */
    struct FieldSpec {
        std::string name;
        int field_id;
        pml_pre::FieldCategory category;
    };
    std::vector<FieldSpec> fields;

    for (auto &sf : select_fields) {
        std::string canonical = pml_pre::normalize_field_name(sf);
        if (canonical.empty())
            throw std::invalid_argument("Unknown field: '" + sf + "'");
        const pml_pre::FieldMeta *meta = pml_pre::get_field_meta(canonical);
        if (!meta) continue;

        FieldSpec fs;
        fs.name = canonical;
        fs.field_id = meta->field_id;
        fs.category = pml_pre::get_field_category(meta->field_id);
        fields.push_back(fs);
    }

    /* Prepare context */
    const auto &rd = *reader_;
    const uint8_t *c_buf = rd.mmap_data();
    int64_t c_buf_len = rd.mmap_size();
    const auto &offsets = rd.event_offsets();
    int64_t n_total = static_cast<int64_t>(offsets.size());
    int pvsz = rd.pvoid_size();
    const auto &hostname_lut = rd.hostnames();
    const auto &port_lut = rd.ports();
    const auto &proc_table = rd.process_table();

    ScanContext ctx;
    ctx.buf = c_buf; ctx.buf_len = c_buf_len;
    ctx.offsets = offsets.data();
    ctx.proc_mask = nullptr; ctx.proc_mask_len = 0;
    ctx.op_lut = &op_lut_; ctx.sub_op_lut = &sub_op_lut_;
    ctx.err_lut = &err_lut_; ctx.category_lut = &cat_lut_;
    ctx.pvoid_size = pvsz;
    ctx.tz_offset_seconds = tz_offset_seconds;

    std::vector<EventOutput> results;
    results.reserve(indices.size());

    for (int64_t event_index : indices) {
        if (event_index < 0 || event_index >= n_total)
            throw std::out_of_range(
                "event index " + std::to_string(event_index) +
                " out of range [0, " + std::to_string(n_total) + ")");

        int64_t off = offsets[static_cast<size_t>(event_index)];
        if (off < 0 || off + EVT_HEADER_SIZE > c_buf_len)
            throw std::runtime_error(
                "event " + std::to_string(event_index) + " has invalid offset");

        const uint8_t *evt = c_buf + off;

        /* Read raw header fields */
        uint32_t process_index    = rd_u32(evt + EVT_PROCESS_INDEX);
        uint32_t tid              = rd_u32(evt + EVT_THREAD_ID);
        uint32_t event_class      = rd_u32(evt + EVT_EVENT_CLASS);
        uint16_t operation        = rd_u16(evt + EVT_OPERATION);
        uint64_t duration         = rd_u64(evt + EVT_DURATION);
        uint64_t date_filetime    = rd_u64(evt + EVT_DATE_FILETIME);
        uint32_t result_code      = rd_u32(evt + EVT_RESULT);
        uint16_t stacktrace_depth = rd_u16(evt + EVT_STACKTRACE_DEPTH);
        uint32_t details_size     = rd_u32(evt + EVT_DETAILS_SIZE);
        uint32_t extra_det_off    = rd_u32(evt + EVT_EXTRA_DETAILS_OFFSET);

        /* Sub-operation (filesystem events) */
        int sub_operation = -1;
        if (event_class == EC_FILE_SYSTEM && details_size > 0) {
            int64_t detail_off = off + EVT_HEADER_SIZE +
                                 static_cast<int64_t>(stacktrace_depth) * pvsz;
            if (detail_off >= 0 && detail_off < c_buf_len)
                sub_operation = static_cast<int>(c_buf[detail_off]);
        }

        /* Network protocol */
        std::string net_protocol;
        if (event_class == EC_NETWORK && details_size >= 2) {
            int64_t detail_off = off + EVT_HEADER_SIZE +
                                 static_cast<int64_t>(stacktrace_depth) * pvsz;
            if (detail_off >= 0 && detail_off + 2 <= c_buf_len) {
                uint16_t flags = rd_u16(c_buf + detail_off);
                net_protocol = (flags & 4) ? "TCP" : "UDP";
            }
        }

        /* Lazy-evaluated detail strings */
        std::string path_str, category_str, detail_str;
        bool path_done = false, category_done = false, detail_done = false;

        auto get_path = [&]() -> const std::string & {
            if (!path_done) {
                if (event_class == EC_NETWORK && details_size > 0) {
                    int64_t detail_off = off + EVT_HEADER_SIZE +
                                         static_cast<int64_t>(stacktrace_depth) * pvsz;
                    if (detail_off >= 0 && detail_off + details_size <= c_buf_len)
                        path_str = extract_network_path_resolved(
                            c_buf + detail_off, static_cast<int>(details_size),
                            &hostname_lut, &port_lut);
                } else {
                    path_str = extract_path(c_buf, c_buf_len, off, event_class, operation,
                                            stacktrace_depth, details_size, pvsz);
                }
                path_done = true;
            }
            return path_str;
        };

        auto get_category = [&]() -> const std::string & {
            if (!category_done) {
                category_str = resolve_category_detailed(
                    ctx, c_buf, c_buf_len, off,
                    event_class, operation,
                    stacktrace_depth, details_size, extra_det_off);
                category_done = true;
            }
            return category_str;
        };

        auto get_detail = [&]() -> const std::string & {
            if (!detail_done) {
                std::string json = extract_detail_json(
                    c_buf, c_buf_len, off,
                    event_class, operation, tid,
                    stacktrace_depth, details_size, pvsz, tz_offset_seconds);
                /* Convert JSON to Procmon-style "Key: Value, Key: Value" */
                /* Simple parsing: strip outer {}, split by commas/colons */
                if (json.size() > 2 && json.front() == '{' && json.back() == '}') {
                    detail_str = "";
                    /* Use the JSON string directly — it's already Procmon-formatted
                     * by extract_detail_json in pml_filter_core.cpp
                     * But we need to convert from JSON to display format.
                     * Actually keep as JSON for now since the Python side was
                     * also parsing JSON then formatting. */
                    detail_str = json;
                } else {
                    detail_str = json;
                }
                detail_done = true;
            }
            return detail_str;
        };

        /* Look up process */
        const PmlProcessInfo *proc = nullptr;
        auto pit = proc_table.find(process_index);
        if (pit != proc_table.end())
            proc = &pit->second;

        /* Build output record */
        EventOutput record;
        record.reserve(fields.size() + 1);
        /* event_index is always included */
        record.emplace_back("event_index", static_cast<int64_t>(event_index));

        const std::string *net_proto_ptr = net_protocol.empty() ? nullptr : &net_protocol;

        for (auto &fs : fields) {
            OutputValue val;
            switch (fs.field_id) {
                case pml_pre::FID_EVENT_CLASS:
                    val = pml_fmt::format_event_class(event_class);
                    break;
                case pml_pre::FID_OPERATION_EXACT:
                case pml_pre::FID_OPERATION_REGEX:
                    val = pml_fmt::format_operation(
                        event_class, operation, sub_operation,
                        event_class == pml::EC_FS && fs_has_sub_op(operation),
                        net_proto_ptr, op_lut_, sub_op_lut_);
                    break;
                case pml_pre::FID_RESULT_EXACT:
                case pml_pre::FID_RESULT_REGEX:
                    val = pml_fmt::format_result(result_code, err_lut_);
                    break;
                case pml_pre::FID_DURATION:
                    val = pml_fmt::format_duration(duration, result_code, err_lut_);
                    break;
                case pml_pre::FID_TIMESTAMP:
                    val = pml_fmt::format_timestamp(date_filetime, tz_offset_seconds);
                    break;
                case pml_pre::FID_TID:
                    val = static_cast<int64_t>(tid);
                    break;
                case pml_pre::FID_EVENT_INDEX:
                    /* Already added above */
                    continue;
                case pml_pre::FID_PROCESS_INDEX:
                    val = static_cast<int64_t>(process_index);
                    break;
                case pml_pre::FID_PROCESS_NAME:
                    val = proc ? proc->process_name : std::string("");
                    break;
                case pml_pre::FID_PID:
                    val = proc ? static_cast<int64_t>(proc->process_id) : int64_t(0);
                    break;
                case pml_pre::FID_PARENT_PID:
                    val = proc ? static_cast<int64_t>(proc->parent_process_id) : int64_t(0);
                    break;
                case pml_pre::FID_IMAGE_PATH:
                    val = proc ? proc->image_path : std::string("");
                    break;
                case pml_pre::FID_COMMAND_LINE:
                    val = proc ? proc->command_line : std::string("");
                    break;
                case pml_pre::FID_USER:
                    val = proc ? proc->user : std::string("");
                    break;
                case pml_pre::FID_COMPANY:
                    val = proc ? proc->company : std::string("");
                    break;
                case pml_pre::FID_VERSION:
                    val = proc ? proc->version : std::string("");
                    break;
                case pml_pre::FID_DESCRIPTION:
                    val = proc ? proc->description : std::string("");
                    break;
                case pml_pre::FID_INTEGRITY:
                    val = proc ? proc->integrity : std::string("");
                    break;
                case pml_pre::FID_SESSION:
                    val = proc ? static_cast<int64_t>(proc->session_number) : int64_t(0);
                    break;
                case pml_pre::FID_AUTHENTICATION_ID:
                    val = pml_fmt::format_auth_id(proc ? proc->authentication_id : 0);
                    break;
                case pml_pre::FID_VIRTUALIZED:
                    if (proc) {
                        if (proc->is_virtualized == 0) val = false;
                        else if (proc->is_virtualized == 1) val = true;
                        else val = std::string("n/a");
                    } else {
                        val = false;
                    }
                    break;
                case pml_pre::FID_IS_64_BIT:
                    val = proc ? proc->is_64bit : false;
                    break;
                case pml_pre::FID_PATH:
                    val = get_path();
                    break;
                case pml_pre::FID_CATEGORY:
                    val = get_category();
                    break;
                case pml_pre::FID_DETAIL:
                    val = get_detail();
                    break;
                case pml_pre::FID_STACKTRACE: {
                    std::vector<uint64_t> stack;
                    if (stacktrace_depth > 0) {
                        int64_t stack_off = off + EVT_HEADER_SIZE;
                        for (int s = 0; s < stacktrace_depth; s++) {
                            uint64_t addr;
                            if (pvsz == 8)
                                addr = (stack_off + s * 8 + 8 <= c_buf_len)
                                    ? rd_u64(c_buf + stack_off + s * 8) : 0;
                            else
                                addr = (stack_off + s * 4 + 4 <= c_buf_len)
                                    ? rd_u32(c_buf + stack_off + s * 4) : 0;
                            stack.push_back(addr);
                        }
                    }
                    val = std::move(stack);
                    break;
                }
                default:
                    val = std::string("");
                    break;
            }
            record.emplace_back(fs.name, std::move(val));
        }

        results.push_back(std::move(record));
    }
    return results;
}
