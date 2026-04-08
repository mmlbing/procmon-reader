/*
 * pml_filter_core.cpp â€” PML event filter engine implementation.
 *
 * Contains: path extraction, detail JSON dispatch, name resolution,
 * category resolution, and filter tree evaluation.
 *
 * Detail extraction for each event class is in separate modules:
 *   pml_detail_registry.cpp, pml_detail_filesystem.cpp,
 *   pml_detail_process.cpp, pml_detail_network.cpp.
 */

#include "pml_filter_core.h"
#include "pml_detail.h"
#include "pml_detail_common.h"
#include "pml_preprocess.h"

#include <cstdio>
#include <algorithm>
#include <thread>


/* ================================================================
 * Internal: IP address formatting
 * ================================================================ */

static std::string format_ipv4(const uint8_t *raw) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  raw[0], raw[1], raw[2], raw[3]);
    return buf;
}

static std::string format_ipv6(const uint8_t *raw) {
    char buf[48];
    std::snprintf(buf, sizeof(buf),
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        raw[0], raw[1], raw[2], raw[3],
        raw[4], raw[5], raw[6], raw[7],
        raw[8], raw[9], raw[10], raw[11],
        raw[12], raw[13], raw[14], raw[15]);
    return buf;
}


/* ================================================================
 * Internal: Path extraction per event class
 * ================================================================ */

static int registry_skip_bytes(uint16_t operation) {
    switch (operation) {
        case  0: case  1: return 6;   /* RegOpenKey, RegCreateKey: u16+u32 */
        case  3: case  5: return 10;  /* RegQueryKey, RegQueryValue: u16+u32+u32 */
        case  4:          return 14;  /* RegSetValue: u16+u32+u32+u32 */
        case  6: case  7: return 14;  /* RegEnumValue, RegEnumKey: u16+u32+u32+u32 */
        case  8:          return 14;  /* RegSetInfoKey: u16+u32+u32+u16+u16 */
        case 12: case 14: return 2;   /* RegLoadKey, RegRenameKey: u16 */
        case 18: case 19: case 20: return 6; /* Unknown1/3, RegRestorekey */
        default: return 0;
    }
}

static std::string extract_registry_path(
    const uint8_t *detail, int detail_size, uint16_t operation)
{
    if (detail_size < 2) return {};
    uint16_t path_info = rd_u16(detail);
    bool is_ascii = (path_info >> 15) == 1;
    int char_count = path_info & 0x7FFF;
    if (char_count == 0) return {};

    int skip = registry_skip_bytes(operation);
    int path_start = 2 + skip;
    return read_pml_string(detail, path_start, detail_size, is_ascii, char_count);
}

static std::string extract_filesystem_path(
    const uint8_t *detail, int detail_size, uint16_t operation, int pvoid_size)
{
    /* Layout: sub_op(1)+pad(3) + details_io(pvoid*5+0x14) + path_info(2)+pad(2) + path */
    int path_info_offset = 4 + pvoid_size * 5 + 0x14;
    if (path_info_offset + 4 > detail_size) return {};

    uint16_t path_info = rd_u16(detail + path_info_offset);
    bool is_ascii = (path_info >> 15) == 1;
    int char_count = path_info & 0x7FFF;
    if (char_count == 0) return {};

    int path_start = path_info_offset + 4;
    std::string path = read_pml_string(detail, path_start, detail_size, is_ascii, char_count);

    /* QueryDirectory (op=32, sub_op=1): append directory name filter */
    if (operation == FS_DirectoryControl && detail_size > 0 && detail[0] == 1 && !path.empty()) {
        int needed = is_ascii ? char_count : char_count * 2;
        int dir_info_off = path_start + needed;
        if (dir_info_off + 2 <= detail_size) {
            uint16_t dir_info = rd_u16(detail + dir_info_off);
            bool dir_ascii = (dir_info >> 15) == 1;
            int dir_count = dir_info & 0x7FFF;
            if (dir_count > 0) {
                std::string dir_name = read_pml_string(
                    detail, dir_info_off + 2, detail_size, dir_ascii, dir_count);
                if (!dir_name.empty()) {
                    if (path.back() != '\\') path.push_back('\\');
                    path.append(dir_name);
                }
            }
        }
    }
    return path;
}

static std::string extract_network_path(const uint8_t *detail, int detail_size) {
    if (detail_size < 44) return {};
    uint16_t flags = rd_u16(detail);
    bool src_ipv4 = (flags & 1) != 0;
    bool dst_ipv4 = (flags & 2) != 0;
    const uint8_t *src_ip = detail + 8;
    const uint8_t *dst_ip = detail + 24;
    uint16_t src_port = rd_u16(detail + 40);
    uint16_t dst_port = rd_u16(detail + 42);

    std::string src_host = src_ipv4 ? format_ipv4(src_ip) : format_ipv6(src_ip);
    std::string dst_host = dst_ipv4 ? format_ipv4(dst_ip) : format_ipv6(dst_ip);
    return src_host + ":" + std::to_string(src_port) +
           " -> " + dst_host + ":" + std::to_string(dst_port);
}

std::string extract_network_path_resolved(
    const uint8_t *detail, int detail_size,
    const std::unordered_map<std::string, std::string> *hostname_lut,
    const std::unordered_map<uint32_t, std::string> *port_lut)
{
    if (detail_size < 44) return {};
    uint16_t flags = rd_u16(detail);
    bool src_ipv4 = (flags & 1) != 0;
    bool dst_ipv4 = (flags & 2) != 0;
    bool is_tcp = (flags & 4) != 0;
    const uint8_t *src_ip = detail + 8;
    const uint8_t *dst_ip = detail + 24;
    uint16_t src_port = rd_u16(detail + 40);
    uint16_t dst_port = rd_u16(detail + 42);

    /* Resolve hostnames */
    std::string src_host, dst_host;
    if (hostname_lut && !hostname_lut->empty()) {
        std::string src_key(reinterpret_cast<const char*>(src_ip), 16);
        auto it = hostname_lut->find(src_key);
        if (it != hostname_lut->end()) src_host = it->second;
        std::string dst_key(reinterpret_cast<const char*>(dst_ip), 16);
        auto dit = hostname_lut->find(dst_key);
        if (dit != hostname_lut->end()) dst_host = dit->second;
    }
    if (src_host.empty()) src_host = src_ipv4 ? format_ipv4(src_ip) : format_ipv6(src_ip);
    if (dst_host.empty()) dst_host = dst_ipv4 ? format_ipv4(dst_ip) : format_ipv6(dst_ip);

    /* Resolve port names */
    std::string src_port_str, dst_port_str;
    if (port_lut && !port_lut->empty()) {
        uint32_t sk = (static_cast<uint32_t>(src_port) << 1) | (is_tcp ? 1u : 0u);
        auto it = port_lut->find(sk);
        src_port_str = (it != port_lut->end()) ? it->second : std::to_string(src_port);
        uint32_t dk = (static_cast<uint32_t>(dst_port) << 1) | (is_tcp ? 1u : 0u);
        auto dit = port_lut->find(dk);
        dst_port_str = (dit != port_lut->end()) ? dit->second : std::to_string(dst_port);
    } else {
        src_port_str = std::to_string(src_port);
        dst_port_str = std::to_string(dst_port);
    }

    return src_host + ":" + src_port_str + " -> " + dst_host + ":" + dst_port_str;
}

static std::string extract_process_path(
    const uint8_t *detail, int detail_size, uint16_t operation, int pvoid_size)
{
    switch (operation) {
        case 0: case 1: /* Process_Defined, Process_Create */
        {
            if (detail_size < 52) return {};
            uint8_t unk1 = detail[44];
            uint8_t unk2 = detail[45];
            uint16_t path_info = rd_u16(detail + 46);
            bool is_ascii = (path_info >> 15) == 1;
            int char_count = path_info & 0x7FFF;
            if (char_count == 0) return {};
            int path_start = 52 + unk1 + unk2;
            return read_pml_string(detail, path_start, detail_size, is_ascii, char_count);
        }
        case 5: /* Load_Image */
        {
            int info_off = pvoid_size + 4;
            if (info_off + 4 > detail_size) return {};
            uint16_t path_info = rd_u16(detail + info_off);
            bool is_ascii = (path_info >> 15) == 1;
            int char_count = path_info & 0x7FFF;
            if (char_count == 0) return {};
            int path_start = info_off + 4;
            return read_pml_string(detail, path_start, detail_size, is_ascii, char_count);
        }
        default: return {};
    }
}

std::string extract_path(
    const uint8_t *buf, int64_t buf_len,
    int64_t event_offset, uint32_t event_class, uint16_t operation,
    uint16_t stacktrace_depth, uint32_t details_size, int pvoid_size)
{
    if (details_size == 0) return {};
    int64_t detail_off = event_offset + EVT_HEADER_SIZE +
                         static_cast<int64_t>(stacktrace_depth) * pvoid_size;
    if (detail_off < 0 || detail_off + details_size > buf_len) return {};
    const uint8_t *detail = buf + detail_off;
    int dsz = static_cast<int>(details_size);

    switch (event_class) {
        case EC_REGISTRY:    return extract_registry_path(detail, dsz, operation);
        case EC_FILE_SYSTEM: return extract_filesystem_path(detail, dsz, operation, pvoid_size);
        case EC_NETWORK:     return extract_network_path(detail, dsz);
        case EC_PROCESS:     return extract_process_path(detail, dsz, operation, pvoid_size);
        default:             return {};
    }
}



/* ================================================================
 * Detail JSON dispatcher (calls per-event-class modules)
 * ================================================================ */

std::string extract_detail_json(
    const uint8_t *buf, int64_t buf_len,
    int64_t event_offset,
    uint32_t event_class, uint16_t operation, uint32_t tid,
    uint16_t stacktrace_depth, uint32_t details_size,
    int pvoid_size, int tz_offset_seconds)
{
    if (details_size == 0) return "{}";

    int64_t detail_off = event_offset + EVT_HEADER_SIZE +
                         static_cast<int64_t>(stacktrace_depth) * pvoid_size;
    if (detail_off < 0 || detail_off + details_size > buf_len) return "{}";
    const uint8_t *detail_data = buf + detail_off;
    int dsz = static_cast<int>(details_size);

    /* Read extra_details_offset from header */
    const uint8_t *evt = buf + event_offset;
    uint32_t extra_details_rel = rd_u32(evt + EVT_EXTRA_DETAILS_OFFSET);
    const uint8_t *extra_data = nullptr;
    int extra_size = 0;
    int extra_buf_avail = -1;  /* bytes from extra_data to file-end (for reading past esz) */

    if (extra_details_rel > 0) {
        int64_t abs_extra = event_offset + extra_details_rel;
        if (abs_extra >= 0 && abs_extra + 2 <= buf_len) {
            uint16_t esz = rd_u16(buf + abs_extra);
            if (esz > 0 && abs_extra + 2 + esz <= buf_len) {
                extra_data = buf + abs_extra + 2;
                extra_size = static_cast<int>(esz);
                extra_buf_avail = static_cast<int>(buf_len - (abs_extra + 2));
            }
        }
    }

    switch (event_class) {
        case EC_REGISTRY:
            return extract_registry_detail_json(detail_data, dsz, operation,
                                                extra_data, extra_size, extra_buf_avail);
        case EC_FILE_SYSTEM:
            return extract_filesystem_detail_json(detail_data, dsz, operation,
                                                  extra_data, extra_size, pvoid_size, tz_offset_seconds);
        case EC_PROCESS:
            return extract_process_detail_json(detail_data, dsz, operation,
                                               tid, pvoid_size);
        case EC_NETWORK:
            return extract_network_detail_json(detail_data, dsz, operation);
        case EC_PROFILING:
            return extract_profiling_detail_json(detail_data, dsz);
        default:
            return "{}";
    }
}


/* ================================================================
 * Internal: Name resolution
 * ================================================================ */

static std::string resolve_category(
    const ScanContext &ctx,
    uint32_t event_class, uint16_t operation)
{
    uint32_t key = (event_class << 16) | operation;
    auto it = ctx.category_lut->find(key);
    if (it != ctx.category_lut->end()) return it->second;
    return {};
}

static std::string resolve_op_name(
    const ScanContext &ctx,
    uint32_t event_class, uint16_t operation,
    const uint8_t *buf, int64_t buf_len,
    int64_t event_offset,
    uint16_t stacktrace_depth, uint32_t details_size)
{
    uint32_t key = (event_class << 16) | operation;
    auto it = ctx.op_lut->find(key);
    std::string name;
    if (it != ctx.op_lut->end()) {
        name = it->second;
    } else {
        char tmp[32];
        std::snprintf(tmp, sizeof(tmp), "<Unknown: %u>", operation);
        return tmp;
    }

    if (event_class == EC_FILE_SYSTEM && fs_has_sub_op(operation) && details_size > 0) {
        int64_t detail_off = event_offset + EVT_HEADER_SIZE +
                             static_cast<int64_t>(stacktrace_depth) * ctx.pvoid_size;
        if (detail_off >= 0 && detail_off < buf_len) {
            uint8_t sub_op = buf[detail_off];
            if (sub_op != 0) {
                uint32_t sub_key = (static_cast<uint32_t>(operation) << 16) | sub_op;
                auto sit = ctx.sub_op_lut->find(sub_key);
                if (sit != ctx.sub_op_lut->end()) {
                    name = sit->second;
                } else {
                    name = "<Unknown>";
                }
            }
        }
    }

    if (event_class == EC_NETWORK && details_size >= 2) {
        int64_t detail_off = event_offset + EVT_HEADER_SIZE +
                             static_cast<int64_t>(stacktrace_depth) * ctx.pvoid_size;
        if (detail_off >= 0 && detail_off + 2 <= buf_len) {
            uint16_t flags = rd_u16(buf + detail_off);
            bool is_tcp = (flags & 4) != 0;
            name = (is_tcp ? "TCP " : "UDP ") + name;
        }
    }

    return name;
}

static std::string resolve_result_name(
    const ScanContext &ctx, uint32_t result_code)
{
    auto it = ctx.err_lut->find(result_code);
    if (it != ctx.err_lut->end()) return it->second;
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%X", result_code);
    return buf;
}


/* ================================================================
 * Category resolution with detail-based refinement (public)
 * ================================================================ */

std::string resolve_category_detailed(
    const ScanContext &ctx,
    const uint8_t *buf, int64_t buf_len,
    int64_t event_offset,
    uint32_t event_class, uint16_t operation,
    uint16_t stacktrace_depth, uint32_t details_size,
    uint32_t extra_details_offset)
{
    std::string category = resolve_category(ctx, event_class, operation);

    if (details_size == 0) return category;

    int64_t detail_off = event_offset + EVT_HEADER_SIZE +
                         static_cast<int64_t>(stacktrace_depth) * ctx.pvoid_size;
    if (detail_off < 0 || detail_off + details_size > buf_len)
        return category;
    const uint8_t *detail = buf + detail_off;
    int dsz = static_cast<int>(details_size);

    /* Get extra detail data */
    const uint8_t *extra_data = nullptr;
    int extra_size = 0;
    if (extra_details_offset > 0) {
        int64_t abs_extra = event_offset + extra_details_offset;
        if (abs_extra >= 0 && abs_extra + 2 <= buf_len) {
            uint16_t esz = rd_u16(buf + abs_extra);
            if (esz > 0 && abs_extra + 2 + esz <= buf_len) {
                extra_data = buf + abs_extra + 2;
                extra_size = static_cast<int>(esz);
            }
        }
    }

    if (event_class == EC_REGISTRY) {
        if ((operation == 0 || operation == 1) && extra_data && extra_size >= 8) {
            uint32_t disposition = rd_u32(extra_data + 4);
            if (disposition == 1) /* REG_CREATED_NEW_KEY */
                category = "Write";
        }
    } else if (event_class == EC_FILE_SYSTEM) {
        uint8_t sub_op = detail[0];
        if (sub_op != 0 && fs_has_sub_op(operation)) {
            uint32_t sub_key = (static_cast<uint32_t>(operation) << 16) | sub_op;
            auto sit = ctx.sub_op_lut->find(sub_key);
            if (sit != ctx.sub_op_lut->end()) {
                const std::string &eff_name = sit->second;
                if (eff_name == "SetDispositionInformationFile") {
                    int pio = 4 + ctx.pvoid_size * 5 + 0x14;
                    if (pio + 4 <= dsz) {
                        uint16_t path_info = rd_u16(detail + pio);
                        bool pa = (path_info >> 15) == 1;
                        int pc = path_info & 0x7FFF;
                        int path_end = pio + 4 + (pa ? pc : pc * 2);
                        if (path_end < dsz) {
                            uint8_t del_flag = detail[path_end];
                            if (del_flag) category = "Write";
                        }
                    }
                } else if (eff_name == "SetDispositionInformationEx") {
                    int pio = 4 + ctx.pvoid_size * 5 + 0x14;
                    if (pio + 4 <= dsz) {
                        uint16_t path_info = rd_u16(detail + pio);
                        bool pa = (path_info >> 15) == 1;
                        int pc = path_info & 0x7FFF;
                        int path_end = pio + 4 + (pa ? pc : pc * 2);
                        if (path_end + 4 <= dsz) {
                            uint32_t flags = rd_u32(detail + path_end);
                            if (flags & 0x1) category = "Write";
                        }
                    }
                } else if (eff_name == "SetRenameInformationFile" ||
                           eff_name == "SetRenameInformationEx" ||
                           eff_name == "SetRenameInformationExBypassAccessCheck" ||
                           eff_name == "SetLinkInformationFile") {
                    category = "Write";
                } else if (eff_name == "QueryDirectory" ||
                           eff_name == "NotifyChangeDirectory") {
                    category = "Read Metadata";
                }
            }
        }
        if (operation == 20 /* CreateFile */) {
            if (extra_data && extra_size >= 4) {
                uint32_t open_result = rd_u32(extra_data);
                if (open_result == 0 || open_result == 2 || open_result == 3)
                    category = "Write";
            } else {
                /* No completion record (failed op) â€” infer from disposition.
                 * disp_and_opts is at details_io + 0x10 + (pvoid_size==8?4:0).
                 * With details_io_offset=4: detail[4 + 0x10 + cond4]. */
                int cond4 = (ctx.pvoid_size == 8) ? 4 : 0;
                int disp_off = 4 + 0x10 + cond4;
                if (disp_off + 4 <= dsz) {
                    uint32_t disp_and_opts = rd_u32(detail + disp_off);
                    uint32_t disposition = disp_and_opts >> 24;
                    /* FILE_SUPERSEDE(0), FILE_CREATE(2), FILE_OPEN_IF(3), FILE_OVERWRITE(4), FILE_OVERWRITE_IF(5) */
                    if (disposition == 0 || disposition == 2 || disposition == 3 ||
                        disposition == 4 || disposition == 5)
                        category = "Write";
                }
            }
        }
        if (operation == 33 /* FileSystemControl */ && dsz >= 40) {
            /* IOCTL code is at detail[4 + 8 + 8 + cond4 + 4 + cond4]
             * where cond4 = 4 if pvoid_size==8.
             * 64-bit: offset = 4+8+8+4+4+4 = 32+4 = 36
             * 32-bit: offset = 4+8+8+0+4+0 = 24+4 = 28 */
            int ioctl_off = 4 + 8 + 8 + (ctx.pvoid_size == 8 ? 4 : 0) + 4 + (ctx.pvoid_size == 8 ? 4 : 0);
            if (ioctl_off + 4 <= dsz) {
                uint32_t ioctl = rd_u32(detail + ioctl_off);
                /* Map IOCTL to category */
                static const struct { uint32_t code; const char *cat; } ioctl_cat[] = {
                    {0x900bb, "Read Metadata"},   /* FSCTL_READ_USN_JOURNAL */
                    {0x900c0, "Read Metadata"},   /* FSCTL_CREATE_OR_GET_OBJECT_ID */
                    {0x900eb, "Read Metadata"},   /* FSCTL_READ_FILE_USN_DATA */
                    {0x900f4, "Read Metadata"},   /* FSCTL_QUERY_USN_JOURNAL */
                    {0x90078, "Read Metadata"},   /* FSCTL_IS_VOLUME_DIRTY */
                    {0x940cf, "Read Metadata"},   /* FSCTL_QUERY_ALLOCATED_RANGES */
                    {0x900a8, "Read"},            /* FSCTL_GET_REPARSE_POINT */
                    {0x900a4, "Write Metadata"},  /* FSCTL_SET_REPARSE_POINT */
                    {0x900c4, "Write Metadata"},  /* FSCTL_SET_SPARSE */
                    {0x900d7, "Write Metadata"},  /* FSCTL_SET_ENCRYPTION */
                    {0x9c040, "Write Metadata"},  /* FSCTL_SET_COMPRESSION */
                };
                for (auto &e : ioctl_cat) {
                    if (e.code == ioctl) {
                        category = e.cat;
                        break;
                    }
                }
            }
        }
    }

    return category;
}


/* ================================================================
 * Tree evaluation
 * ================================================================ */

static bool eval_tree_rule(
    const TreeRule &rule, const ScanContext &ctx, const EventData &ed)
{
    switch (rule.type) {
        case RT_HEADER_CMP: {
            uint64_t v;
            if (rule.field_offset == -1)
                v = static_cast<uint64_t>(ed.event_index);
            else
                v = read_header_field(ed.evt, rule.field_offset, rule.field_size);
            switch (rule.op_id) {
                case OP_EQ: return v == rule.int_value;
                case OP_NE: return v != rule.int_value;
                case OP_LE: return v <= rule.int_value;
                case OP_GE: return v >= rule.int_value;
                case OP_GT: return v >  rule.int_value;
                case OP_LT: return v <  rule.int_value;
                default: return true;
            }
        }
        case RT_PROCESS_MASK: {
            if (rule.proc_mask_data.empty()) return true;
            if (ed.proc_idx >= rule.proc_mask_data.size())
                return false;
            return rule.proc_mask_data[ed.proc_idx] != 0;
        }
        case RT_HEADER_EQ_ANY: {
            uint64_t v = read_header_field(ed.evt, rule.field_offset, rule.field_size);
            for (size_t i = 0; i < rule.int_values.size(); i++) {
                if (v == rule.int_values[i]) {
                    if (rule.check_event_class && ed.event_class != rule.ec_values[i])
                        continue;
                    return true;
                }
            }
            return false;
        }
        case RT_OP_REGEX: {
            if (!ed.op_name_resolved) {
                ed.op_name = resolve_op_name(
                    ctx, ed.event_class, ed.operation,
                    ctx.buf, ctx.buf_len, ed.event_offset,
                    ed.stacktrace_depth, ed.details_size);
                ed.op_name_resolved = true;
            }
            if (rule.is_multi_substr)
                return pml_pre::ci_contains_any(ed.op_name, rule.multi_substrs);
            return std::regex_search(ed.op_name, rule.regex);
        }
        case RT_RESULT_REGEX: {
            if (!ed.result_name_resolved) {
                ed.result_name = resolve_result_name(ctx, ed.result_code);
                ed.result_name_resolved = true;
            }
            if (rule.is_multi_substr)
                return pml_pre::ci_contains_any(ed.result_name, rule.multi_substrs);
            return std::regex_search(ed.result_name, rule.regex);
        }
        case RT_PATH_REGEX: {
            if (!ed.path_resolved) {
                ed.path = extract_path(
                    ctx.buf, ctx.buf_len, ed.event_offset,
                    ed.event_class, ed.operation,
                    ed.stacktrace_depth, ed.details_size, ctx.pvoid_size);
                ed.path_resolved = true;
            }
            if (rule.is_multi_substr)
                return pml_pre::ci_contains_any(ed.path, rule.multi_substrs);
            return std::regex_search(ed.path, rule.regex);
        }
        case RT_CATEGORY_REGEX: {
            if (!ed.category_resolved) {
                ed.category = resolve_category(ctx, ed.event_class, ed.operation);
                ed.category_resolved = true;
            }
            if (rule.is_multi_substr)
                return pml_pre::ci_contains_any(ed.category, rule.multi_substrs);
            return std::regex_search(ed.category, rule.regex);
        }
        case RT_DETAIL_REGEX: {
            if (!ed.detail_resolved) {
                ed.detail_json = extract_detail_json(
                    ctx.buf, ctx.buf_len, ed.event_offset,
                    ed.event_class, ed.operation, ed.tid,
                    ed.stacktrace_depth, ed.details_size, ctx.pvoid_size, ctx.tz_offset_seconds);
                ed.detail_resolved = true;
            }
            if (rule.is_multi_substr)
                return pml_pre::ci_contains_any(ed.detail_json, rule.multi_substrs);
            return std::regex_search(ed.detail_json, rule.regex);
        }
        case RT_ALWAYS_TRUE:
            return true;
        default:
            return true;
    }
}

static bool eval_tree(
    const std::vector<TreeNode> &nodes,
    const std::vector<TreeRule> &rules,
    int node_idx,
    const ScanContext &ctx,
    const EventData &ed)
{
    if (node_idx < 0 || node_idx >= static_cast<int>(nodes.size()))
        return true;
    const TreeNode &n = nodes[node_idx];
    switch (n.type) {
        case NT_LEAF:
            if (n.rule_idx < 0 || n.rule_idx >= static_cast<int>(rules.size()))
                return true;
            return eval_tree_rule(rules[n.rule_idx], ctx, ed);
        case NT_AND:
            for (int c : n.children) {
                if (!eval_tree(nodes, rules, c, ctx, ed)) return false;
            }
            return true;
        case NT_OR:
            for (int c : n.children) {
                if (eval_tree(nodes, rules, c, ctx, ed)) return true;
            }
            return false;
        case NT_NOT:
            if (n.children.empty()) return true;
            return !eval_tree(nodes, rules, n.children[0], ctx, ed);
        default:
            return true;
    }
}


/* ================================================================
 * Worker function (public)
 * ================================================================ */

void worker_tree(
    const ScanContext &ctx,
    const std::vector<TreeNode> &nodes,
    const std::vector<TreeRule> &rules,
    int root_idx,
    WorkerResult &wr)
{
    const uint8_t    *buf     = ctx.buf;
    const int64_t     buf_len = ctx.buf_len;
    const int64_t    *offsets = ctx.offsets;

    wr.results.reserve(std::min<int64_t>(wr.hi - wr.lo, 65536));

    EventData ed;
    for (int64_t i = wr.lo; i < wr.hi; i++) {
        int64_t off = offsets[i];
        if (off < 0 || off + EVT_HEADER_SIZE > buf_len) continue;
        const uint8_t *evt = buf + off;

        ed.event_index       = i;
        ed.evt               = evt;
        ed.event_offset      = off;
        ed.proc_idx          = rd_u32(evt + EVT_PROCESS_INDEX);
        ed.event_class       = rd_u32(evt + EVT_EVENT_CLASS);
        ed.operation         = rd_u16(evt + EVT_OPERATION);
        ed.result_code       = rd_u32(evt + EVT_RESULT);
        ed.stacktrace_depth  = rd_u16(evt + EVT_STACKTRACE_DEPTH);
        ed.details_size      = rd_u32(evt + EVT_DETAILS_SIZE);
        ed.tid               = rd_u32(evt + EVT_THREAD_ID);
        ed.op_name_resolved  = false;
        ed.result_name_resolved = false;
        ed.path_resolved     = false;
        ed.category_resolved = false;
        ed.detail_resolved   = false;

        if (eval_tree(nodes, rules, root_idx, ctx, ed))
            wr.results.push_back(i);
    }
}


/* ================================================================
 * Threading helper (public)
 * ================================================================ */

int compute_thread_count(int64_t range_size, int requested) {
    int n = requested;
    if (n <= 0) {
        unsigned hw = std::thread::hardware_concurrency();
        n = (hw > 0) ? static_cast<int>(hw) : 1;
    }
    n = std::min(n, MAX_THREADS);
    int max_by_work = static_cast<int>(range_size / MIN_EVENTS_PER_THREAD);
    if (max_by_work < 1) max_by_work = 1;
    n = std::min(n, max_by_work);
    n = std::min(n, static_cast<int>(range_size));
    return std::max(n, 1);
}
