/*
 * pml_filter_core.cpp — PML event filter engine implementation.
 */

#include "pml_filter_core.h"
#include "pml_preprocess.h"

#include <cstdio>
#include <algorithm>
#include <thread>


/* ================================================================
 * Internal: Read a PML string from detail data
 * ================================================================ */
static std::string read_pml_string(const uint8_t *data, int offset, int max_bytes,
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
 * Internal: Detail string extraction helpers
 * ================================================================ */

/* Stream-like reader over a byte buffer with bounds checking */
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

/* JSON builder for detail output */
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
 * Internal: Enum name tables
 * ================================================================ */

static const char* reg_type_name(uint32_t typ) {
    switch (typ) {
        case 0:  return "REG_NONE";
        case 1:  return "REG_SZ";
        case 2:  return "REG_EXPAND_SZ";
        case 3:  return "REG_BINARY";
        case 4:  return "REG_DWORD";
        case 5:  return "REG_DWORD_BIG_ENDIAN";
        case 6:  return "REG_LINK";
        case 7:  return "REG_MULTI_SZ";
        case 8:  return "REG_RESOURCE_LIST";
        case 9:  return "REG_FULL_RESOURCE_DESCRIPTOR";
        case 10: return "REG_RESOURCE_REQUIREMENTS_LIST";
        case 11: return "REG_QWORD";
        default: return nullptr;
    }
}

static const char* reg_key_info_class_name(uint32_t cls) {
    switch (cls) {
        case 0: return "Basic";     case 1: return "Node";
        case 2: return "Full";      case 3: return "Name";
        case 4: return "Cached";    case 5: return "Flags";
        case 6: return "Virtualization"; case 7: return "HandleTags";
        case 8: return "Trust";     case 9: return "Layer";
        default: return nullptr;
    }
}

static const char* reg_disposition_name(uint32_t d) {
    switch (d) {
        case 1: return "REG_CREATED_NEW_KEY";
        case 2: return "REG_OPENED_EXISTING_KEY";
        default: return nullptr;
    }
}

static const char* reg_set_info_class_name(uint32_t c) {
    switch (c) {
        case 0: return "KeyWriteTimeInformation";
        case 1: return "KeyWow64FlagsInformation";
        case 5: return "KeySetHandleTagsInformation";
        default: return nullptr;
    }
}

static const char* fs_disposition_name(uint32_t d) {
    switch (d) {
        case 0: return "Supersede"; case 1: return "Open";
        case 2: return "Create";    case 3: return "OpenIf";
        case 4: return "Overwrite"; case 5: return "OverwriteIf";
        default: return nullptr;
    }
}

static const char* fs_open_result_name(uint32_t r) {
    switch (r) {
        case 0: return "Superseded"; case 1: return "Opened";
        case 2: return "Created";    case 3: return "Overwritten";
        case 4: return "Exists";     case 5: return "DoesNotExist";
        default: return nullptr;
    }
}

/* ----------------------------------------------------------------
 * File Desired Access → Procmon display string
 * Matches Procmon v3 output exactly.
 * ---------------------------------------------------------------- */
static std::string format_file_desired_access(uint32_t mask) {
    /* Procmon maps FILE_GENERIC_READ (0x120089) to "Generic Read" not "Read".
     * Both the raw generic bit (0x80000000) and its expanded form (0x120089) map to
     * "Generic Read". Same logic for Write/Execute/All. */

    /* Whole-mask composites */
    if (mask == 0x1F01FFu)  return "All Access";
    if (mask == 0xC0000000u || mask == 0x12019Fu ||
        mask == 0x80120116u || mask == 0x40120089u)
        return "Generic Read/Write";
    if (mask == 0xA0000000u || mask == 0x1200A9u) return "Generic Read/Execute";
    if (mask == 0x80000000u || mask == 0x120089u) return "Generic Read";
    if (mask == 0x40000000u || mask == 0x120116u) return "Generic Write";
    if (mask == 0x20000000u || mask == 0x1200A0u) return "Generic Execute";
    if (mask == 0x10000000u)                      return "Generic All";

    /* Bit-by-bit: generic bits first, then specific bits ascending.
     * FILE_GENERIC_* composites map to "Generic *" for consistency with Procmon. */
    static const struct { uint32_t val; const char *name; } tbl[] = {
        /* combined generic access pairs (must precede individual generic entries) */
        {0xC0000000, "Generic Read/Write"},
        {0x12019F,   "Generic Read/Write"},
        {0x80120116, "Generic Read/Write"},
        {0x40120089, "Generic Read/Write"},
        {0xA0000000, "Generic Read/Execute"},
        {0x1200A9,   "Generic Read/Execute"},
        /* raw generic bits */
        {0x80000000, "Generic Read"},
        {0x40000000, "Generic Write"},
        {0x20000000, "Generic Execute"},
        {0x10000000, "Generic All"},
        {0x2000000,  "Maximum Allowed"},
        {0x1000000,  "Access System Security"},
        /* FILE_GENERIC_* composites (expanded equivalents) */
        {0x1F01FF,   "All Access"},
        {0x120116,   "Generic Write"},
        {0x120089,   "Generic Read"},
        {0x1200A0,   "Generic Execute"},
        /* individual specific bits, ascending */
        {0x0001,     "Read Data/List Directory"},
        {0x0002,     "Write Data/Add File"},
        {0x0004,     "Append Data/Add Subdirectory/Create Pipe Instance"},
        {0x0008,     "Read EA"},
        {0x0010,     "Write EA"},
        {0x0020,     "Execute/Traverse"},
        {0x0040,     "Delete Child"},
        {0x0080,     "Read Attributes"},
        {0x0100,     "Write Attributes"},
        {0x10000,    "Delete"},
        {0x20000,    "Read Control"},
        {0x40000,    "Write DAC"},
        {0x80000,    "Write Owner"},
        {0x100000,   "Synchronize"},
    };

    std::string result;
    uint32_t rem = mask;
    for (auto &e : tbl) {
        if ((rem & e.val) == e.val) {
            if (!result.empty()) result += ", ";
            result += e.name;
            rem &= ~e.val;
        }
    }
    if (result.empty()) {
        char tmp[32]; std::snprintf(tmp, sizeof(tmp), "None 0x%x", mask);
        return tmp;
    }
    return result;
}

/* ----------------------------------------------------------------
 * File Options → Procmon display string (NtCreateFile options)
 * ---------------------------------------------------------------- */
static std::string format_file_options(uint32_t opts) {
    /* Procmon option flag names (from procmon_parser, NtCreateFile CreateOptions) */
    static const struct { uint32_t val; const char *name; } procmon_tbl[] = {
        {0x000001, "Directory"},
        {0x000002, "Write Through"},
        {0x000004, "Sequential Access"},
        {0x000008, "No Buffering"},
        {0x000010, "Synchronous IO Alert"},
        {0x000020, "Synchronous IO Non-Alert"},
        {0x000040, "Non-Directory File"},
        {0x000080, "Create Tree Connection"},
        {0x000100, "Complete If Oplocked"},
        {0x000200, "No EA Knowledge"},
        {0x000400, "Open for Recovery"},
        {0x000800, "Random Access"},
        {0x001000, "Delete On Close"},
        {0x002000, "Open By ID"},
        {0x004000, "Open For Backup"},
        {0x008000, "No Compression"},
        {0x100000, "Reserve OpFilter"},
        {0x200000, "Open Reparse Point"},
        {0x400000, "Open No Recall"},
        {0x800000, "Open For Free Space Query"},
        /* Newer NT flags appended after original table (Win8+) */
        {0x010000, "Open Requiring Oplock"},
        {0x020000, "Disallow Exclusive"},
    };
    std::string result;
    uint32_t rem = opts;
    for (auto &e : procmon_tbl) {
        if (rem & e.val) {
            if (!result.empty()) result += ", ";
            result += e.name;
            rem &= ~e.val;
        }
    }
    if (result.empty()) {
        if (opts == 0) return "";
        char tmp[32]; std::snprintf(tmp, sizeof(tmp), "0x%x", opts);
        return tmp;
    }
    return result;
}

/* ----------------------------------------------------------------
 * File ShareMode → Procmon display string
 * ---------------------------------------------------------------- */
static std::string format_file_share_mode(uint32_t mode) {
    if (mode == 0) return "None";
    std::string r;
    if (mode & 0x1) r = "Read";
    if (mode & 0x2) { if (!r.empty()) r += ", "; r += "Write"; }
    if (mode & 0x4) { if (!r.empty()) r += ", "; r += "Delete"; }
    if (r.empty()) { char tmp[16]; std::snprintf(tmp, sizeof(tmp), "0x%x", mode); return tmp; }
    return r;
}

/* ----------------------------------------------------------------
 * File Attributes → Procmon display string
 * ---------------------------------------------------------------- */
static std::string format_file_attributes(uint32_t attr) {
    if (attr == 0) return "n/a";
    std::string r;
    /* Procmon uses abbreviated letter notation (1-char for common, multi-char for others) */
    static const struct { uint32_t bit; char letter; } tbl[] = {
        {0x0001, 'R'}, {0x0002, 'H'}, {0x0004, 'S'}, {0x0008, 0},  /* reserved */
        {0x0010, 'D'}, {0x0020, 'A'}, {0x0040, 'T'}, {0x0080, 0},  /* regular → 'N' */
        {0x0100, 0},   {0x0200, 0},   {0x0400, 0},   {0x0800, 'C'},  /* 0x800=Compressed */
        {0x1000, 'O'}, {0x2000, 0},   {0x4000, 'E'}, {0x8000, 0},
    };
    for (auto &e : tbl) {
        if (e.letter && (attr & e.bit)) r += e.letter;
    }
    /* FILE_ATTRIBUTE_NORMAL (0x80) */
    if (attr & 0x80) { if (!r.empty()) r += "N"; else r = "N"; }
    /* FILE_ATTRIBUTE_NOT_CONTENT_INDEXED (0x2000): multi-char abbreviation */
    if (attr & 0x2000) r += "NCI";
    /* FILE_ATTRIBUTE_SPARSE_FILE (0x200): multi-char abbreviation */
    if (attr & 0x200) r += "SF";
    /* FILE_ATTRIBUTE_REPARSE_POINT (0x400): multi-char abbreviation */
    if (attr & 0x400) r += "RP";
    if (r.empty()) { char tmp[16]; std::snprintf(tmp, sizeof(tmp), "0x%x", attr); return tmp; }
    return r;
}

static const char* sync_type_name(uint32_t t) {
    switch (t) {
        case 0: return "SyncTypeOther";
        case 1: return "SyncTypeCreateSection";
        case 2: return "SyncTypeCloseSection";
        default: return nullptr;
    }
}

/* Page protection for NtCreateSection / CreateFileMapping events.
 *
 * The effective section page protection is encoded in the LOW 10 BITS of the
 * little-endian u32 stored at offset 20 within the details_io sub-stream
 * (i.e., the first 4 bytes of the pvoid-width field at that position):
 *
 *   bits 4-7  (0xF0)  : execute-family flags; multiple bits may be set;
 *                        the LOWEST set bit determines the base protection:
 *                          0x10 PAGE_EXECUTE  0x20 PAGE_EXECUTE_READ
 *                          0x40 PAGE_EXECUTE_READWRITE  0x80 PAGE_EXECUTE_WRITECOPY
 *   bits 0-3  (0x0F)  : non-execute base protection (exact-match):
 *                          0x01 PAGE_NOACCESS  0x02 PAGE_READONLY
 *                          0x04 PAGE_READWRITE  0x08 PAGE_WRITECOPY
 *   bit  9   (0x200)  : PAGE_NOCACHE modifier
 *   bit  10  (0x400)  : PAGE_WRITECOMBINE modifier
 *   bit  8   (0x100)  : ignored (not a valid modifier for file-section mappings)
 */
static std::string format_section_page_protection(uint32_t prot_info) {
    /* prot_info should already be masked with 0x3FF by the caller */
    uint8_t exec_bits = static_cast<uint8_t>(prot_info & 0xF0u);
    uint8_t non_exec  = static_cast<uint8_t>(prot_info & 0x0Fu);
    std::string result;
    if (exec_bits) {
        static const struct { uint8_t bit; const char *name; } tbl[] = {
            { 0x10, "PAGE_EXECUTE" },
            { 0x20, "PAGE_EXECUTE_READ" },
            { 0x40, "PAGE_EXECUTE_READWRITE" },
            { 0x80, "PAGE_EXECUTE_WRITECOPY" },
        };
        for (const auto &e : tbl)
            if (exec_bits & e.bit) { result = e.name; break; }
    } else {
        static const struct { uint8_t mask; const char *name; } non_tbl[] = {
            { 0x01, "PAGE_NOACCESS" }, { 0x02, "PAGE_READONLY" },
            { 0x04, "PAGE_READWRITE" }, { 0x08, "PAGE_WRITECOPY" },
        };
        for (const auto &e : non_tbl)
            if (non_exec == e.mask) { result = e.name; break; }
    }
    if (result.empty()) {
        if (prot_info == 0) return {};
        char tmp[10]; std::snprintf(tmp, sizeof(tmp), "0x%03x", prot_info);
        return tmp;
    }
    /* Apply modifier bits (only NOCACHE and WRITECOMBINE are valid here) */
    if (prot_info & 0x200u) result += "|PAGE_NOCACHE";
    if (prot_info & 0x400u) result += "|PAGE_WRITECOMBINE";
    return result;
}

static std::string format_page_protection(uint32_t prot) {
    static const struct { uint32_t mask; const char *name; } base[] = {
        { 0x01, "PAGE_NOACCESS" },
        { 0x02, "PAGE_READONLY" },
        { 0x04, "PAGE_READWRITE" },
        { 0x08, "PAGE_WRITECOPY" },
        { 0x10, "PAGE_EXECUTE" },
        { 0x20, "PAGE_EXECUTE_READ" },
        { 0x40, "PAGE_EXECUTE_READWRITE" },
        { 0x80, "PAGE_EXECUTE_WRITECOPY" },
    };
    static const struct { uint32_t mask; const char *name; } mods[] = {
        { 0x100, "PAGE_GUARD" },
        { 0x200, "PAGE_NOCACHE" },
        { 0x400, "PAGE_WRITECOMBINE" },
    };
    std::string result;
    uint32_t base_prot = prot & 0xFF;
    for (auto &e : base) {
        if (base_prot == e.mask) { result = e.name; break; }
    }
    if (result.empty()) {
        char tmp[16]; std::snprintf(tmp, sizeof(tmp), "0x%x", prot);
        return tmp;
    }
    for (auto &e : mods) {
        if (prot & e.mask) { result += '|'; result += e.name; }
    }
    return result;
}

/* Convert a FILETIME (100ns ticks since 1601-01-01 UTC) to
 * Procmon display format: "M/D/YYYY H:MM:SS AM/PM" in local time.
 * If allow_epoch is true, ft==0 is formatted as the epoch date/time;
 * otherwise ft==0 returns "n/a". */
static std::string format_filetime_local(uint64_t ft, int tz_offset_seconds,
                                         bool allow_epoch = false) {
    if (ft == 0 && !allow_epoch) return "n/a";
    /* FILETIME epoch offset from Unix epoch (seconds): 11644473600 */
    static const int64_t FT_TO_UNIX_OFFSET_100NS = 116444736000000000LL;
    int64_t unix_100ns = static_cast<int64_t>(ft) - FT_TO_UNIX_OFFSET_100NS;
    /* Floor division (round toward -infinity) to convert 100ns to seconds */
    int64_t unix_secs;
    if (unix_100ns >= 0)
        unix_secs = unix_100ns / 10000000LL;
    else
        unix_secs = (unix_100ns - 9999999LL) / 10000000LL;
    /* Apply local timezone offset */
    int64_t local_secs = unix_secs + tz_offset_seconds;
    /* Manual calendar conversion */
    /* Days since Unix epoch */
    int64_t days = local_secs / 86400LL;
    int sod = (int)(local_secs % 86400LL);
    if (sod < 0) { sod += 86400; days--; }
    /* Convert days to Y/M/D (proleptic Gregorian, Unix epoch = 1970-01-01) */
    /* Algorithm from Howard Hinnant's date library */
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
    /* Time of day */
    int hour = sod / 3600;
    int minute = (sod % 3600) / 60;
    int second = sod % 60;
    const char *ampm = (hour < 12) ? "AM" : "PM";
    int hour12 = hour % 12;
    if (hour12 == 0) hour12 = 12;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%d/%d/%d %d:%02d:%02d %s",
                  m, d, year, hour12, minute, second, ampm);
    return buf;
}

static std::string format_duration_ticks(uint64_t ticks) {
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

/* Format CPU ticks (100ns units) as "s.fffffff" — Procmon's format for
 * Thread User Time / Kernel Time. */
static std::string format_cpu_ticks(uint64_t ticks) {
    uint64_t secs = ticks / 10000000ULL;
    uint64_t frac = ticks % 10000000ULL;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llu.%07llu",
                  (unsigned long long)secs, (unsigned long long)frac);
    return buf;
}

/* Same as format_cpu_ticks but appends " seconds" for Process Profiling events. */
static std::string format_profiling_ticks(uint64_t ticks) {
    return format_cpu_ticks(ticks) + " seconds";
}

/* Registry access mask → display string */
static std::string get_reg_access_mask_string(uint32_t mask) {
    if (mask & 0x80000000u) mask |= 0x20019u;
    if (mask & 0x40000000u) mask |= 0x20006u;
    if (mask & 0x20000000u) mask |= 0x20019u;
    if (mask & 0x10000000u) mask |= 0xf003fu;

    static const struct { uint32_t val; const char *name; } tbl[] = {
        {0xf003f, "All Access"}, {0x2001f, "Read/Write"}, {0x20019, "Read"},
        {0x20006, "Write"}, {0x1, "Query Value"}, {0x2, "Set Value"},
        {0x4, "Create Sub Key"}, {0x8, "Enumerate Sub Keys"},
        {0x10, "Notify"}, {0x20, "Create Link"}, {0x300, "WOW64_Res"},
        {0x200, "WOW64_32Key"}, {0x100, "WOW64_64Key"}, {0x10000, "Delete"},
        {0x20000, "Read Control"}, {0x40000, "Write DAC"},
        {0x80000, "Write Owner"}, {0x100000, "Synchronize"},
        {0x1000000, "Access System Security"}, {0x2000000, "Maximum Allowed"},
    };
    std::string result;
    uint32_t rem = mask;
    for (auto &e : tbl) {
        if ((rem & e.val) == e.val) {
            if (!result.empty()) result += ", ";
            result += e.name;
            rem &= ~e.val;
        }
    }
    if (result.empty()) {
        char tmp[32]; std::snprintf(tmp, sizeof(tmp), "None 0x%x", mask);
        return tmp;
    }
    return result;
}

/* Read registry data from extra detail and add to JSON builder */
static std::string format_reg_type_str(const char *tn, uint32_t rtype) {
    if (tn) return tn;
    return "<Unknown: " + std::to_string(rtype) + ">";
}

static void read_reg_data(DetailReader &dr, JsonBuilder &jb,
                          uint32_t reg_type, uint32_t length,
                          int multi_sz_entry_limit = 0x7FFFFFFF) {
    const char *tname = reg_type_name(reg_type);
    if (!tname) { jb.add_str("Data", ""); return; }
    if (length == 0) return;

    if (reg_type == 4 /* REG_DWORD */ && length >= 4) {
        jb.add_uint("Data", dr.u32());
    } else if (reg_type == 11 /* REG_QWORD */ && length >= 8) {
        /* Procmon shows empty Data for REG_QWORD */
        jb.add_str("Data", "");
    } else if ((reg_type == 1 || reg_type == 2) /* REG_SZ/REG_EXPAND_SZ */) {
        int chars = static_cast<int>(length / 2);
        if (dr.has(static_cast<int>(length))) {
            std::string s = utf16le_to_utf8(dr.data + dr.pos, chars);
            dr.skip(static_cast<int>(length));
            while (!s.empty() && s.back() == '\0') s.pop_back();
            jb.add_str("Data", s);
        }
    } else if (reg_type == 7 /* REG_MULTI_SZ */) {
        if (dr.has(static_cast<int>(length))) {
            /* Split at UTF-16LE null code units before converting to UTF-8.
             * utf16le_to_utf8 stops at the first null, so we must split first.
             * Entries are joined with ", " to match Procmon XML output format.
             * Procmon replaces individual entries longer than 48 chars with an
             * empty entry (contributing only the ", " separator) — matching the
             * display-width limit applied during XML export. */
            int chars = static_cast<int>(length / 2);
            const uint8_t *p = dr.data + dr.pos;
            dr.skip(static_cast<int>(length));
            std::string joined;
            int start = 0;
            for (int i = 0; i <= chars; i++) {
                uint16_t cu = (i < chars) ? rd_u16(p + i * 2) : 0;
                if (cu == 0) {
                    int segment_len = i - start;
                    int next_start = i + 1;
                    if (segment_len > multi_sz_entry_limit) {
                        /* Entry too long: emit an empty entry (separator only) */
                        if (!joined.empty()) joined += ", ";
                    } else if (segment_len > 0) {
                        if (!joined.empty()) joined += ", ";
                        joined += utf16le_to_utf8(p + start * 2, segment_len);
                    } else if (next_start < chars) {
                        /* Genuine empty entry in the middle of the MULTI_SZ */
                        if (!joined.empty()) joined += ", ";
                    }
                    start = next_start;
                }
            }
            /* Strip trailing separator left by a long last entry */
            while (joined.size() >= 2 &&
                   joined.back() == ' ' && joined[joined.size()-2] == ',')
                joined.resize(joined.size() - 2);
            jb.add_str("Data", joined);
        }
    } else if (reg_type == 3 /* REG_BINARY */) {
        /* Format as hex string for searchability */
        int to_read = std::min(static_cast<int>(length), dr.size - dr.pos);
        if (to_read > 0) {
            std::string hex;
            for (int i = 0; i < to_read; i++) {
                char tmp[4]; std::snprintf(tmp, sizeof(tmp), "%02x", dr.data[dr.pos + i]);
                hex += tmp;
            }
            dr.skip(to_read);
            jb.add_str("Data", hex);
        }
    }
}


/* ================================================================
 * Internal: Registry detail extraction
 * ================================================================ */

static std::string extract_registry_detail_json(
    const uint8_t *detail_data, int detail_size,
    uint16_t operation,
    const uint8_t *extra_data, int extra_size,
    int buf_avail = -1)
{
    DetailReader dr(detail_data, detail_size);
    JsonBuilder jb;

    /* Read path_info (first u16) */
    uint16_t path_info; dr.read_path_info(path_info);
    bool path_is_ascii = (path_info >> 15) == 1;
    int path_count = path_info & 0x7FFF;

    /* Operation-specific fields before the path string */
    uint32_t desired_access = 0, length = 0, info_class = 0;
    uint32_t index_val = 0, reg_type_val = 0, data_length = 0;
    uint16_t set_info_length = 0;
    int new_path_count = 0;
    bool new_path_is_ascii = true;

    switch (operation) {
        case 0: case 1: /* RegOpenKey, RegCreateKey */
            dr.skip(2); desired_access = dr.u32();
            break;
        case 3: case 5: /* RegQueryKey, RegQueryValue */
            dr.skip(2); length = dr.u32(); info_class = dr.u32();
            break;
        case 4: /* RegSetValue */
            dr.skip(2); reg_type_val = dr.u32(); length = dr.u32(); data_length = dr.u16(); dr.skip(2);
            break;
        case 6: case 7: /* RegEnumValue, RegEnumKey */
            dr.skip(2); length = dr.u32(); index_val = dr.u32(); info_class = dr.u32();
            break;
        case 8: /* RegSetInfoKey */
            dr.skip(2); info_class = dr.u32(); dr.skip(4);
            set_info_length = dr.u16(); dr.skip(2);
            break;
        case 12: case 14: /* RegLoadKey, RegRenameKey */ {
            uint16_t ni = dr.u16();
            new_path_is_ascii = (ni >> 15) == 1;
            new_path_count = ni & 0x7FFF;
            break;
        }
        case 18: case 19: case 20: /* Unknown1, RestoreKey, Unknown3 */
            dr.skip(2); dr.skip(4);
            break;
        default: break;
    }

    /* Extract registry path for context-sensitive logic.
     * Used to detect HKU\.DEFAULT paths, which have stricter EXPAND_SZ
     * display thresholds than user-specific HKU\SID paths. */
    std::string reg_path_lower;
    {
        int path_bytes = path_is_ascii ? path_count : path_count * 2;
        if (path_count > 0 && dr.has(path_bytes)) {
            std::string p;
            if (path_is_ascii)
                p.assign(reinterpret_cast<const char*>(dr.data + dr.pos), path_count);
            else
                p = utf16le_to_utf8(dr.data + dr.pos, path_count);
            reg_path_lower.reserve(p.size());
            for (unsigned char c : p)
                reg_path_lower.push_back(static_cast<char>(tolower(c)));
        }
    }
    bool is_hku_default = (reg_path_lower.find(".default") != std::string::npos);

    /* Skip the path string */
    dr.skip(path_is_ascii ? path_count : path_count * 2);

    /* Build detail JSON based on operation */
    DetailReader exdr(extra_data, extra_size);

    switch (operation) {
        case 0: case 1: { /* RegOpenKey / RegCreateKey */
            jb.add_str("Desired Access", get_reg_access_mask_string(desired_access));
            if (extra_size >= 8) {
                uint32_t granted    = exdr.u32();  /* GrantedAccess */
                uint32_t disposition = exdr.u32();
                /* Procmon shows Granted Access when the desired access is
                 * MAXIMUM_ALLOWED (0x02000000) alone — not when specific bits
                 * are also set alongside it. */
                static const uint32_t MAXIMUM_ALLOWED = 0x02000000;
                if (desired_access == MAXIMUM_ALLOWED && granted != desired_access)
                    jb.add_str("Granted Access", get_reg_access_mask_string(granted));
                const char *dn = reg_disposition_name(disposition);
                if (dn) jb.add_str("Disposition", dn);
            } else if (extra_size >= 4) {
                /* Older format: just disposition */
                uint32_t disposition = exdr.u32();
                const char *dn = reg_disposition_name(disposition);
                if (dn) jb.add_str("Disposition", dn);
            }
            break;
        }
        case 5: case 6: { /* RegQueryValue / RegEnumValue */
            if (operation == 6) jb.add_str("Index", std::to_string(index_val));
            if (extra_size > 0) {
                if (!exdr.has(12)) break;
                exdr.skip(4);                      /* TitleIndex */
                uint32_t rtype = exdr.u32();       /* Type */
                const char *tn = reg_type_name(rtype);

                if (info_class == 1) {
                    /* KeyValueFullInformation:
                     *   DataOffset(4)+DataLength(4)+NameLength(4)+Name(UTF-16)+Data@DataOffset
                     * Display order: Index, Name, Type, Length, Data */
                    if (!exdr.has(12)) break;
                    uint32_t data_offset  = exdr.u32();
                    uint32_t data_length  = exdr.u32();
                    uint32_t name_len_bytes = exdr.u32(); /* NameLength in bytes */

                    /* Determine whether Data will be displayed.  Must be computed first
                     * so the name-threshold estimate can use the accurate data_est.
                     *
                     * RegEnumValue (op=6) type-specific rules:
                     *   REG_MULTI_SZ (7) : always shown (list entries are individually short)
                     *   REG_EXPAND_SZ(2) : shown when data buffer does NOT exactly fill the
                     *                      extra_data (has_exact_fit=False). When exact_fit=True
                     *                      the data is the expanded path — hidden like op=5.
                     *   All other types  : shown when has_exact_fit OR data_length ≤ 128
                     * RegQueryValue (op=5): has_exact_fit || data_length ≤ 128 for all types. */
                    bool has_exact_fit = (static_cast<uint32_t>(extra_size) ==
                                          data_offset + data_length);
                    bool show_data;
                    if (data_length == 0 || data_offset >= static_cast<uint32_t>(extra_size)) {
                        show_data = false;
                    } else if (operation == 6 && rtype == 7 /* REG_MULTI_SZ */) {
                        show_data = true;
                    } else if (operation == 6 && rtype == 2 /* REG_EXPAND_SZ */) {
                        /* HKU\.DEFAULT paths use 80-byte limit for both the
                         * expanded (exact-fit) and template (non-exact) forms.
                         * User-specific HKU\SID paths use 128 bytes for
                         * the template form and 80 bytes for the expanded form. */
                        uint32_t threshold;
                        if (is_hku_default) {
                            threshold = 80u;
                        } else {
                            threshold = has_exact_fit ? 80u : 128u;
                        }
                        show_data = data_length <= threshold;
                    } else {
                        show_data = has_exact_fit || data_length <= 128u;
                    }

                    /* Masking marker: when an EXPAND_SZ value was masked,
                     * procmon stores 0xFFFF (0xFF 0xFF) in the 2 alignment
                     * bytes immediately after the data region.  This signals
                     * that the data content should be hidden (shown as empty)
                     * in XML export.  For REG_SZ the same padding value is
                     * incidental (the bytes already hold a masked *token*). */
                    if (show_data && !has_exact_fit && rtype == 2 /* EXPAND_SZ */) {
                        uint32_t pad_off = data_offset + data_length;
                        uint32_t pad_end = static_cast<uint32_t>(extra_size);
                        if (pad_end - pad_off == 2 &&
                            extra_data[pad_off] == 0xFF && extra_data[pad_off + 1] == 0xFF)
                            show_data = false;
                    }

                    /* Estimate data content length for computing name-clearing budget.
                     * 0 when data will not be displayed. */
                    size_t data_est = 0;
                    if (show_data) {
                        if (rtype == 3 /* REG_BINARY */)
                            data_est = (size_t)data_length * 3;
                        else if (rtype == 4 /* REG_DWORD */)
                            data_est = 10;
                        else if (rtype == 11 /* REG_QWORD */)
                            data_est = 0;
                        else if (rtype == 7 /* REG_MULTI_SZ */)
                            data_est = (data_length > 4) ? (data_length - 4) / 2 : 0;
                        else /* REG_SZ, REG_EXPAND_SZ, others */
                            data_est = (data_length > 2) ? (data_length - 2) / 2 : 0;
                    }

                    /* Read Name for RegEnumValue (op=6).
                     * Show name only when header-with-name + data_est fits in 256 chars.
                     * (fixed_overhead=41 + idx_digits + type_len + length_digits + data_est). */
                    if (name_len_bytes > 0 && exdr.has(static_cast<int>(name_len_bytes))) {
                        if (operation == 6) {
                            std::string name_str = utf16le_to_utf8(exdr.data + exdr.pos,
                                                   static_cast<int>(name_len_bytes / 2));
                            if (rtype == 7 /* REG_MULTI_SZ */) {
                                /* For MULTI_SZ, procmon uses a name-length-only cap (~80 chars). */
                                if ((int)name_str.size() > 80)
                                    name_str.clear();
                            } else {
                                std::string type_s = format_reg_type_str(tn, rtype);
                                size_t overhead = 41 + std::to_string(index_val).size() +
                                                 type_s.size() + std::to_string(data_length).size() +
                                                 data_est;
                                if ((int)name_str.size() > 200 - (int)overhead)
                                    name_str.clear();
                            }
                            jb.add_str("Name", name_str);
                        }
                        exdr.skip(static_cast<int>(name_len_bytes));
                    } else if (operation == 6) {
                        jb.add_str("Name", "");
                    }
                    jb.add_str("Type", format_reg_type_str(tn, rtype));
                    jb.add_str("Length", std::to_string(data_length));
                    if (show_data) {
                        /* procmon reads min(data_length, esz-24) bytes of data
                         * starting at data_offset. Since data_offset > 24 for
                         * most structures, this may extend past the esz boundary
                         * into adjacent memory (next event in the PML file).
                         * buf_avail (bytes from extra_data to file-end) allows
                         * reading past esz when needed. */
                        int read_cap = extra_size - 24;  /* esz - 24 formula */
                        int to_show = (static_cast<uint32_t>(read_cap) < data_length)
                                      ? read_cap : static_cast<int>(data_length);
                        int ext_avail = (buf_avail > 0)
                                        ? (buf_avail - static_cast<int>(data_offset))
                                        : (extra_size - static_cast<int>(data_offset));
                        int avail = std::min(to_show, ext_avail);
                        if (avail > 0) {
                            DetailReader data_dr(extra_data + data_offset, avail);
                            /* RegEnumValue (op=6) MULTI_SZ: procmon suppresses
                             * individual entries longer than 48 chars */
                            int msz_limit = (operation == 6) ? 48 : 0x7FFFFFFF;
                            read_reg_data(data_dr, jb, rtype, avail, msz_limit);
                        }
                    } else {
                        jb.add_str("Data", "");
                    }
                } else {
                    /* KeyValuePartialInformation (info_class==2) and others:
                     * DataLength(4) + Data[DataLength]
                     * For info_class==2, Procmon shows Type+Length+Data for both op=5 and op=6.
                     * For info_class==0 (KeyValueBasicInformation), Procmon shows only Type.
                     * Show data rules:
                     *  - REG_MULTI_SZ: always show (same as info_class=1 branch)
                     *  - Others: show when truncated, exact-fit, or dl ≤ 192 bytes.
                     * When full data is available (avail = dl+2) but dl > 192, hide it. */
                    jb.add_str("Type", format_reg_type_str(tn, rtype));
                    if (info_class == 2 || operation == 5) {
                        uint32_t dl = exdr.u32();
                        jb.add_str("Length", std::to_string(dl));
                        int avail_after = exdr.size - exdr.pos;
                        bool is_truncated = (static_cast<uint32_t>(avail_after) < dl);
                        bool partial_exact_fit = (static_cast<uint32_t>(avail_after) == dl);
                        bool partial_show;
                        if (rtype == 7 /* REG_MULTI_SZ */) {
                            partial_show = true;  /* MULTI_SZ: always show entries */
                        } else {
                            partial_show = is_truncated || partial_exact_fit || dl <= 192u;
                        }
                        if (dl > 0 && partial_show)
                            read_reg_data(exdr, jb, rtype, dl);
                        else if (dl > 0)
                            jb.add_str("Data", "");
                    }
                }
            } else {
                jb.add_str("Length", std::to_string(length));
            }
            break;
        }
        case 3: case 7: { /* RegQueryKey / RegEnumKey */
            if (operation == 7) {
                jb.add_str("Index", std::to_string(index_val));
            } else {
                const char *qn = reg_key_info_class_name(info_class);
                if (qn) jb.add_str("Query", qn);
            }
            if (extra_size > 0 && operation == 7) {
                /* Extract Name from returned KEY_*_INFORMATION structure (RegEnumKey only) */
                auto read_name = [&](DetailReader &r, int skip_prefix) {
                    if (!r.has(skip_prefix + 4)) return;
                    r.skip(skip_prefix);
                    uint32_t nsz = r.u32(); /* NameLength in bytes */
                    if (nsz > 0 && r.has(static_cast<int>(nsz)))
                        jb.add_str("Name", utf16le_to_utf8(r.data + r.pos, static_cast<int>(nsz / 2)));
                };
                if (info_class == 0) { /* KeyBasicInformation: LWT(8)+TitleIdx(4)+NameLen(4)+Name */
                    read_name(exdr, 8 + 4);
                } else if (info_class == 1) { /* KeyNodeInformation: LWT(8)+TitleIdx(4)+ClassOff(4)+ClassLen(4)+NameLen(4)+Name */
                    read_name(exdr, 8 + 4 + 4 + 4);
                } else if (info_class == 3) { /* KeyNameInformation: NameLen(4)+Name */
                    read_name(exdr, 0);
                } else {
                    jb.add_str("Length", std::to_string(length));
                }
            } else if (extra_size > 0 && operation == 3) {
                /* RegQueryKey: handle special extra_data formats */
                auto read_name = [&](DetailReader &r, int skip_prefix) {
                    if (!r.has(skip_prefix + 4)) return;
                    r.skip(skip_prefix);
                    uint32_t nsz = r.u32(); /* NameLength in bytes */
                    if (nsz > 0 && r.has(static_cast<int>(nsz)))
                        jb.add_str("Name", utf16le_to_utf8(r.data + r.pos, static_cast<int>(nsz / 2)));
                };
                if (info_class == 0) { /* KeyBasicInformation: LWT(8)+TitleIdx(4)+NameLen(4)+Name */
                    read_name(exdr, 8 + 4);
                } else if (info_class == 1) { /* KeyNodeInformation: LWT(8)+TitleIdx(4)+ClassOff(4)+ClassLen(4)+NameLen(4)+Name */
                    read_name(exdr, 8 + 4 + 4 + 4);
                } else if (info_class == 2) { /* KeyFullInformation:
                    * LWT(8)+TitleIndex(4)+ClassOff(4)+ClassLen(4)+SubKeys(4)+MaxNameLen(4)
                    * +MaxClassLen(4)+Values(4)+MaxValueNameLen(4)+MaxValueDataLen(4)+ClassLen(4) */
                    if (exdr.has(28)) {
                        exdr.skip(16);              /* skip LWT(8)+TitleIndex(4)+ClassOff(4) */
                        exdr.skip(4);               /* ClassLen */
                        uint32_t sub_keys = exdr.u32();
                        exdr.skip(4);               /* MaxNameLen */
                        exdr.skip(4);               /* MaxClassLen */
                        uint32_t values   = exdr.u32();
                        jb.add_uint("SubKeys", sub_keys);
                        jb.add_uint("Values",  values);
                    }
                } else if (info_class == 4) { /* KeyCachedInformation:
                    * LastWriteTime(8)+TitleIndex(4)+SubKeys(4)+MaxNameLen(4)
                    * +Values(4)+MaxValueNameLen(4)+MaxValueDataLen(4)+NameLength(4) */
                    if (exdr.has(20)) {
                        exdr.skip(12);              /* skip LastWriteTime(8) + TitleIndex(4) */
                        uint32_t sub_keys = exdr.u32();
                        exdr.skip(4);               /* skip MaxNameLen */
                        uint32_t values   = exdr.u32();
                        jb.add_uint("SubKeys", sub_keys);
                        jb.add_uint("Values",  values);
                    }
                } else if (info_class == 7) { /* HandleTags */
                    jb.add_hex("HandleTags", exdr.u32());
                } else if (info_class == 5) { /* Flags */
                    jb.add_hex("UserFlags", exdr.u32());
                }
                /* info_class 3 (Name), 6, 8, 9: Procmon shows nothing beyond "Query: <type>" */
            } else if (operation == 7) {
                jb.add_str("Length", std::to_string(length));
            } else if (operation == 3) {
                /* RegQueryKey with no extra data (e.g. BUFFER TOO SMALL):
                 * Procmon shows Length: 0 for most info classes. */
                if (info_class <= 7)
                    jb.add_str("Length", std::to_string(length));
            }
            break;
        }
        case 4: { /* RegSetValue */
            const char *tn = reg_type_name(reg_type_val);
            jb.add_str("Type", format_reg_type_str(tn, reg_type_val));
            jb.add_str("Length", std::to_string(length));
            bool data_emitted = false;
            if (tn && extra_size > 0) {
                uint32_t read_len = std::min(length, data_length);
                if (read_len > 0) { read_reg_data(exdr, jb, reg_type_val, read_len); data_emitted = true; }
            } else if (tn && dr.has(1)) {
                uint32_t read_len = std::min(length, data_length);
                if (read_len > 0) { read_reg_data(dr, jb, reg_type_val, read_len); data_emitted = true; }
            }
            if (!data_emitted && tn && length > 0) jb.add_str("Data", "");  /* empty when no bytes available */
            break;
        }
        case 8: { /* RegSetInfoKey */
            const char *cn = reg_set_info_class_name(info_class);
            jb.add_str("KeySetInformationClass", cn ? cn : "<Unknown>");
            jb.add_uint("Length", set_info_length);
            if (extra_size > 0 && set_info_length > 0) {
                if (info_class == 0) jb.add_uint("LastWriteTime", exdr.u64());
                else if (info_class == 1) jb.add_uint("Wow64Flags", exdr.u32());
                else if (info_class == 5) jb.add_uint("HandleTags", exdr.u32());
            } else if (dr.has(1) && set_info_length > 0) {
                if (info_class == 0) jb.add_uint("LastWriteTime", dr.u64());
                else if (info_class == 1) jb.add_uint("Wow64Flags", dr.u32());
                else if (info_class == 5) jb.add_uint("HandleTags", dr.u32());
            }
            break;
        }
        case 14: { /* RegRenameKey */
            if (new_path_count > 0) {
                int needed = new_path_is_ascii ? new_path_count : new_path_count * 2;
                if (dr.has(needed)) {
                    std::string new_name;
                    if (new_path_is_ascii) {
                        new_name = std::string(reinterpret_cast<const char*>(dr.data+dr.pos),
                                               static_cast<size_t>(new_path_count));
                        dr.skip(new_path_count);
                    } else {
                        new_name = utf16le_to_utf8(dr.data+dr.pos, new_path_count);
                        dr.skip(new_path_count * 2);
                    }
                    jb.add_str("New Name", new_name);
                }
            }
            break;
        }
        case 12: { /* RegLoadKey */
            if (new_path_count > 0) {
                int needed = new_path_is_ascii ? new_path_count : new_path_count * 2;
                if (dr.has(needed)) {
                    std::string hive_path;
                    if (new_path_is_ascii) {
                        hive_path = std::string(reinterpret_cast<const char*>(dr.data+dr.pos),
                                                static_cast<size_t>(new_path_count));
                        dr.skip(new_path_count);
                    } else {
                        hive_path = utf16le_to_utf8(dr.data+dr.pos, new_path_count);
                        dr.skip(new_path_count * 2);
                    }
                    jb.add_str("Hive Path", hive_path);
                }
            }
            break;
        }
        default: break;
    }

    return jb.build();
}


/* ================================================================
 * Internal: Process detail extraction
 * ================================================================ */

static std::string extract_process_detail_json(
    const uint8_t *detail_data, int detail_size,
    uint16_t operation, uint32_t tid, int pvoid_size)
{
    DetailReader dr(detail_data, detail_size);
    JsonBuilder jb;

    switch (operation) {
        case 0: case 1: { /* Process_Defined / Process_Create */
            dr.skip(4);
            uint32_t pid = dr.u32();
            jb.add_uint("PID", pid);
            dr.skip(0x24);
            uint8_t unk1 = dr.u8();
            uint8_t unk2 = dr.u8();
            uint16_t path_info = dr.u16();
            bool path_is_ascii = (path_info >> 15) == 1;
            int path_count = path_info & 0x7FFF;
            uint16_t cmd_info = dr.u16();
            bool cmd_is_ascii = (cmd_info >> 15) == 1;
            int cmd_count = cmd_info & 0x7FFF;
            dr.skip(2 + unk1 + unk2);
            /* Skip path string */
            dr.skip(path_is_ascii ? path_count : path_count * 2);
            /* Read command line */
            if (cmd_count > 0) {
                int needed = cmd_is_ascii ? cmd_count : cmd_count * 2;
                if (dr.has(needed)) {
                    std::string cmd;
                    if (cmd_is_ascii) {
                        cmd = std::string(reinterpret_cast<const char*>(dr.data+dr.pos),
                                          static_cast<size_t>(cmd_count));
                        dr.skip(cmd_count);
                    } else {
                        cmd = utf16le_to_utf8(dr.data+dr.pos, cmd_count);
                        dr.skip(cmd_count * 2);
                    }
                    while (!cmd.empty() && cmd.back() == '\0') cmd.pop_back();
                    jb.add_str("Command line", cmd);
                }
            }
            break;
        }
        case 2: case 8: { /* Process_Exit / Process_Statistics */
            uint32_t exit_status = dr.u32();
            jb.add_uint("Exit Status", exit_status);
            uint64_t kernel_ticks = dr.u64();
            uint64_t user_ticks = dr.u64();
            uint64_t working_set = dr.u64();
            uint64_t peak_ws = dr.u64();
            uint64_t private_b = dr.u64();
            uint64_t peak_priv = dr.u64();
            jb.add_str("User Time", format_profiling_ticks(user_ticks));
            jb.add_str("Kernel Time", format_profiling_ticks(kernel_ticks));
            jb.add_str("Private Bytes", std::to_string(private_b));
            jb.add_str("Peak Private Bytes", std::to_string(peak_priv));
            jb.add_str("Working Set", std::to_string(working_set));
            jb.add_str("Peak Working Set", std::to_string(peak_ws));
            break;
        }
        case 3: { /* Thread_Create */
            jb.add_uint("Thread ID", dr.u32());
            break;
        }
        case 4: { /* Thread_Exit */
            jb.add_uint("Thread ID", tid);
            dr.skip(4);
            uint64_t kernel_ticks = dr.u64();
            uint64_t user_ticks = dr.u64();
            jb.add_str("User Time", format_cpu_ticks(user_ticks));
            jb.add_str("Kernel Time", format_cpu_ticks(kernel_ticks));
            break;
        }
        case 5: { /* Load_Image */
            uint64_t image_base = (pvoid_size == 8) ? dr.u64() : dr.u32();
            uint32_t image_size = dr.u32();
            jb.add_hex("Image Base", image_base);
            jb.add_hex("Image Size", image_size);
            break;
        }
        case 7: { /* Process_Start */
            uint32_t ppid = dr.u32();
            jb.add_uint("Parent PID", ppid);
            uint16_t cmd_info = dr.u16();
            bool cmd_is_ascii = (cmd_info >> 15) == 1;
            int cmd_count = cmd_info & 0x7FFF;
            uint16_t dir_info = dr.u16();
            bool dir_is_ascii = (dir_info >> 15) == 1;
            int dir_count = dir_info & 0x7FFF;
            uint32_t env_count = dr.u32(); /* total wide chars in env block */
            if (cmd_count > 0) {
                int needed = cmd_is_ascii ? cmd_count : cmd_count * 2;
                if (dr.has(needed)) {
                    std::string cmd;
                    if (cmd_is_ascii) {
                        cmd = std::string(reinterpret_cast<const char*>(dr.data+dr.pos),
                                          static_cast<size_t>(cmd_count));
                        dr.skip(cmd_count);
                    } else {
                        cmd = utf16le_to_utf8(dr.data+dr.pos, cmd_count);
                        dr.skip(cmd_count * 2);
                    }
                    while (!cmd.empty() && cmd.back() == '\0') cmd.pop_back();
                    jb.add_str("Command line", cmd);
                }
            }
            if (dir_count > 0) {
                int needed = dir_is_ascii ? dir_count : dir_count * 2;
                if (dr.has(needed)) {
                    std::string cwd;
                    if (dir_is_ascii) {
                        cwd = std::string(reinterpret_cast<const char*>(dr.data+dr.pos),
                                          static_cast<size_t>(dir_count));
                        dr.skip(dir_count);
                    } else {
                        cwd = utf16le_to_utf8(dr.data+dr.pos, dir_count);
                        dr.skip(dir_count * 2);
                    }
                    while (!cwd.empty() && cwd.back() == '\0') cwd.pop_back();
                    jb.add_str("Current directory", cwd);
                }
            }
            if (env_count > 0) {
                int env_bytes = static_cast<int>(env_count) * 2;
                if (dr.has(env_bytes)) {
                    const uint8_t *env_data = dr.data + dr.pos;
                    std::string env_str;
                    int epos = 0;
                    while (epos + 2 <= env_bytes) {
                        int start = epos;
                        while (epos + 2 <= env_bytes) {
                            if (rd_u16(env_data + epos) == 0) { epos += 2; break; }
                            epos += 2;
                        }
                        int entry_chars = (epos - start) / 2 - 1;
                        if (entry_chars <= 0) break;
                        std::string entry = utf16le_to_utf8(env_data + start, entry_chars);
                        if (!entry.empty()) {
                            env_str += "\n\n\t";
                            env_str += entry;
                        }
                    }
                    if (!env_str.empty()) {
                        jb.add_str("Environment", env_str);
                    }
                }
            }
            break;
        }
        default: break;
    }

    return jb.build();
}


/* ================================================================
 * Internal: Filesystem detail extraction
 * ================================================================ */

static std::string get_io_flags_string(uint32_t flags) {
    static const struct { uint32_t val; const char *name; } tbl[] = {
        {0x01, "Non-cached"}, {0x02, "Paging I/O"}, {0x40, "Synchronous Paging I/O"},
        {0x400000, "Write Through"},
    };
    std::string r;
    for (auto &e : tbl) {
        if ((flags & e.val) == e.val) {
            if (!r.empty()) r += ", ";
            r += e.name;
        }
    }
    return r;
}

/* Parse a Windows SID from raw bytes and return a human-readable name.
 * For well-known SIDs, returns the symbolic name (e.g. "NT AUTHORITY\\SYSTEM").
 * For others, returns the S-R-A-... string representation. */
static std::string format_sid_name(const uint8_t *sid, int sid_len) {
    if (sid_len < 8) return {};   /* minimum SID: revision+count+authority */
    uint8_t revision   = sid[0];
    uint8_t sub_count  = sid[1];
    uint64_t authority = 0;
    for (int i = 0; i < 6; i++) authority = (authority << 8) | sid[2 + i];
    if (sid_len < 8 + sub_count * 4) return {};

    uint32_t subs[8] = {};
    for (uint8_t i = 0; i < sub_count && i < 8; i++) {
        subs[i] = rd_u32(sid + 8 + i * 4);
    }

    /* Well-known SID table: authority 5 (NT), authority 16 (Mandatory Label) */
    if (authority == 5) {
        if (sub_count == 1) {
            switch (subs[0]) {
                case  2: return "NT AUTHORITY\\NETWORK";
                case  3: return "NT AUTHORITY\\BATCH";
                case  4: return "NT AUTHORITY\\INTERACTIVE";
                case  6: return "NT AUTHORITY\\SERVICE";
                case  7: return "NT AUTHORITY\\ANONYMOUS LOGON";
                case 10: return "NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS";
                case 11: return "NT AUTHORITY\\Authenticated Users";
                case 13: return "NT AUTHORITY\\TERMINAL SERVER USER";
                case 14: return "NT AUTHORITY\\REMOTE INTERACTIVE LOGON";
                case 18: return "NT AUTHORITY\\SYSTEM";
                case 19: return "NT AUTHORITY\\LOCAL SERVICE";
                case 20: return "NT AUTHORITY\\NETWORK SERVICE";
            }
        } else if (sub_count == 2 && subs[0] == 32) {
            switch (subs[1]) {
                case 543: return "BUILTIN\\Pre-Windows 2000 Compatible Access";
                case 544: return "BUILTIN\\Administrators";
                case 545: return "BUILTIN\\Users";
                case 546: return "BUILTIN\\Guests";
                case 547: return "BUILTIN\\Power Users";
                case 548: return "BUILTIN\\Account Operators";
                case 549: return "BUILTIN\\Server Operators";
                case 550: return "BUILTIN\\Print Operators";
                case 551: return "BUILTIN\\Backup Operators";
                case 552: return "BUILTIN\\Replicators";
                case 555: return "BUILTIN\\Remote Desktop Users";
                case 556: return "BUILTIN\\Network Configuration Operators";
            }
        }
    } else if (authority == 16 && sub_count == 1) {
        switch (subs[0]) {
            case 0x1000: return "Mandatory Label\\Untrusted Mandatory Level";
            case 0x2000: return "Mandatory Label\\Low Mandatory Level";
            case 0x3000: return "Mandatory Label\\Medium Mandatory Level";
            case 0x4000: return "Mandatory Label\\High Mandatory Level";
            case 0x5000: return "Mandatory Label\\System Mandatory Level";
            case 0x7000: return "Mandatory Label\\Protected Process Mandatory Level";
        }
    }

    /* Fallback: S-R-A[-S1[-S2...]] */
    std::string s = "S-";
    s += std::to_string(revision);
    s += '-';
    s += std::to_string(authority);
    for (uint8_t i = 0; i < sub_count; i++) {
        s += '-';
        s += std::to_string(subs[i]);
    }
    return s;
}

static std::string extract_filesystem_detail_json(
    const uint8_t *detail_data, int detail_size,
    uint16_t operation,
    const uint8_t *extra_data, int extra_size,
    int pvoid_size, int tz_offset_seconds)
{
    DetailReader dr(detail_data, detail_size);
    JsonBuilder jb;

    /* sub_op(1) + pad(3) */
    uint8_t sub_op = dr.u8();
    dr.skip(3);

    /* Save position of details_io sub-stream */
    int details_io_offset = dr.pos;
    int details_io_size = pvoid_size * 5 + 0x14;
    dr.skip(details_io_size);

    /* Skip path_info(2) + pad(2) */
    uint16_t path_info = dr.u16();
    dr.skip(2);

    /* Skip path string, but remember start for directory extraction */
    bool path_is_ascii = (path_info >> 15) == 1;
    int path_count = path_info & 0x7FFF;
    int path_start_pos = dr.pos;
    dr.skip(path_is_ascii ? path_count : path_count * 2);

    bool is_read_write = false;
    bool is_create_file = false;

    if (operation == 23 || operation == 24 ||
        operation == 5 || operation == 3)
        is_read_write = true;
    else if (operation == 20)
        is_create_file = true;

    /* Parse details from details_io sub-stream */
    DetailReader dio(detail_data + details_io_offset, details_io_size);

    if (is_read_write) {
        dio.skip(0x4);
        uint32_t io_flags_and_priority = dio.u32();
        uint32_t io_flags = io_flags_and_priority & 0xe000ff;
        uint32_t priority = (io_flags_and_priority >> 0x11) & 7;
        dio.skip(0x4);
        uint32_t length = dio.u32();
        if (pvoid_size == 8) dio.skip(4);
        dio.skip(0x4);
        if (pvoid_size == 8) dio.skip(4);
        int64_t offset = dio.i64();

        char off_buf[32]; std::snprintf(off_buf, sizeof(off_buf), "%lld", (long long)offset);
        std::string off_str = off_buf;
        jb.add_str("Offset", off_str);

        if (extra_size >= 4) {
            DetailReader exdr(extra_data, extra_size);
            length = exdr.u32();
        }
        jb.add_str("Length", std::to_string(length));

        if (io_flags) {
            std::string flags_str = get_io_flags_string(io_flags);
            if (!flags_str.empty()) jb.add_str("I/O Flags", flags_str);
        }
        if (priority) {
            static const char* prio_names[] = {
                nullptr, "Very Low", "Low", "Normal", "High", "Critical"
            };
            const char *pn = (priority < 6) ? prio_names[priority] : nullptr;
            if (pn) jb.add_str("Priority", pn);
            else jb.add_hex("Priority", priority);
        }
    } else if (is_create_file) {
        uint32_t desired_access = dr.u32();
        std::string da_str = format_file_desired_access(desired_access);
        jb.add_str("Desired Access", da_str);
        uint8_t imp_sid_len = dr.u8();
        dr.skip(3);

        dio.skip(0x10);
        if (pvoid_size == 8) dio.skip(4);
        uint32_t disp_and_opts = dio.u32();
        uint32_t disposition = disp_and_opts >> 0x18;
        uint32_t options = disp_and_opts & 0xffffff;
        if (pvoid_size == 8) dio.skip(4);
        uint16_t attributes = dio.u16();
        uint16_t share_mode = dio.u16();

        const char *dn = fs_disposition_name(disposition);
        jb.add_str("Disposition", dn ? dn : std::to_string(disposition));
        jb.add_str("Options", format_file_options(options));
        std::string attr_str = format_file_attributes(attributes);
        if (!attr_str.empty()) jb.add_str("Attributes", attr_str);
        jb.add_str("ShareMode", format_file_share_mode(share_mode));

        dio.skip(0x4 + pvoid_size * 2);
        uint32_t alloc = dio.u32();
        /* Procmon shows "n/a" for AllocationSize when disposition is FILE_OPEN (1),
         * because opening an existing file does not involve an allocation request. */
        if (disposition == 1 /* FILE_OPEN */)
            jb.add_str("AllocationSize", "n/a");
        else
            jb.add_uint("AllocationSize", alloc);

        if (imp_sid_len > 0) {
            /* Read the impersonation SID and show "Impersonating: <name>" */
            if (dr.has(imp_sid_len)) {
                std::string sid_name = format_sid_name(dr.data + dr.pos, imp_sid_len);
                if (!sid_name.empty())
                    jb.add_str("Impersonating", sid_name);
            }
            dr.skip(imp_sid_len);
        } else if (extra_size >= 4) {
            DetailReader exdr(extra_data, extra_size);
            uint32_t open_result = exdr.u32();
            const char *orn = fs_open_result_name(open_result);
            jb.add_str("OpenResult", orn ? orn : "<unknown>");
        }
    } else if (operation == 19) { /* CreateFileMapping */
        dio.skip(0x0C);
        uint32_t sync_type = dio.u32();
        /* Skip the compact protection field at dio[16:20]; the effective
         * section protection is encoded in the low 10 bits of the u32 at
         * dio[20:24] (first 4 bytes of the pvoid at that position):
         *   bits 4-7  = execute-family base (lowest set bit wins)
         *   bits 0-3  = non-execute base (exact match)
         *   bit  9    = PAGE_NOCACHE modifier
         *   bit  10   = PAGE_WRITECOMBINE modifier */
        dio.skip(4);
        uint32_t prot_raw  = dio.u32();
        uint32_t prot_info = prot_raw & 0x3FFu;
        const char *stn = sync_type_name(sync_type);
        if (stn) jb.add_str("SyncType", stn);
        else { char tmp[32]; std::snprintf(tmp, sizeof(tmp), "SyncType%u", sync_type); jb.add_str("SyncType", tmp); }
        if (prot_info != 0) {
            jb.add_str("PageProtection", format_section_page_protection(prot_info));
        }
    } else if (operation == 6) { /* QueryOpen */
        /* extra_data = FILE_NETWORK_OPEN_INFORMATION (56 bytes):
         *   CreationTime(8)+LastAccessTime(8)+LastWriteTime(8)+ChangeTime(8)
         *   +AllocationSize(8)+EndOfFile(8)+FileAttributes(4) */
        if (extra_size >= 52) {
            DetailReader exdr(extra_data, extra_size);
            uint64_t creation_time    = exdr.u64();
            uint64_t last_access_time = exdr.u64();
            uint64_t last_write_time  = exdr.u64();
            uint64_t change_time      = exdr.u64();
            uint64_t alloc_size       = exdr.u64();
            uint64_t eof              = exdr.u64();
            uint32_t file_attrs       = exdr.u32();
            jb.add_str("CreationTime",   format_filetime_local(creation_time,    tz_offset_seconds));
            jb.add_str("LastAccessTime", format_filetime_local(last_access_time, tz_offset_seconds));
            jb.add_str("LastWriteTime",  format_filetime_local(last_write_time,  tz_offset_seconds));
            jb.add_str("ChangeTime",     format_filetime_local(change_time,      tz_offset_seconds));
            /* AllocationSize and EndOfFile are file sizes (bytes), not FILETIMEs */
            jb.add_str("AllocationSize", std::to_string(alloc_size));
            jb.add_str("EndOfFile",      std::to_string(eof));
            std::string attrs = format_file_attributes(file_attrs);
            jb.add_str("FileAttributes", attrs.empty() ? "n/a" : attrs);
        }
    } else if (operation == 4 || operation == 2) { /* FASTIO_MDL_READ_COMPLETE / FASTIO_MDL_WRITE_COMPLETE */
        /* MDL pointer at details_io[12..19] (= detail_data[16..23]) */
        dio.skip(12);
        if (dio.has(pvoid_size)) {
            uint64_t mdl = (pvoid_size == 8) ? dio.u64() : dio.u32();
            char tmp[24];
            std::snprintf(tmp, sizeof(tmp), "0x%llx", (unsigned long long)mdl);
            jb.add_str("MDL", tmp);
        }
    } else if (operation == 7) { /* FASTIO_CHECK_IF_POSSIBLE */
        /* Offset: details_io[12..19], Length: details_io[20..27], OpFlag: details_io[36..39] */
        dio.skip(12);
        if (dio.has(8 + 8 + 8 + 4)) {
            int64_t offset = (int64_t)dio.u64();
            int64_t length_val = (int64_t)dio.u64();
            dio.skip(8);  /* skip 8 bytes */
            uint32_t op_flag = dio.u32();
            /* op_flag: 1=Read, 0=Write */
            jb.add_str("Operation", (op_flag == 1) ? "Read" : "Write");
            jb.add_str("Offset", std::to_string(offset));
            jb.add_str("Length", std::to_string(length_val));
        }
    } else if (operation == 17) { /* FASTIO_ACQUIRE_FOR_MOD_WRITE */
        /* After the path, a u32 EndingOffset is stored. */
        if (dr.has(4)) {
            uint32_t ending_offset = dr.u32();
            jb.add_str("EndingOffset", std::to_string(ending_offset));
        }
    } else if (operation == 33 || operation == 34) { /* FileSystemControl / DeviceIoControl */
        dio.skip(0x8);
        uint32_t write_length = dio.u32();
        uint32_t read_length  = dio.u32();
        if (pvoid_size == 8) dio.skip(4);
        dio.skip(0x4);
        if (pvoid_size == 8) dio.skip(4);
        uint32_t ioctl = dio.u32();
        /* FSCTL/IOCTL code → display name table */
        static const struct { uint32_t code; const char *name; } fsctl_tbl[] = {
            {0x10003c, nullptr},  /* unknown — keep raw */
            {0x11c017, "FSCTL_PIPE_TRANSCEIVE"},
            {0x1401a3, "FSCTL_NETWORK_ENUMERATE_CONNECTIONS"},
            {0x1401a7, "FSCTL_NETWORK_GET_CONNECTION_INFO"},
            {0x1401ac, "FSCTL_NETWORK_DELETE_CONNECTION"},
            {0x1401c4, "FSCTL_LMR_GET_HINT_SIZE"},
            {0x1401f0, nullptr},  /* unknown — keep raw */
            {0x140390, "IOCTL_LMR_DISABLE_LOCAL_BUFFERING"},
            {0x144064, nullptr},  /* unknown — keep raw */
            {0x4d0008, "IOCTL_MOUNTDEV_QUERY_DEVICE_NAME"},
            {0x4d000c, "IOCTL_MOUNTDEV_QUERY_UNIQUE_ID"},
            {0x4d0014, "IOCTL_MOUNTDEV_QUERY_DEVICE_NAME"},
            {0x4d0020, "IOCTL_MOUNTDEV_LINK_CREATED"},
            {0x4d0024, "IOCTL_MOUNTDEV_LINK_DELETED"},
            {0x4d0028, "IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME"},
            {0x6d0008, "IOCTL_MOUNTMGR_QUERY_POINTS"},
            {0x6d000c, "IOCTL_MOUNTMGR_DELETE_POINTS"},
            {0x6d0010, "IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT"},
            {0x6d0018, "IOCTL_MOUNTMGR_NEXT_DRIVE_LETTER"},
            {0x60194,  "FSCTL_DFS_GET_REFERRALS"},
            {0x90028,  "FSCTL_IS_VOLUME_MOUNTED"},
            {0x90078,  "FSCTL_IS_VOLUME_DIRTY"},
            {0x900a4,  "FSCTL_SET_REPARSE_POINT"},
            {0x900a8,  "FSCTL_GET_REPARSE_POINT"},
            {0x900bb,  "FSCTL_READ_USN_JOURNAL"},
            {0x900c0,  "FSCTL_CREATE_OR_GET_OBJECT_ID"},
            {0x900c4,  "FSCTL_SET_SPARSE"},
            {0x900d7,  "FSCTL_SET_ENCRYPTION"},
            {0x900db,  "FSCTL_ENCRYPTION_FSCTL_IO"},
            {0x900eb,  "FSCTL_READ_FILE_USN_DATA"},
            {0x900f4,  "FSCTL_QUERY_USN_JOURNAL"},
            {0x90194,  nullptr},  /* unknown — keep raw */
            {0x90240,  "FSCTL_REQUEST_OPLOCK"},
            {0x940cf,  "FSCTL_QUERY_ALLOCATED_RANGES"},
            {0x9c040,  "FSCTL_SET_COMPRESSION"},
        };
        const char *fsctl_name = nullptr;
        bool name_found = false;
        for (auto &e : fsctl_tbl) {
            if (e.code == ioctl) {
                fsctl_name = e.name;  /* may be nullptr for unknown */
                name_found = true;
                break;
            }
        }
        if (name_found && fsctl_name != nullptr) {
            jb.add_str("Control", fsctl_name);
        } else {
            /* Raw format for unknown/unmapped codes */
            uint32_t dev_type = ioctl >> 16;
            uint32_t func     = (ioctl >> 2) & 0xFFF;
            uint32_t method   = ioctl & 0x3;
            char tmp[64];
            std::snprintf(tmp, sizeof(tmp), "0x%x (Device:0x%x Function:%u Method: %u)",
                          ioctl, dev_type, func, method);
            jb.add_str("Control", tmp);
        }
        /* FSCTL_PIPE_TRANSCEIVE: also output WriteLength and ReadLength */
        if (ioctl == 0x11c017) {
            jb.add_str("WriteLength", std::to_string(write_length));
            jb.add_str("ReadLength",  std::to_string(read_length));
        }
    } else if (operation == 30 && sub_op == 7 && extra_size >= 32) { /* QueryFullSizeInformationVolume */
        /* extra_data = FILE_FS_FULL_SIZE_INFORMATION (32 bytes):
         *   TotalAllocationUnits(8) + CallerAvailableAllocationUnits(8) +
         *   ActualAvailableAllocationUnits(8) + SectorsPerAllocationUnit(4) + BytesPerSector(4) */
        DetailReader exdr(extra_data, extra_size);
        uint64_t total_alloc   = exdr.u64();
        uint64_t caller_avail  = exdr.u64();
        uint64_t actual_avail  = exdr.u64();
        uint32_t sectors_alloc = exdr.u32();
        uint32_t bytes_sector  = exdr.u32();
        jb.add_str("TotalAllocationUnits",           std::to_string(total_alloc));
        jb.add_str("CallerAvailableAllocationUnits", std::to_string(caller_avail));
        jb.add_str("ActualAvailableAllocationUnits", std::to_string(actual_avail));
        jb.add_str("SectorsPerAllocationUnit",       std::to_string(sectors_alloc));
        jb.add_str("BytesPerSector",                 std::to_string(bytes_sector));
    } else if (operation == 30 && sub_op == 4 && extra_size >= 8) { /* QueryDeviceInformationVolume */
        /* extra_data = FILE_FS_DEVICE_INFORMATION: DeviceType(u32) + Characteristics(u32) */
        DetailReader exdr(extra_data, extra_size);
        uint32_t device_type    = exdr.u32();
        uint32_t characteristics = exdr.u32();
        static const struct { uint32_t val; const char *name; } dt_tbl[] = {
            {1,  "Beep"},              {2,  "CD-ROM"},       {3,  "CD-ROM File System"},
            {4,  "Controller"},        {5,  "Datalink"},     {6,  "DFS"},
            {7,  "Disk"},              {8,  "Disk File System"}, {9,  "File System"},
            {10, "Inport Port"},       {11, "Keyboard"},     {12, "Mailslot"},
            {13, "MIDI In"},           {14, "MIDI Out"},     {15, "Mouse"},
            {16, "Multi UNC Provider"},{17, "Named Pipe"},   {18, "Network"},
            {19, "Network Browser"},   {20, "Network File System"},{21, "NULL"},
            {22, "Parallel Port"},     {23, "Physical Netcard"},{24, "Printer"},
            {25, "Scanner"},           {26, "Serial Mouse Port"},{27, "Serial Port"},
            {28, "Screen"},            {29, "Sound"},        {30, "Streams"},
            {31, "Tape"},              {32, "Tape File System"},{33, "Transport"},
            {34, "Unknown"},           {35, "Video"},        {36, "Virtual Disk"},
            {37, "Wave In"},           {38, "Wave Out"},     {39, "8042 Port"},
            {40, "Network Redirector"},{41, "Battery"},      {42, "Bus Extender"},
            {43, "Filter"},            {44, "Human Interface Device"},{45, "ACPI"},
        };
        const char *dt_name = nullptr;
        for (auto &e : dt_tbl) { if (e.val == device_type) { dt_name = e.name; break; } }
        if (dt_name) jb.add_str("DeviceType", dt_name);
        else {
            char tmp[12]; std::snprintf(tmp, sizeof(tmp), "0x%x", device_type);
            jb.add_str("DeviceType", tmp);
        }
        /* Map Characteristics bits */
        static const struct { uint32_t bit; const char *name; } ch_tbl[] = {
            {0x01, "Removable"},  {0x02, "Read-Only"},  {0x04, "Floppy"},
            {0x08, "Write-Once"}, {0x10, "Remote"},     {0x20, "Mounted"},
            {0x40, "Virtual"},    {0x80, "Secure Open"},
        };
        std::string ch_str;
        for (auto &e : ch_tbl) {
            if (characteristics & e.bit) {
                if (!ch_str.empty()) ch_str += ", ";
                ch_str += e.name;
            }
        }
        if (!ch_str.empty()) jb.add_str("Characteristics", ch_str);
    } else if (operation == 30 && sub_op == 3 && extra_size >= 24) { /* QuerySizeInformationVolume */
        /* extra_data = FILE_FS_SIZE_INFORMATION (24 bytes):
         *   TotalAllocationUnits(i64)+AvailableAllocationUnits(i64)
         *   +SectorsPerAllocationUnit(u32)+BytesPerSector(u32) */
        DetailReader exdr(extra_data, extra_size);
        uint64_t total_alloc     = exdr.u64();
        uint64_t avail_alloc     = exdr.u64();
        uint32_t sectors_per     = exdr.u32();
        uint32_t bytes_per       = exdr.u32();
        jb.add_str("TotalAllocationUnits",     std::to_string(total_alloc));
        jb.add_str("AvailableAllocationUnits", std::to_string(avail_alloc));
        jb.add_str("SectorsPerAllocationUnit", std::to_string(sectors_per));
        jb.add_str("BytesPerSector",           std::to_string(bytes_per));
    } else if (operation == 30 && sub_op == 5 && extra_size >= 12) { /* QueryAttributeInformationVolume */
        /* extra_data = FILE_FS_ATTRIBUTE_INFORMATION:
         *   FileSystemAttributes(u32)+MaximumComponentNameLength(i32)+FileSystemNameLength(u32)+FileSystemName(UTF-16LE) */
        DetailReader exdr(extra_data, extra_size);
        uint32_t fs_attrs     = exdr.u32();
        int32_t  max_comp_len = static_cast<int32_t>(exdr.u32());
        uint32_t fs_name_len  = exdr.u32();
        /* Map FileSystemAttributes bits to Procmon display names */
        static const struct { uint32_t bit; const char *name; } fa_tbl[] = {
            {0x00000002, "Case Preserved"},
            {0x00000001, "Case Sensitive"},
            {0x00000004, "Unicode"},
            {0x00000008, "ACLs"},
            {0x00000010, "Compression"},
            {0x00040000, "Named Streams"},
            {0x00020000, "EFS"},
            {0x00010000, "Object IDs"},
            {0x00000080, "Reparse Points"},
            {0x00000040, "Sparse Files"},
            {0x00000020, "Quotas"},
            {0x00200000, "Transactions"},
        };
        std::string attr_str;
        uint32_t handled_bits = 0;
        for (auto &e : fa_tbl) {
            if (fs_attrs & e.bit) {
                if (!attr_str.empty()) attr_str += ", ";
                attr_str += e.name;
                handled_bits |= e.bit;
            }
        }
        uint32_t remainder = fs_attrs & ~handled_bits;
        if (remainder) {
            if (!attr_str.empty()) attr_str += ", ";
            char tmp[12]; std::snprintf(tmp, sizeof(tmp), "0x%x", remainder);
            attr_str += tmp;
        }
        if (attr_str.empty()) attr_str = "n/a";
        jb.add_str("FileSystemAttributes", attr_str);
        jb.add_str("MaximumComponentNameLength", std::to_string(max_comp_len));
        if (fs_name_len > 0 && exdr.has(static_cast<int>(fs_name_len))) {
            std::string fs_name = utf16le_to_utf8(exdr.data + exdr.pos,
                                                  static_cast<int>(fs_name_len / 2));
            jb.add_str("FileSystemName", fs_name);
        }
    } else if (operation == 30 && sub_op == 1 && extra_size >= 17) { /* QueryInformationVolume */
        /* extra_data = FILE_FS_VOLUME_INFORMATION:
         *   VolumeCreationTime(i64)+VolumeSerialNumber(u32)+VolumeLabelLength(u32)+SupportsObjects(u8)+[pad]+VolumeLabel(UTF-16LE) */
        DetailReader exdr(extra_data, extra_size);
        uint64_t creation_time   = exdr.u64();
        uint32_t serial_number   = exdr.u32();
        uint32_t label_length    = exdr.u32();
        uint8_t  supports_obj    = exdr.u8();
        exdr.skip(1); /* pad */
        jb.add_str("VolumeCreationTime", format_filetime_local(creation_time, tz_offset_seconds, true));
        /* Serial number: "XXXX-XXXX" */
        char sn_buf[12];
        std::snprintf(sn_buf, sizeof(sn_buf), "%04X-%04X",
                      (serial_number >> 16) & 0xFFFF, serial_number & 0xFFFF);
        jb.add_str("VolumeSerialNumber", sn_buf);
        jb.add_bool_str("SupportsObjects", supports_obj != 0);
        if (label_length > 0) {
            int avail = exdr.size - exdr.pos;
            int to_read = static_cast<int>(label_length);
            if (avail > 0) {
                if (to_read > avail) to_read = avail & ~1; /* round down to even */
                if (to_read > 0) {
                    std::string label = utf16le_to_utf8(exdr.data + exdr.pos,
                                                        to_read / 2);
                    jb.add_str("VolumeLabel", label);
                } else {
                    jb.add_str("VolumeLabel", "");
                }
            } else {
                jb.add_str("VolumeLabel", "");
            }
        } else {
            jb.add_str("VolumeLabel", "");
        }
    } else if (operation == 32 && sub_op == 1) { /* QueryDirectory */
        /* Read FileInformationClass from details_io sub-stream */
        dio.skip(0x10);
        if (pvoid_size == 8) dio.skip(4);
        dio.skip(0x4);
        if (pvoid_size == 8) dio.skip(4);
        uint32_t fi_class = dio.u32();

        /* Map FileInformationClass integer to name */
        static const struct { uint32_t val; const char *name; } fic_tbl[] = {
            {1, "FileDirectoryInformation"},
            {2, "FileFullDirectoryInformation"},
            {3, "FileBothDirectoryInformation"},
            {12, "FileNamesInformation"},
            {37, "FileIdBothDirectoryInformation"},
            {38, "FileIdFullDirectoryInformation"},
        };
        const char *fic_name = nullptr;
        for (auto &e : fic_tbl) { if (e.val == fi_class) { fic_name = e.name; break; } }
        if (fic_name) jb.add_str("FileInformationClass", fic_name);
        else jb.add_uint("FileInformationClass", fi_class);

        /* Read filter string from main detail stream (right after path bytes) */
        /* Layout after path: dir_info(u16) + dir_bytes (no padding) */
        std::string filter_name;
        bool has_filter = false;
        if (dr.has(2)) {
            uint16_t dir_info = dr.u16();
            bool dir_ascii = (dir_info >> 15) == 1;
            int dir_count = dir_info & 0x7FFF;
            if (dir_count > 0 && dr.has(dir_ascii ? dir_count : dir_count * 2)) {
                filter_name = read_pml_string(dr.data, dr.pos, dr.size, dir_ascii, dir_count);
                dr.skip(dir_ascii ? dir_count : dir_count * 2);
                if (!filter_name.empty()) {
                    jb.add_str("Filter", filter_name);
                    has_filter = true;
                }
            }
        }

        /* Parse directory entries from extra_data:
         * Supported: FileBothDirectoryInformation, FileDirectoryInformation,
         *            FileFullDirectoryInformation, FileNamesInformation */
        if (extra_size > 0 && (fi_class == 1 || fi_class == 2 || fi_class == 3 ||
                               fi_class == 12 || fi_class == 37 || fi_class == 38)) {
            /* Procmon entry numbering:
             * With filter: starts at index 2 for first entry
             * Without filter: starts at index 1 */
            int i = has_filter ? 1 : 0;
            int cur_off = 0;
            DetailReader edir(extra_data, extra_size);

            /* Track accumulated detail string length and entry count.
             * Procmon caps display at 6 directory entries per QueryDirectory event. */
            int detail_len;
            int dir_entry_count = 0;
            if (fic_name) {
                detail_len = 20 + 2 + static_cast<int>(strlen(fic_name));
            } else {
                char fi_tmp[16];
                std::snprintf(fi_tmp, sizeof(fi_tmp), "%u", fi_class);
                detail_len = 20 + 2 + static_cast<int>(strlen(fi_tmp));
            }
            /* ", Filter: {name}" = 10 + name.size() */
            if (has_filter) detail_len += 2 + 8 + static_cast<int>(filter_name.size());

            while (true) {
                i++;
                if (cur_off >= extra_size) break;
                edir.pos = cur_off;
                if (!edir.has(8)) break;
                uint32_t next_off = edir.u32();
                edir.skip(4); /* FileIndex */
                /* Read FileName depending on class */
                std::string fname;
                if (fi_class == 12) {
                    /* FileNamesInformation: NextEntryOffset(4)+FileIndex(4)+FileNameLength(4)+FileName */
                    if (!edir.has(4)) break;
                    uint32_t fnl = edir.u32();
                    if (fnl > 0 && edir.has(static_cast<int>(fnl)))
                        fname = utf16le_to_utf8(edir.data + edir.pos, static_cast<int>(fnl / 2));
                } else {
                    /* FileBothDirectoryInformation and similar:
                     * skip times(4×8)+EndOfFile(8)+AllocationSize(8)+FileAttributes(4)+FileNameLength(4) */
                    if (!edir.has(56)) break;
                    edir.skip(4 * 8); /* 4 timestamps × 8 bytes */
                    edir.skip(8 + 8); /* EndOfFile + AllocationSize */
                    edir.skip(4);     /* FileAttributes */
                    uint32_t fnl = edir.u32();
                    if (fi_class == 2 || fi_class == 38) {
                        /* FileFullDirectoryInformation: EaSize(4) */
                        edir.skip(4);
                        if (fi_class == 38) edir.skip(8); /* FileId */
                    } else if (fi_class == 3 || fi_class == 37) {
                        /* FileBothDirectoryInformation: EaSize(4)+ShortNameLength(1)+pad(1)+ShortName(24) */
                        edir.skip(4 + 1 + 1 + 24);
                        if (fi_class == 37) { edir.skip(2); edir.skip(8); } /* pad+FileId */
                    }
                    if (fnl > 0 && edir.has(static_cast<int>(fnl)))
                        fname = utf16le_to_utf8(edir.data + edir.pos, static_cast<int>(fnl / 2));
                }
                if (!fname.empty()) {
                    if (dir_entry_count >= 6) break;
                    std::string key_s = std::to_string(i);
                    dir_entry_count++;
                    jb.add_str(key_s.c_str(), fname);
                }
                if (next_off == 0) break;
                cur_off += static_cast<int>(next_off);
            }
        }
    } else if (operation == 32 && sub_op == 2) { /* NotifyChangeDirectory */
        dio.skip(0x10);
        if (pvoid_size == 8) dio.skip(4);
        uint32_t notify_flags = dio.u32();
        /* Map FILE_NOTIFY_CHANGE_* bits to Procmon display string */
        static const struct { uint32_t bit; const char *name; } nc_tbl[] = {
            {0x0001, "FILE_NOTIFY_CHANGE_FILE_NAME"},
            {0x0002, "FILE_NOTIFY_CHANGE_DIR_NAME"},
            {0x0004, "FILE_NOTIFY_CHANGE_ATTRIBUTES"},
            {0x0008, "FILE_NOTIFY_CHANGE_SIZE"},
            {0x0010, "FILE_NOTIFY_CHANGE_LAST_WRITE"},
            {0x0020, "FILE_NOTIFY_CHANGE_LAST_ACCESS"},
            {0x0040, "FILE_NOTIFY_CHANGE_CREATION"},
            {0x0100, "FILE_NOTIFY_CHANGE_SECURITY"},
            {0x0200, "FILE_NOTIFY_CHANGE_STREAM_NAME"},
            {0x0400, "FILE_NOTIFY_CHANGE_STREAM_SIZE"},
            {0x0800, "FILE_NOTIFY_CHANGE_STREAM_WRITE"},
        };
        std::string filter_str;
        for (auto &e : nc_tbl) {
            if (notify_flags & e.bit) {
                if (!filter_str.empty()) filter_str += ", ";
                filter_str += e.name;
            }
        }
        if (!filter_str.empty())
            jb.add_str("Filter", filter_str);
        else {
            char tmp[12];
            std::snprintf(tmp, sizeof(tmp), "0x%x", notify_flags);
            jb.add_str("Filter", tmp);
        }
    } else if (operation == 26 && sub_op == 0x04) { /* SetBasicInformationFile */
        /* FILE_BASIC_INFORMATION is inline after path in detail stream:
         * CreationTime(i64)+LastAccessTime(i64)+LastWriteTime(i64)+ChangeTime(i64)+FileAttributes(u32)
         * Zero timestamps mean "do not change" — Procmon still shows them as epoch date. */
        if (dr.has(36)) {
            uint64_t creation_time    = dr.u64();
            uint64_t last_access_time = dr.u64();
            uint64_t last_write_time  = dr.u64();
            uint64_t change_time      = dr.u64();
            uint32_t file_attrs       = dr.u32();
            jb.add_str("CreationTime",   format_filetime_local(creation_time,    tz_offset_seconds, true));
            jb.add_str("LastAccessTime", format_filetime_local(last_access_time, tz_offset_seconds, true));
            jb.add_str("LastWriteTime",  format_filetime_local(last_write_time,  tz_offset_seconds, true));
            jb.add_str("ChangeTime",     format_filetime_local(change_time,      tz_offset_seconds, true));
            std::string attrs = format_file_attributes(file_attrs);
            jb.add_str("FileAttributes", attrs.empty() ? "n/a" : attrs);
        }
    } else if (operation == 37) { /* LockUnlockFile: LockFile/UnlockFileSingle/etc */
        /* details_io layout (64-bit, pvoid_size=8):
         *   [0:8]   Length pointer (pvoid)
         *   [8:12]  Key (u32)
         *   [12:20] ByteOffset pointer (pvoid)
         *   [20:28] zeros (LARGE_INTEGER-sized)
         *   [28:36] ByteOffset value (LARGE_INTEGER) = pvoid_size*3 + 4
         *   [36:44] another pointer (pvoid)
         *   [44]    Exclusive BOOLEAN (1=True)   = pvoid_size*4 + 12
         *   [45]    FailImmediately BOOLEAN       = pvoid_size*4 + 13
         * Main stream after path: Length (u64)
         */
        int exclusive_off   = pvoid_size * 4 + 12;  /* 44 on 64-bit */
        int byte_offset_off = pvoid_size * 3 + 4;   /* 28 on 64-bit */
        bool exclusive = false;
        bool fail_imm  = false;
        {
            DetailReader dio_flags(detail_data + details_io_offset, details_io_size);
            if (dio_flags.has(exclusive_off + 2)) {
                dio_flags.skip(exclusive_off);
                fail_imm  = (dio_flags.u8() != 0);  /* dio[44]: FailImmediately */
                exclusive = (dio_flags.u8() != 0);  /* dio[45]: ExclusiveLock */
            }
        }
        int64_t byte_offset = 0;
        DetailReader dio_lock(detail_data + details_io_offset, details_io_size);
        if (dio_lock.has(byte_offset_off + 8)) {
            dio_lock.skip(byte_offset_off);
            byte_offset = static_cast<int64_t>(dio_lock.u64());
        }
        /* Length is stored in the main detail stream after the path */
        int64_t length_val = dr.has(8) ? static_cast<int64_t>(dr.u64()) : 0;
        /* Only LockFile (sub_op=1) shows Exclusive and Fail Immediately flags */
        if (sub_op == 1) {
            jb.add_bool_str("Exclusive", exclusive);
        }
        jb.add_str("Offset", std::to_string(byte_offset));
        jb.add_str("Length", std::to_string(length_val));
        if (sub_op == 1) {
            jb.add_bool_str("Fail Immediately", fail_imm);
        }
    } else if (operation == 26 && sub_op == 0x13) { /* SetAllocationInformationFile */
        /* FILE_ALLOCATION_INFORMATION: AllocationSize(i64) inline after path in dr */
        if (dr.has(8)) {
            int64_t alloc = static_cast<int64_t>(dr.u64());
            jb.add_str("AllocationSize", std::to_string(alloc));
        }
    } else if (operation == 26 && sub_op == 0x14) { /* SetEndOfFileInformationFile */
        /* FILE_END_OF_FILE_INFORMATION: EndOfFile(i64) inline after path in dr */
        if (dr.has(8)) {
            int64_t eof = static_cast<int64_t>(dr.u64());
            jb.add_str("EndOfFile", std::to_string(eof));
        }
    } else if (operation == 26 && (sub_op == 0x0a || sub_op == 0x41 || sub_op == 0x42 ||
                                    sub_op == 0x0b)) { /* SetRenameInformationFile/Ex/ExBypassAccessCheck, SetLinkInformationFile */
        /* FILE_RENAME_INFORMATION / FILE_LINK_INFORMATION:
         *   ReplaceIfExists(1) + pad(3 or 7) + RootDirectory(pvoid) + FileNameLength(4) + FileName(UTF-16LE)
         * When FileName is relative (no leading backslash), prepend directory of source path. */
        if (dr.has(1)) {
            bool replace = (dr.u8() != 0);
            jb.add_bool_str("ReplaceIfExists", replace);
            int pad = (pvoid_size == 8) ? 7 : 3;
            dr.skip(pad);
            dr.skip(pvoid_size); /* RootDirectory handle */
            if (dr.has(4)) {
                uint32_t fnl = dr.u32();
                if (fnl > 0 && dr.has(static_cast<int>(fnl))) {
                    std::string fname = utf16le_to_utf8(dr.data + dr.pos, static_cast<int>(fnl / 2));
                    /* If relative (no leading backslash), prepend source file's directory */
                    if (!fname.empty() && fname[0] != '\\') {
                        /* Extract source path to get directory */
                        std::string src_path;
                        if (path_is_ascii && path_count > 0 && path_start_pos + path_count <= detail_size) {
                            src_path = std::string(
                                reinterpret_cast<const char*>(detail_data + path_start_pos),
                                static_cast<size_t>(path_count));
                        } else if (!path_is_ascii && path_count > 0) {
                            src_path = utf16le_to_utf8(detail_data + path_start_pos, path_count);
                        }
                        /* Find last backslash to get directory */
                        size_t last_bs = src_path.rfind('\\');
                        if (last_bs != std::string::npos)
                            fname = src_path.substr(0, last_bs + 1) + fname;
                    }
                    jb.add_str("FileName", fname);
                }
            }
        }
    } else if (operation == 26 && sub_op == 0x0d) { /* SetDispositionInformationFile */
        bool is_delete = (dr.u8() != 0);
        jb.add_bool_str("Delete", is_delete);
    } else if (operation == 26 && sub_op == 0x40) { /* SetDispositionInformationEx */
        uint32_t flags = dr.u32();
        bool is_delete = (flags & 0x1) != 0;
        jb.add_bool_str("Delete", is_delete);
    } else if (operation == 25 && sub_op == 4) { /* QueryBasicInformationFile */
        /* extra_data = FILE_BASIC_INFORMATION (40 bytes) */
        if (extra_size >= 36) {
            DetailReader exdr(extra_data, extra_size);
            uint64_t creation_time    = exdr.u64();
            uint64_t last_access_time = exdr.u64();
            uint64_t last_write_time  = exdr.u64();
            uint64_t change_time      = exdr.u64();
            uint32_t file_attrs       = exdr.u32();
            jb.add_str("CreationTime",    format_filetime_local(creation_time,    tz_offset_seconds));
            jb.add_str("LastAccessTime",  format_filetime_local(last_access_time, tz_offset_seconds));
            jb.add_str("LastWriteTime",   format_filetime_local(last_write_time,  tz_offset_seconds));
            jb.add_str("ChangeTime",      format_filetime_local(change_time,      tz_offset_seconds));
            std::string attrs = format_file_attributes(file_attrs);
            jb.add_str("FileAttributes",  attrs.empty() ? "n/a" : attrs);
        }
    } else if (operation == 25 && sub_op == 0x12) { /* QueryAllInformationFile */
        /* extra_data = FILE_ALL_INFORMATION:
         *   BasicInformation(40) + StandardInformation(24) + ...
         *   Shows BasicInformation fields + AllocationSize + EndOfFile */
        if (extra_size >= 56) {
            DetailReader exdr(extra_data, extra_size);
            uint64_t creation_time    = exdr.u64();
            uint64_t last_access_time = exdr.u64();
            uint64_t last_write_time  = exdr.u64();
            uint64_t change_time      = exdr.u64();
            uint32_t file_attrs       = exdr.u32();
            exdr.skip(4); /* padding to align StandardInformation */
            uint64_t alloc_size       = exdr.u64();
            uint64_t eof              = exdr.u64();
            jb.add_str("CreationTime",    format_filetime_local(creation_time,    tz_offset_seconds));
            jb.add_str("LastAccessTime",  format_filetime_local(last_access_time, tz_offset_seconds));
            jb.add_str("LastWriteTime",   format_filetime_local(last_write_time,  tz_offset_seconds));
            jb.add_str("ChangeTime",      format_filetime_local(change_time,      tz_offset_seconds));
            std::string attrs = format_file_attributes(file_attrs);
            jb.add_str("FileAttributes",  attrs.empty() ? "n/a" : attrs);
            jb.add_str("AllocationSize",  std::to_string(alloc_size));
            jb.add_str("EndOfFile",       std::to_string(eof));
        }
    } else if (operation == 25 && sub_op == 5) { /* QueryStandardInformationFile */
        /* extra_data = FILE_STANDARD_INFORMATION (24 bytes):
         *   AllocationSize(i64) + EndOfFile(i64) + NumberOfLinks(u32)
         *   + DeletePending(u8) + Directory(u8) */
        if (extra_size >= 18) {
            DetailReader exdr(extra_data, extra_size);
            uint64_t alloc_size = exdr.u64();
            uint64_t eof        = exdr.u64();
            uint32_t num_links  = exdr.u32();
            uint8_t  del_pend   = exdr.u8();
            uint8_t  is_dir     = exdr.u8();
            /* Procmon formats large integers with comma separators (add_str
             * causes the normalizer to apply thousands formatting) */
            jb.add_str("AllocationSize", std::to_string(alloc_size));
            jb.add_str("EndOfFile",      std::to_string(eof));
            jb.add_str("NumberOfLinks",  std::to_string(num_links));
            jb.add_bool_str("DeletePending", del_pend != 0);
            jb.add_bool_str("Directory",     is_dir != 0);
        }
    } else if (operation == 25 && sub_op == 6) { /* QueryFileInternalInformationFile */
        /* extra_data = FILE_INTERNAL_INFORMATION (8 bytes): IndexNumber(i64) */
        if (extra_size >= 8) {
            DetailReader exdr(extra_data, extra_size);
            uint64_t idx = exdr.u64();
            char tmp[24];
            std::snprintf(tmp, sizeof(tmp), "0x%llx", (unsigned long long)idx);
            jb.add_str("IndexNumber", tmp);
        }
    } else if (operation == 25 && sub_op == 0x22) { /* QueryNetworkOpenInformationFile */
        /* extra_data = FILE_NETWORK_OPEN_INFORMATION (56 bytes):
         *   CreationTime(8)+LastAccessTime(8)+LastWriteTime(8)+ChangeTime(8)
         *   +AllocationSize(8)+EndOfFile(8)+FileAttributes(4)
         * Procmon formats ALL LARGE_INTEGER fields as FILETIMEs. */
        if (extra_size >= 52) {
            DetailReader exdr(extra_data, extra_size);
            uint64_t creation_time    = exdr.u64();
            uint64_t last_access_time = exdr.u64();
            uint64_t last_write_time  = exdr.u64();
            uint64_t change_time      = exdr.u64();
            uint64_t alloc_size       = exdr.u64();
            uint64_t eof              = exdr.u64();
            uint32_t file_attrs       = exdr.u32();
            jb.add_str("CreationTime",   format_filetime_local(creation_time,    tz_offset_seconds));
            jb.add_str("LastAccessTime", format_filetime_local(last_access_time, tz_offset_seconds));
            jb.add_str("LastWriteTime",  format_filetime_local(last_write_time,  tz_offset_seconds));
            jb.add_str("ChangeTime",     format_filetime_local(change_time,      tz_offset_seconds));
            /* AllocationSize and EndOfFile are also formatted as FILETIMEs by
             * Procmon; use allow_epoch=true so zero displays as epoch date. */
            jb.add_str("AllocationSize", format_filetime_local(alloc_size, tz_offset_seconds, true));
            jb.add_str("EndOfFile",      format_filetime_local(eof,        tz_offset_seconds, true));
            std::string attrs = format_file_attributes(file_attrs);
            jb.add_str("FileAttributes", attrs.empty() ? "n/a" : attrs);
        }
    } else if (operation == 25 && sub_op == 9) { /* QueryNameInformationFile */
        /* extra_data = FILE_NAME_INFORMATION:
         *   FileNameLength(4) + FileName(FileNameLength bytes, UTF-16LE)
         * The extra data may be truncated; show whatever chars are available. */
        if (extra_size >= 4) {
            DetailReader exdr(extra_data, extra_size);
            uint32_t fnl = exdr.u32();
            int avail = exdr.size - exdr.pos;
            if (fnl > 0 && avail > 0) {
                int chars = static_cast<int>(std::min(fnl, static_cast<uint32_t>(avail))) / 2;
                if (chars > 0) {
                    std::string name = utf16le_to_utf8(exdr.data + exdr.pos, chars);
                    jb.add_str("Name", name);
                }
            }
        }
    } else if (operation == 25 && sub_op == 35) { /* QueryAttributeTagFile */
        /* extra_data = FILE_ATTRIBUTE_TAG_INFORMATION (8 bytes):
         *   FileAttributes(u32) + ReparseTag(u32) */
        if (extra_size >= 8) {
            DetailReader exdr(extra_data, extra_size);
            uint32_t file_attrs = exdr.u32();
            uint32_t reparse_tag = exdr.u32();
            std::string attrs = format_file_attributes(file_attrs);
            jb.add_str("Attributes", attrs.empty() ? "n/a" : attrs);
            char tag_buf[12];
            std::snprintf(tag_buf, sizeof(tag_buf), "0x%x", reparse_tag);
            jb.add_str("ReparseTag", tag_buf);
        }
    } else if (operation == 40 || operation == 41) { /* QuerySecurityFile / SetSecurityFile */
        /* SECURITY_INFORMATION mask is stored at details_io[0x0C..0x0F].
         * Layout: FileObject(pvoid) + PVOID + u32_unk + SECURITY_INFORMATION(u32) */
        dio.skip(0x08);
        dio.skip(0x04); /* unknown u32 */
        if (dio.has(4)) {
            uint32_t sec_info = dio.u32();
            /* Build comma-separated list of SECURITY_INFORMATION flag names */
            static const struct { uint32_t bit; const char *name; } si_tbl[] = {
                {0x00000001, "Owner"},
                {0x00000002, "Group"},
                {0x00000004, "DACL"},
                {0x00000008, "SACL"},
                {0x00000010, "Label"},
                {0x00000020, "Attribute"},
                {0x00000040, "Scope"},
                {0x00000080, "Process Trust Label"},
                {0x00000100, "Access Filter"},
                {0x00001000, "Backup"},
                {0x00002000, "Protected DACL"},
                {0x00004000, "Protected SACL"},
                {0x00010000, "Unprotected DACL"},
                {0x00020000, "Unprotected SACL"},
            };
            std::string info_str;
            for (auto &e : si_tbl) {
                if (sec_info & e.bit) {
                    if (!info_str.empty()) info_str += ", ";
                    info_str += e.name;
                }
            }
            if (!info_str.empty())
                jb.add_str("Information", info_str);
        }
    }

    return jb.build();
}


/* ================================================================
 * Detail JSON dispatcher (public)
 * ================================================================ */

static std::string extract_profiling_detail_json(
    const uint8_t *detail_data, int detail_size)
{
    /* Process Profiling event detail layout (32 bytes):
     *   UserTime(u64, 100ns ticks)  @ offset 0
     *   KernelTime(u64, 100ns ticks) @ offset 8
     *   WorkingSet(u64, bytes)       @ offset 16
     *   PrivateBytes(u64, bytes)     @ offset 24
     * Display order: User Time, Kernel Time, Private Bytes, Working Set */
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

static std::string extract_network_detail_json(
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
                /* empty string terminates list */
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
                /* TCP Connect (op==5) and Accept (op==4): Procmon omits sndwinscale, seqnum, connid */
                if ((operation == 5 || operation == 4) &&
                    (key == "sndwinscale" || key == "seqnum" || key == "connid"))
                    continue;
                /* Try to parse val as a decimal integer: output as uint to avoid
                 * the comma-formatting that the Python normalizer applies to strings */
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
                /* No completion record (failed op) — infer from disposition.
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
                default: return true;
            }
        }
        case RT_PROCESS_MASK: {
            if (rule.proc_mask_data.empty()) return true;
            if (ed.proc_idx >= rule.proc_mask_data.size())
                return false;
            return rule.proc_mask_data[ed.proc_idx] != 0;
        }
        case RT_OP_REGEX: {
            if (!ed.op_name_resolved) {
                ed.op_name = resolve_op_name(
                    ctx, ed.event_class, ed.operation,
                    ctx.buf, ctx.buf_len, ed.event_offset,
                    ed.stacktrace_depth, ed.details_size);
                ed.op_name_resolved = true;
            }
            if (rule.is_substr)
                return pml_pre::ci_contains(ed.op_name, rule.plain_substr);
            return std::regex_search(ed.op_name, rule.regex);
        }
        case RT_RESULT_REGEX: {
            if (!ed.result_name_resolved) {
                ed.result_name = resolve_result_name(ctx, ed.result_code);
                ed.result_name_resolved = true;
            }
            if (rule.is_substr)
                return pml_pre::ci_contains(ed.result_name, rule.plain_substr);
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
            if (rule.is_substr)
                return pml_pre::ci_contains(ed.path, rule.plain_substr);
            return std::regex_search(ed.path, rule.regex);
        }
        case RT_CATEGORY_REGEX: {
            if (!ed.category_resolved) {
                ed.category = resolve_category(ctx, ed.event_class, ed.operation);
                ed.category_resolved = true;
            }
            if (rule.is_substr)
                return pml_pre::ci_contains(ed.category, rule.plain_substr);
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
            if (rule.is_substr)
                return pml_pre::ci_contains(ed.detail_json, rule.plain_substr);
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
