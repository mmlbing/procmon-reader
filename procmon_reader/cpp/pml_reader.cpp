/*
 * pml_reader.cpp — PML file reader implementation.
 */

#include "pml_reader.h"

#include <stdexcept>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif


/* ================================================================
 * MmapFile — cross-platform memory-mapped file
 * ================================================================ */

#ifdef _WIN32

MmapFile::MmapFile(const std::string &path) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    std::wstring wpath(static_cast<size_t>(wlen), 0);
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], wlen);

    HANDLE file = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        throw std::runtime_error("Cannot open file: " + path);

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(file, &file_size)) {
        CloseHandle(file);
        throw std::runtime_error("Cannot get file size: " + path);
    }
    size_ = file_size.QuadPart;

    if (size_ == 0) {
        CloseHandle(file);
        throw std::runtime_error("File is empty: " + path);
    }

    HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping) {
        CloseHandle(file);
        throw std::runtime_error("Cannot create file mapping: " + path);
    }

    data_ = static_cast<const uint8_t *>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
    if (!data_) {
        CloseHandle(mapping);
        CloseHandle(file);
        throw std::runtime_error("Cannot map file: " + path);
    }

    file_handle_ = file;
    mapping_handle_ = mapping;
}

MmapFile::~MmapFile() {
    if (data_) UnmapViewOfFile(data_);
    if (mapping_handle_) CloseHandle(static_cast<HANDLE>(mapping_handle_));
    if (file_handle_) CloseHandle(static_cast<HANDLE>(file_handle_));
}

#else  /* POSIX */

MmapFile::MmapFile(const std::string &path) {
    fd_ = ::open(path.c_str(), O_RDONLY);
    if (fd_ == -1)
        throw std::runtime_error("Cannot open file: " + path);

    struct stat st;
    if (fstat(fd_, &st) == -1) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("Cannot stat file: " + path);
    }
    size_ = st.st_size;

    if (size_ == 0) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("File is empty: " + path);
    }

    void *ptr = ::mmap(nullptr, static_cast<size_t>(size_), PROT_READ, MAP_PRIVATE, fd_, 0);
    if (ptr == MAP_FAILED) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("Cannot mmap file: " + path);
    }
    data_ = static_cast<const uint8_t *>(ptr);
}

MmapFile::~MmapFile() {
    if (data_) ::munmap(const_cast<uint8_t *>(data_), static_cast<size_t>(size_));
    if (fd_ != -1) ::close(fd_);
}

#endif


/* ================================================================
 * PmlReader — construction
 * ================================================================ */

PmlReader::PmlReader(const std::string &file_path) {
    mmap_ = std::make_unique<MmapFile>(file_path);

    parse_header();

    parse_event_offsets();

    std::vector<std::string> strings;
    parse_strings_table(strings);

    parse_process_table(strings);

    /* Strings table no longer needed — let it go out of scope */

    parse_hostnames_and_ports();
}

void PmlReader::close() {
    mmap_.reset();
    event_offsets_.clear();
    processes_.clear();
    hostnames_.clear();
    ports_.clear();
}

const PmlProcessInfo *PmlReader::get_process(uint32_t process_index) const {
    auto it = processes_.find(process_index);
    return (it != processes_.end()) ? &it->second : nullptr;
}


/* ================================================================
 * Header parsing (0x3A8 bytes)
 * ================================================================ */

void PmlReader::parse_header() {
    if (mmap_->size() < PmlHeader::SIZE)
        throw std::runtime_error("File too small to contain a valid PML header.");

    const uint8_t *d = mmap_->data();

    /* Signature check */
    if (std::memcmp(d, "PML_", 4) != 0)
        throw std::runtime_error("Not a Process Monitor backing file (signature missing).");

    header_.version = rd_u32(d + 0x04);
    if (header_.version != 9)
        throw std::runtime_error("PML version " + std::to_string(header_.version) +
                                 " is not supported (only v9).");

    header_.is_64bit = (rd_u32(d + 0x08) != 0);
    header_.computer_name = read_utf16le_fixed(d + 0x0C, 0x20);
    header_.system_root = read_utf16le_fixed(d + 0x2C, 0x208);
    header_.number_of_events = rd_u32(d + 0x234);

    /* 8 bytes unknown at 0x238 */

    header_.events_offset = rd_u64(d + 0x240);
    header_.events_offsets_array_offset = rd_u64(d + 0x248);
    header_.process_table_offset = rd_u64(d + 0x250);
    header_.strings_table_offset = rd_u64(d + 0x258);
    header_.icon_table_offset = rd_u64(d + 0x260);

    /* 12 bytes unknown at 0x268 */

    header_.windows_major_number = rd_u32(d + 0x274);
    header_.windows_minor_number = rd_u32(d + 0x278);
    header_.windows_build_number = rd_u32(d + 0x27C);
    header_.windows_build_number_after_decimal = rd_u32(d + 0x280);
    header_.service_pack_name = read_utf16le_fixed(d + 0x284, 0x32);

    /* 0xD6 bytes unknown at 0x2B6 */

    header_.number_of_logical_processors = rd_u32(d + 0x38C);
    header_.ram_memory_size = rd_u64(d + 0x390);
    header_.header_size = rd_u64(d + 0x398);
    header_.hosts_and_ports_tables_offset = rd_u64(d + 0x3A0);

    /* Validate key offsets */
    if (header_.events_offset == 0 || header_.events_offsets_array_offset == 0 ||
        header_.process_table_offset == 0 || header_.strings_table_offset == 0 ||
        header_.icon_table_offset == 0) {
        throw std::runtime_error(
            "PML was not closed cleanly during capture and is corrupt.");
    }
    if (header_.header_size != static_cast<uint64_t>(PmlHeader::SIZE) ||
        header_.hosts_and_ports_tables_offset == 0) {
        throw std::runtime_error("PML is corrupt and cannot be opened.");
    }
}


/* ================================================================
 * Event offsets array (5 bytes per entry)
 * ================================================================ */

void PmlReader::parse_event_offsets() {
    uint32_t n = header_.number_of_events;
    int64_t start = static_cast<int64_t>(header_.events_offsets_array_offset);
    int64_t needed = static_cast<int64_t>(n) * 5;

    if (start + needed > mmap_->size())
        throw std::runtime_error("Event offsets array extends beyond file.");

    const uint8_t *base = mmap_->data() + start;
    event_offsets_.resize(n);

    constexpr uint64_t u32_max = 0x100000000ULL;
    for (uint32_t i = 0; i < n; i++) {
        int64_t pos = static_cast<int64_t>(i) * 5;
        uint32_t offset_u32 = rd_u32(base + pos);
        uint8_t flags = base[pos + 4];
        event_offsets_[i] = static_cast<int64_t>(
            (static_cast<uint64_t>(flags & 0x01) * u32_max) + offset_u32);
    }
}


/* ================================================================
 * Strings table
 * ================================================================ */

void PmlReader::parse_strings_table(std::vector<std::string> &strings) {
    int64_t start = static_cast<int64_t>(header_.strings_table_offset);
    int64_t end = static_cast<int64_t>(header_.icon_table_offset);
    int64_t data_size = end - start;

    if (start < 0 || data_size <= 4 || start + data_size > mmap_->size())
        throw std::runtime_error("Invalid strings table region.");

    const uint8_t *base = mmap_->data() + start;
    uint32_t num_strings = rd_u32(base);
    int64_t pos = 4;

    /* Read offset array */
    std::vector<uint32_t> offsets(num_strings);
    for (uint32_t i = 0; i < num_strings; i++) {
        if (pos + 4 > data_size) break;
        offsets[i] = rd_u32(base + pos);
        pos += 4;
    }

    /* Read strings */
    strings.resize(num_strings);
    for (uint32_t i = 0; i < num_strings; i++) {
        int64_t str_pos = static_cast<int64_t>(offsets[i]);
        if (str_pos + 4 > data_size) continue;

        uint32_t string_size = rd_u32(base + str_pos);
        str_pos += 4;

        if (string_size == 0 || str_pos + string_size > data_size) continue;

        strings[i] = read_utf16le_bounded(base + str_pos, static_cast<int>(string_size));
    }
}


/* ================================================================
 * Process table
 * ================================================================ */

static std::string rstrip(const std::string &s) {
    auto end = s.find_last_not_of(" \t\r\n\0");
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

static std::string strip(const std::string &s) {
    auto start = s.find_first_not_of(" \t\r\n\0");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n\0");
    return s.substr(start, end - start + 1);
}

static std::string safe_string(const std::vector<std::string> &strings, uint32_t idx) {
    return (idx < strings.size()) ? strings[idx] : "";
}

static PmlModuleInfo read_single_module(
    const uint8_t *data, int64_t data_size, int64_t &pos,
    const std::vector<std::string> &strings,
    int pvoid_size)
{
    PmlModuleInfo mod;

    /* Unknown pvoid field */
    pos += pvoid_size;

    /* base_address */
    if (pvoid_size == 8)
        mod.base_address = (pos + 8 <= data_size) ? rd_u64(data + pos) : 0;
    else
        mod.base_address = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += pvoid_size;

    mod.size = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += 4;

    uint32_t path_idx = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += 4;
    mod.path = safe_string(strings, path_idx);

    uint32_t ver_idx = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += 4;
    mod.version = safe_string(strings, ver_idx);

    uint32_t comp_idx = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += 4;
    mod.company = safe_string(strings, comp_idx);

    uint32_t desc_idx = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += 4;
    mod.description = safe_string(strings, desc_idx);

    mod.timestamp = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += 4;

    /* 0x18 bytes unknown */
    pos += 0x18;

    return mod;
}

static PmlProcessInfo read_single_process(
    const uint8_t *data, int64_t data_size, int64_t pos,
    const std::vector<std::string> &strings,
    int pvoid_size)
{
    PmlProcessInfo pi;

    pi.process_index = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += 4;
    pi.process_id = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += 4;
    pi.parent_process_id = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += 4;
    pi.parent_process_index = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += 4;
    pi.authentication_id = (pos + 8 <= data_size) ? rd_u64(data + pos) : 0;
    pos += 8;
    pi.session_number = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += 4;
    pos += 4; /* Unknown field */
    pi.start_time = (pos + 8 <= data_size) ? rd_u64(data + pos) : 0;
    pos += 8;
    pi.end_time = (pos + 8 <= data_size) ? rd_u64(data + pos) : 0;
    pos += 8;
    pi.is_virtualized = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += 4;
    pi.is_64bit = ((pos + 4 <= data_size) ? rd_u32(data + pos) : 0) != 0;
    pos += 4;

    /* String-indexed fields */
    uint32_t idx;
    idx = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0; pos += 4;
    pi.integrity = rstrip(safe_string(strings, idx));
    idx = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0; pos += 4;
    pi.user = rstrip(safe_string(strings, idx));
    idx = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0; pos += 4;
    pi.process_name = rstrip(safe_string(strings, idx));
    idx = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0; pos += 4;
    pi.image_path = rstrip(safe_string(strings, idx));
    idx = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0; pos += 4;
    pi.command_line = strip(safe_string(strings, idx));
    idx = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0; pos += 4;
    pi.company = rstrip(safe_string(strings, idx));
    idx = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0; pos += 4;
    pi.version = rstrip(safe_string(strings, idx));
    idx = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0; pos += 4;
    pi.description = rstrip(safe_string(strings, idx));

    /* icon_index_small, icon_index_big (not used) */
    pos += 4; pos += 4;

    /* Unknown pvoid field */
    pos += pvoid_size;

    /* Modules */
    uint32_t num_modules = (pos + 4 <= data_size) ? rd_u32(data + pos) : 0;
    pos += 4;
    if (num_modules > 100000) num_modules = 0; /* sanity cap for corrupt files */

    pi.modules.reserve(num_modules);
    for (uint32_t m = 0; m < num_modules; m++) {
        pi.modules.push_back(
            read_single_module(data, data_size, pos, strings, pvoid_size));
    }

    return pi;
}

void PmlReader::parse_process_table(const std::vector<std::string> &strings) {
    int64_t start = static_cast<int64_t>(header_.process_table_offset);
    int64_t end = static_cast<int64_t>(header_.strings_table_offset);
    int64_t data_size = end - start;

    if (start < 0 || data_size <= 4 || start + data_size > mmap_->size())
        throw std::runtime_error("Invalid process table region.");

    const uint8_t *base = mmap_->data() + start;
    int pvoid_size = header_.is_64bit ? 8 : 4;

    uint32_t num_processes = rd_u32(base);
    if (num_processes > 1000000)
        throw std::runtime_error("Corrupt PML: process count too large");
    int64_t pos = 4;

    /* Skip process index array */
    pos += static_cast<int64_t>(num_processes) * 4;

    /* Read process offset array */
    std::vector<uint32_t> offsets(num_processes);
    for (uint32_t i = 0; i < num_processes; i++) {
        if (pos + 4 > data_size) break;
        offsets[i] = rd_u32(base + pos);
        pos += 4;
    }

    /* Parse each process */
    for (uint32_t i = 0; i < num_processes; i++) {
        int64_t proc_pos = static_cast<int64_t>(offsets[i]);
        if (proc_pos >= data_size) continue;

        PmlProcessInfo pi = read_single_process(base, data_size, proc_pos,
                                                strings, pvoid_size);
        processes_[pi.process_index] = std::move(pi);
    }
}


/* ================================================================
 * Hostnames and ports tables
 * ================================================================ */

void PmlReader::parse_hostnames_and_ports() {
    int64_t start = static_cast<int64_t>(header_.hosts_and_ports_tables_offset);
    int64_t total_size = mmap_->size() - start;

    if (start < 0 || total_size <= 4 || start > mmap_->size())
        return; /* Non-fatal: some files may not have these tables */

    const uint8_t *base = mmap_->data() + start;
    int64_t pos = 0;

    /* --- Hostnames table --- */
    if (pos + 4 > total_size) return;
    uint32_t num_hostnames = rd_u32(base + pos);
    pos += 4;
    if (num_hostnames > 1000000) return; /* sanity cap for corrupt files */

    for (uint32_t i = 0; i < num_hostnames; i++) {
        if (pos + 16 > total_size) break;
        std::string ip_key(reinterpret_cast<const char *>(base + pos), 16);
        pos += 16;

        if (pos + 4 > total_size) break;
        uint32_t hostname_len = rd_u32(base + pos);
        pos += 4;

        if (pos + hostname_len > total_size) break;
        std::string hostname = read_utf16le_bounded(base + pos,
                                                    static_cast<int>(hostname_len));
        pos += hostname_len;

        hostnames_[ip_key] = std::move(hostname);
    }

    /* --- Ports table --- */
    if (pos + 4 > total_size) return;
    uint32_t num_ports = rd_u32(base + pos);
    pos += 4;
    if (num_ports > 1000000) return; /* sanity cap for corrupt files */

    for (uint32_t i = 0; i < num_ports; i++) {
        if (pos + 8 > total_size) break;

        uint16_t port_value = rd_u16(base + pos);
        pos += 2;
        bool is_tcp = (rd_u16(base + pos) != 0);
        pos += 2;
        uint32_t port_name_len = rd_u32(base + pos);
        pos += 4;

        if (pos + port_name_len > total_size) break;
        std::string port_name = read_utf16le_bounded(base + pos,
                                                     static_cast<int>(port_name_len));
        pos += port_name_len;

        uint32_t encoded = (static_cast<uint32_t>(port_value) << 1) | (is_tcp ? 1u : 0u);
        ports_[encoded] = std::move(port_name);
    }
}
