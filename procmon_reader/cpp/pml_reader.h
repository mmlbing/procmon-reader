/*
 * pml_reader.h — Memory-mapped PML file reader.
 *
 * Parses file header, event offsets, strings table,
 * process table, and hostnames/ports tables.
 */

#pragma once

#include "pml_types.h"
#include "pml_utils.h"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>


/* ================================================================
 * Cross-platform memory-mapped file
 * ================================================================ */

class MmapFile {
public:
    explicit MmapFile(const std::string &path);
    ~MmapFile();

    MmapFile(const MmapFile &) = delete;
    MmapFile &operator=(const MmapFile &) = delete;

    const uint8_t *data() const { return data_; }
    int64_t size() const { return size_; }

private:
    const uint8_t *data_ = nullptr;
    int64_t size_ = 0;

#ifdef _WIN32
    void *file_handle_ = nullptr;
    void *mapping_handle_ = nullptr;
#else
    int fd_ = -1;
#endif
};


/* ================================================================
 * PmlReader — high-level PML file accessor
 * ================================================================ */

class PmlReader {
public:
    explicit PmlReader(const std::string &file_path);
    ~PmlReader() = default;

    PmlReader(const PmlReader &) = delete;
    PmlReader &operator=(const PmlReader &) = delete;

    void close();

    /* --- Header info --- */
    const PmlHeader &header() const { return header_; }
    uint32_t event_count() const { return header_.number_of_events; }
    bool is_64bit() const { return header_.is_64bit; }
    int pvoid_size() const { return header_.is_64bit ? 8 : 4; }

    /* --- Raw mmap access --- */
    const uint8_t *mmap_data() const { return mmap_ ? mmap_->data() : nullptr; }
    int64_t mmap_size() const { return mmap_ ? mmap_->size() : 0; }

    /* --- Event offsets --- */
    const std::vector<int64_t> &event_offsets() const { return event_offsets_; }
    const int64_t *event_offsets_data() const { return event_offsets_.data(); }

    /* --- Process table --- */
    const std::unordered_map<uint32_t, PmlProcessInfo> &process_table() const {
        return processes_;
    }
    const PmlProcessInfo *get_process(uint32_t process_index) const;

    /* --- Hostnames / ports --- */
    const std::unordered_map<std::string, std::string> &hostnames() const {
        return hostnames_;
    }
    const std::unordered_map<uint32_t, std::string> &ports() const {
        return ports_;
    }

private:
    void parse_header();
    void parse_event_offsets();
    void parse_strings_table(std::vector<std::string> &strings);
    void parse_process_table(const std::vector<std::string> &strings);
    void parse_hostnames_and_ports();

    std::unique_ptr<MmapFile> mmap_;
    PmlHeader header_;
    std::vector<int64_t> event_offsets_;
    std::unordered_map<uint32_t, PmlProcessInfo> processes_;
    std::unordered_map<std::string, std::string> hostnames_;
    std::unordered_map<uint32_t, std::string> ports_;
};
