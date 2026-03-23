/*
 * pml_types.h — Shared data structures for PML file parsing.
 *
 * Pure C++ data types representing PML file structures:
 * ProcessInfo, ModuleInfo, PmlHeader.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>


/* ================================================================
 * Module information (loaded DLL / image in a process)
 * ================================================================ */

struct PmlModuleInfo {
    uint64_t base_address = 0;
    uint32_t size = 0;
    std::string path;
    std::string version;
    std::string company;
    std::string description;
    uint32_t timestamp = 0;
};


/* ================================================================
 * Process information (from PML process table)
 * ================================================================ */

struct PmlProcessInfo {
    uint32_t process_index = 0;
    uint32_t process_id = 0;
    uint32_t parent_process_id = 0;
    uint32_t parent_process_index = 0;
    uint64_t authentication_id = 0;
    uint32_t session_number = 0;
    uint64_t start_time = 0;
    uint64_t end_time = 0;
    uint32_t is_virtualized = 0;
    bool is_64bit = false;
    std::string integrity;
    std::string user;
    std::string process_name;
    std::string image_path;
    std::string command_line;
    std::string company;
    std::string version;
    std::string description;
    std::vector<PmlModuleInfo> modules;
};


/* ================================================================
 * PML file header (0x3a8 bytes)
 * ================================================================ */

struct PmlHeader {
    static constexpr int SIZE = 0x3A8;

    uint32_t version = 0;
    bool is_64bit = false;
    std::string computer_name;
    std::string system_root;
    uint32_t number_of_events = 0;

    uint64_t events_offset = 0;
    uint64_t events_offsets_array_offset = 0;
    uint64_t process_table_offset = 0;
    uint64_t strings_table_offset = 0;
    uint64_t icon_table_offset = 0;

    uint32_t windows_major_number = 0;
    uint32_t windows_minor_number = 0;
    uint32_t windows_build_number = 0;
    uint32_t windows_build_number_after_decimal = 0;
    std::string service_pack_name;

    uint32_t number_of_logical_processors = 0;
    uint64_t ram_memory_size = 0;
    uint64_t header_size = 0;
    uint64_t hosts_and_ports_tables_offset = 0;
};
