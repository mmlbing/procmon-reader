/*
 * pml_detail_filesystem.cpp — Filesystem event detail extraction.
 *
 * Each filesystem operation (CreateFile, ReadFile, QueryDirectory, etc.)
 * has a dedicated handler function. The public extract_filesystem_detail_json()
 * parses the common detail header and dispatches to the matching handler
 * via a lookup table keyed by (operation, sub_op).
 */

#include "pml_detail.h"
#include "pml_detail_common.h"
#include "pml_enums.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>


/* ================================================================
 * Handler context — parsed common filesystem detail header
 * ================================================================ */

struct FsDetailCtx {
    const uint8_t *detail_data;
    int detail_size;
    const uint8_t *extra_data;
    int extra_size;
    uint8_t sub_op;
    uint16_t operation;
    int details_io_offset;
    int details_io_size;
    bool path_is_ascii;
    int path_count;
    int path_start_pos;
    int after_path_pos;
    int pvoid_size;
    int tz_offset_seconds;
};

using FsHandler = void(*)(const FsDetailCtx &ctx, JsonBuilder &jb);

struct FsOpEntry {
    uint16_t operation;
    int16_t  sub_op;        /* -1 = any sub_op */
    FsHandler handler;
};


/* ================================================================
 * Filesystem operation handlers
 * ================================================================ */

/* --- ReadFile / WriteFile (ops 3, 5, 23, 24) --- */
static void handle_fs_read_write(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dio(ctx.detail_data + ctx.details_io_offset, ctx.details_io_size);
    dio.skip(0x4);
    uint32_t io_flags_and_priority = dio.u32();
    uint32_t io_flags = io_flags_and_priority & 0xe000ff;
    uint32_t priority = (io_flags_and_priority >> 0x11) & 7;
    dio.skip(0x4);
    uint32_t length = dio.u32();
    if (ctx.pvoid_size == 8) dio.skip(4);
    dio.skip(0x4);
    if (ctx.pvoid_size == 8) dio.skip(4);
    int64_t offset = dio.i64();

    char off_buf[32]; std::snprintf(off_buf, sizeof(off_buf), "%lld", (long long)offset);
    jb.add_str("Offset", off_buf);

    if (ctx.extra_size >= 4) {
        DetailReader exdr(ctx.extra_data, ctx.extra_size);
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
}


/* --- CreateFile (op 20) --- */
static void handle_fs_create_file(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dr(ctx.detail_data, ctx.detail_size);
    dr.pos = ctx.after_path_pos;

    uint32_t desired_access = dr.u32();
    jb.add_str("Desired Access", format_file_desired_access(desired_access));
    uint8_t imp_sid_len = dr.u8();
    dr.skip(3);

    DetailReader dio(ctx.detail_data + ctx.details_io_offset, ctx.details_io_size);
    dio.skip(0x10);
    if (ctx.pvoid_size == 8) dio.skip(4);
    uint32_t disp_and_opts = dio.u32();
    uint32_t disposition = disp_and_opts >> 0x18;
    uint32_t options = disp_and_opts & 0xffffff;
    if (ctx.pvoid_size == 8) dio.skip(4);
    uint16_t attributes = dio.u16();
    uint16_t share_mode = dio.u16();

    const char *dn = fs_disposition_name(disposition);
    jb.add_str("Disposition", dn ? dn : std::to_string(disposition));
    jb.add_str("Options", format_file_options(options));
    std::string attr_str = format_file_attributes(attributes);
    if (!attr_str.empty()) jb.add_str("Attributes", attr_str);
    jb.add_str("ShareMode", format_file_share_mode(share_mode));

    dio.skip(0x4 + ctx.pvoid_size * 2);
    uint32_t alloc = dio.u32();
    if (disposition == 1)
        jb.add_str("AllocationSize", "n/a");
    else
        jb.add_uint("AllocationSize", alloc);

    if (imp_sid_len > 0) {
        if (dr.has(imp_sid_len)) {
            std::string sid_name = format_sid_name(dr.data + dr.pos, imp_sid_len);
            if (!sid_name.empty())
                jb.add_str("Impersonating", sid_name);
        }
        dr.skip(imp_sid_len);
    } else if (ctx.extra_size >= 4) {
        DetailReader exdr(ctx.extra_data, ctx.extra_size);
        uint32_t open_result = exdr.u32();
        const char *orn = fs_open_result_name(open_result);
        jb.add_str("OpenResult", orn ? orn : "<unknown>");
    }
}


/* --- CreateFileMapping (op 19) --- */
static void handle_fs_create_file_mapping(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dio(ctx.detail_data + ctx.details_io_offset, ctx.details_io_size);
    dio.skip(0x0C);
    uint32_t sync_type = dio.u32();
    dio.skip(4);
    uint32_t prot_raw  = dio.u32();
    uint32_t prot_info = prot_raw & 0x3FFu;
    const char *stn = sync_type_name(sync_type);
    if (stn) jb.add_str("SyncType", stn);
    else { char tmp[32]; std::snprintf(tmp, sizeof(tmp), "SyncType%u", sync_type); jb.add_str("SyncType", tmp); }
    if (prot_info != 0) {
        jb.add_str("PageProtection", format_section_page_protection(prot_info));
    }
}


/* --- QueryOpen (op 6) --- */
static void handle_fs_query_open(const FsDetailCtx &ctx, JsonBuilder &jb) {
    if (ctx.extra_size < 52) return;
    DetailReader exdr(ctx.extra_data, ctx.extra_size);
    uint64_t creation_time    = exdr.u64();
    uint64_t last_access_time = exdr.u64();
    uint64_t last_write_time  = exdr.u64();
    uint64_t change_time      = exdr.u64();
    uint64_t alloc_size       = exdr.u64();
    uint64_t eof              = exdr.u64();
    uint32_t file_attrs       = exdr.u32();
    jb.add_str("CreationTime",   format_filetime_local(creation_time,    ctx.tz_offset_seconds));
    jb.add_str("LastAccessTime", format_filetime_local(last_access_time, ctx.tz_offset_seconds));
    jb.add_str("LastWriteTime",  format_filetime_local(last_write_time,  ctx.tz_offset_seconds));
    jb.add_str("ChangeTime",     format_filetime_local(change_time,      ctx.tz_offset_seconds));
    jb.add_str("AllocationSize", std::to_string(alloc_size));
    jb.add_str("EndOfFile",      std::to_string(eof));
    std::string attrs = format_file_attributes(file_attrs);
    jb.add_str("FileAttributes", attrs.empty() ? "n/a" : attrs);
}


/* --- FASTIO_MDL_READ_COMPLETE / FASTIO_MDL_WRITE_COMPLETE (ops 2, 4) --- */
static void handle_fs_mdl_complete(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dio(ctx.detail_data + ctx.details_io_offset, ctx.details_io_size);
    dio.skip(12);
    if (dio.has(ctx.pvoid_size)) {
        uint64_t mdl = (ctx.pvoid_size == 8) ? dio.u64() : dio.u32();
        char tmp[24];
        std::snprintf(tmp, sizeof(tmp), "0x%llx", (unsigned long long)mdl);
        jb.add_str("MDL", tmp);
    }
}


/* --- FASTIO_CHECK_IF_POSSIBLE (op 7) --- */
static void handle_fs_check_if_possible(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dio(ctx.detail_data + ctx.details_io_offset, ctx.details_io_size);
    dio.skip(12);
    if (dio.has(8 + 8 + 8 + 4)) {
        int64_t offset = (int64_t)dio.u64();
        int64_t length_val = (int64_t)dio.u64();
        dio.skip(8);
        uint32_t op_flag = dio.u32();
        jb.add_str("Operation", (op_flag == 1) ? "Read" : "Write");
        jb.add_str("Offset", std::to_string(offset));
        jb.add_str("Length", std::to_string(length_val));
    }
}


/* --- FASTIO_ACQUIRE_FOR_MOD_WRITE (op 17) --- */
static void handle_fs_acquire_mod_write(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dr(ctx.detail_data, ctx.detail_size);
    dr.pos = ctx.after_path_pos;
    if (dr.has(4)) {
        uint32_t ending_offset = dr.u32();
        jb.add_str("EndingOffset", std::to_string(ending_offset));
    }
}


/* --- FileSystemControl / DeviceIoControl (ops 33, 34) --- */
static void handle_fs_sys_dev_ioctl(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dio(ctx.detail_data + ctx.details_io_offset, ctx.details_io_size);
    dio.skip(0x8);
    uint32_t write_length = dio.u32();
    uint32_t read_length  = dio.u32();
    if (ctx.pvoid_size == 8) dio.skip(4);
    dio.skip(0x4);
    if (ctx.pvoid_size == 8) dio.skip(4);
    uint32_t ioctl = dio.u32();

    static const struct { uint32_t code; const char *name; } fsctl_tbl[] = {
        {0x10003c, nullptr},
        {0x11c017, "FSCTL_PIPE_TRANSCEIVE"},
        {0x1401a3, "FSCTL_NETWORK_ENUMERATE_CONNECTIONS"},
        {0x1401a7, "FSCTL_NETWORK_GET_CONNECTION_INFO"},
        {0x1401ac, "FSCTL_NETWORK_DELETE_CONNECTION"},
        {0x1401c4, "FSCTL_LMR_GET_HINT_SIZE"},
        {0x1401f0, nullptr},
        {0x140390, "IOCTL_LMR_DISABLE_LOCAL_BUFFERING"},
        {0x144064, nullptr},
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
        {0x90194,  nullptr},
        {0x90240,  "FSCTL_REQUEST_OPLOCK"},
        {0x940cf,  "FSCTL_QUERY_ALLOCATED_RANGES"},
        {0x9c040,  "FSCTL_SET_COMPRESSION"},
    };
    const char *fsctl_name = nullptr;
    bool name_found = false;
    for (auto &e : fsctl_tbl) {
        if (e.code == ioctl) {
            fsctl_name = e.name;
            name_found = true;
            break;
        }
    }
    if (name_found && fsctl_name != nullptr) {
        jb.add_str("Control", fsctl_name);
    } else {
        uint32_t dev_type = ioctl >> 16;
        uint32_t func     = (ioctl >> 2) & 0xFFF;
        uint32_t method   = ioctl & 0x3;
        char tmp[64];
        std::snprintf(tmp, sizeof(tmp), "0x%x (Device:0x%x Function:%u Method: %u)",
                      ioctl, dev_type, func, method);
        jb.add_str("Control", tmp);
    }
    if (ioctl == 0x11c017) {
        jb.add_str("WriteLength", std::to_string(write_length));
        jb.add_str("ReadLength",  std::to_string(read_length));
    }
}


/* --- QueryFullSizeInformationVolume (op 30, sub_op 7) --- */
static void handle_fs_query_full_size_vol(const FsDetailCtx &ctx, JsonBuilder &jb) {
    if (ctx.extra_size < 32) return;
    DetailReader exdr(ctx.extra_data, ctx.extra_size);
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
}


/* --- QueryDeviceInformationVolume (op 30, sub_op 4) --- */
static void handle_fs_query_device_info_vol(const FsDetailCtx &ctx, JsonBuilder &jb) {
    if (ctx.extra_size < 8) return;
    DetailReader exdr(ctx.extra_data, ctx.extra_size);
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
}


/* --- QuerySizeInformationVolume (op 30, sub_op 3) --- */
static void handle_fs_query_size_vol(const FsDetailCtx &ctx, JsonBuilder &jb) {
    if (ctx.extra_size < 24) return;
    DetailReader exdr(ctx.extra_data, ctx.extra_size);
    uint64_t total_alloc = exdr.u64();
    uint64_t avail_alloc = exdr.u64();
    uint32_t sectors_per = exdr.u32();
    uint32_t bytes_per   = exdr.u32();
    jb.add_str("TotalAllocationUnits",     std::to_string(total_alloc));
    jb.add_str("AvailableAllocationUnits", std::to_string(avail_alloc));
    jb.add_str("SectorsPerAllocationUnit", std::to_string(sectors_per));
    jb.add_str("BytesPerSector",           std::to_string(bytes_per));
}


/* --- QueryAttributeInformationVolume (op 30, sub_op 5) --- */
static void handle_fs_query_attribute_vol(const FsDetailCtx &ctx, JsonBuilder &jb) {
    if (ctx.extra_size < 12) return;
    DetailReader exdr(ctx.extra_data, ctx.extra_size);
    uint32_t fs_attrs     = exdr.u32();
    int32_t  max_comp_len = static_cast<int32_t>(exdr.u32());
    uint32_t fs_name_len  = exdr.u32();
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
}


/* --- QueryInformationVolume (op 30, sub_op 1) --- */
static void handle_fs_query_info_vol(const FsDetailCtx &ctx, JsonBuilder &jb) {
    if (ctx.extra_size < 17) return;
    DetailReader exdr(ctx.extra_data, ctx.extra_size);
    uint64_t creation_time   = exdr.u64();
    uint32_t serial_number   = exdr.u32();
    uint32_t label_length    = exdr.u32();
    uint8_t  supports_obj    = exdr.u8();
    exdr.skip(1);
    jb.add_str("VolumeCreationTime", format_filetime_local(creation_time, ctx.tz_offset_seconds, true));
    char sn_buf[12];
    std::snprintf(sn_buf, sizeof(sn_buf), "%04X-%04X",
                  (serial_number >> 16) & 0xFFFF, serial_number & 0xFFFF);
    jb.add_str("VolumeSerialNumber", sn_buf);
    jb.add_bool_str("SupportsObjects", supports_obj != 0);
    if (label_length > 0) {
        int avail = exdr.size - exdr.pos;
        int to_read = static_cast<int>(label_length);
        if (avail > 0) {
            if (to_read > avail) to_read = avail & ~1;
            if (to_read > 0) {
                std::string label = utf16le_to_utf8(exdr.data + exdr.pos, to_read / 2);
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
}


/* --- QueryDirectory (op 32, sub_op 1) --- */
static void handle_fs_query_directory(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dio(ctx.detail_data + ctx.details_io_offset, ctx.details_io_size);
    dio.skip(0x10);
    if (ctx.pvoid_size == 8) dio.skip(4);
    dio.skip(0x4);
    if (ctx.pvoid_size == 8) dio.skip(4);
    uint32_t fi_class = dio.u32();

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
    DetailReader dr(ctx.detail_data, ctx.detail_size);
    dr.pos = ctx.after_path_pos;

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

    /* Parse directory entries from extra_data */
    if (ctx.extra_size > 0 && (fi_class == 1 || fi_class == 2 || fi_class == 3 ||
                                fi_class == 12 || fi_class == 37 || fi_class == 38)) {
        int i = has_filter ? 1 : 0;
        int cur_off = 0;
        DetailReader edir(ctx.extra_data, ctx.extra_size);

        int detail_len;
        int dir_entry_count = 0;
        if (fic_name) {
            detail_len = 20 + 2 + static_cast<int>(strlen(fic_name));
        } else {
            char fi_tmp[16];
            std::snprintf(fi_tmp, sizeof(fi_tmp), "%u", fi_class);
            detail_len = 20 + 2 + static_cast<int>(strlen(fi_tmp));
        }
        if (has_filter) detail_len += 2 + 8 + static_cast<int>(filter_name.size());

        while (true) {
            i++;
            if (cur_off >= ctx.extra_size) break;
            edir.pos = cur_off;
            if (!edir.has(8)) break;
            uint32_t next_off = edir.u32();
            edir.skip(4);
            std::string fname;
            if (fi_class == 12) {
                if (!edir.has(4)) break;
                uint32_t fnl = edir.u32();
                if (fnl > 0 && edir.has(static_cast<int>(fnl)))
                    fname = utf16le_to_utf8(edir.data + edir.pos, static_cast<int>(fnl / 2));
            } else {
                if (!edir.has(56)) break;
                edir.skip(4 * 8);
                edir.skip(8 + 8);
                edir.skip(4);
                uint32_t fnl = edir.u32();
                if (fi_class == 2 || fi_class == 38) {
                    edir.skip(4);
                    if (fi_class == 38) edir.skip(8);
                } else if (fi_class == 3 || fi_class == 37) {
                    edir.skip(4 + 1 + 1 + 24);
                    if (fi_class == 37) { edir.skip(2); edir.skip(8); }
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
}


/* --- NotifyChangeDirectory (op 32, sub_op 2) --- */
static void handle_fs_notify_change_dir(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dio(ctx.detail_data + ctx.details_io_offset, ctx.details_io_size);
    dio.skip(0x10);
    if (ctx.pvoid_size == 8) dio.skip(4);
    uint32_t notify_flags = dio.u32();
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
}


/* ================================================================
 * Shared helper: emit FILE_BASIC_INFORMATION fields
 * ================================================================ */
static void emit_basic_info(DetailReader &r, JsonBuilder &jb, int tz,
                            bool allow_epoch = false) {
    uint64_t creation_time    = r.u64();
    uint64_t last_access_time = r.u64();
    uint64_t last_write_time  = r.u64();
    uint64_t change_time      = r.u64();
    uint32_t file_attrs       = r.u32();
    jb.add_str("CreationTime",   format_filetime_local(creation_time,    tz, allow_epoch));
    jb.add_str("LastAccessTime", format_filetime_local(last_access_time, tz, allow_epoch));
    jb.add_str("LastWriteTime",  format_filetime_local(last_write_time,  tz, allow_epoch));
    jb.add_str("ChangeTime",     format_filetime_local(change_time,      tz, allow_epoch));
    std::string attrs = format_file_attributes(file_attrs);
    jb.add_str("FileAttributes", attrs.empty() ? "n/a" : attrs);
}


/* --- SetBasicInformationFile (op 26, sub_op 0x04) --- */
static void handle_fs_set_basic_info(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dr(ctx.detail_data, ctx.detail_size);
    dr.pos = ctx.after_path_pos;
    if (dr.has(36))
        emit_basic_info(dr, jb, ctx.tz_offset_seconds, true);
}


/* --- LockUnlockFile (op 37) --- */
static void handle_fs_lock_unlock(const FsDetailCtx &ctx, JsonBuilder &jb) {
    int exclusive_off   = ctx.pvoid_size * 4 + 12;
    int byte_offset_off = ctx.pvoid_size * 3 + 4;
    bool exclusive = false;
    bool fail_imm  = false;
    {
        DetailReader dio_flags(ctx.detail_data + ctx.details_io_offset, ctx.details_io_size);
        if (dio_flags.has(exclusive_off + 2)) {
            dio_flags.skip(exclusive_off);
            fail_imm  = (dio_flags.u8() != 0);
            exclusive = (dio_flags.u8() != 0);
        }
    }
    int64_t byte_offset = 0;
    DetailReader dio_lock(ctx.detail_data + ctx.details_io_offset, ctx.details_io_size);
    if (dio_lock.has(byte_offset_off + 8)) {
        dio_lock.skip(byte_offset_off);
        byte_offset = static_cast<int64_t>(dio_lock.u64());
    }
    DetailReader dr(ctx.detail_data, ctx.detail_size);
    dr.pos = ctx.after_path_pos;
    int64_t length_val = dr.has(8) ? static_cast<int64_t>(dr.u64()) : 0;
    if (ctx.sub_op == 1) {
        jb.add_bool_str("Exclusive", exclusive);
    }
    jb.add_str("Offset", std::to_string(byte_offset));
    jb.add_str("Length", std::to_string(length_val));
    if (ctx.sub_op == 1) {
        jb.add_bool_str("Fail Immediately", fail_imm);
    }
}


/* --- SetAllocationInformationFile (op 26, sub_op 0x13) --- */
static void handle_fs_set_allocation(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dr(ctx.detail_data, ctx.detail_size);
    dr.pos = ctx.after_path_pos;
    if (dr.has(8)) {
        int64_t alloc = static_cast<int64_t>(dr.u64());
        jb.add_str("AllocationSize", std::to_string(alloc));
    }
}


/* --- SetEndOfFileInformationFile (op 26, sub_op 0x14) --- */
static void handle_fs_set_eof(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dr(ctx.detail_data, ctx.detail_size);
    dr.pos = ctx.after_path_pos;
    if (dr.has(8)) {
        int64_t eof = static_cast<int64_t>(dr.u64());
        jb.add_str("EndOfFile", std::to_string(eof));
    }
}


/* --- SetRenameInformationFile / SetLinkInformationFile
 *     (op 26, sub_op 0x0a/0x41/0x42/0x0b) --- */
static void handle_fs_set_rename_link(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dr(ctx.detail_data, ctx.detail_size);
    dr.pos = ctx.after_path_pos;
    if (dr.has(1)) {
        bool replace = (dr.u8() != 0);
        jb.add_bool_str("ReplaceIfExists", replace);
        int pad = (ctx.pvoid_size == 8) ? 7 : 3;
        dr.skip(pad);
        dr.skip(ctx.pvoid_size);
        if (dr.has(4)) {
            uint32_t fnl = dr.u32();
            if (fnl > 0 && dr.has(static_cast<int>(fnl))) {
                std::string fname = utf16le_to_utf8(dr.data + dr.pos, static_cast<int>(fnl / 2));
                if (!fname.empty() && fname[0] != '\\') {
                    std::string src_path;
                    if (ctx.path_is_ascii && ctx.path_count > 0 &&
                        ctx.path_start_pos + ctx.path_count <= ctx.detail_size) {
                        src_path = std::string(
                            reinterpret_cast<const char*>(ctx.detail_data + ctx.path_start_pos),
                            static_cast<size_t>(ctx.path_count));
                    } else if (!ctx.path_is_ascii && ctx.path_count > 0) {
                        src_path = utf16le_to_utf8(ctx.detail_data + ctx.path_start_pos, ctx.path_count);
                    }
                    size_t last_bs = src_path.rfind('\\');
                    if (last_bs != std::string::npos)
                        fname = src_path.substr(0, last_bs + 1) + fname;
                }
                jb.add_str("FileName", fname);
            }
        }
    }
}


/* --- SetDispositionInformationFile (op 26, sub_op 0x0d) --- */
static void handle_fs_set_disposition(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dr(ctx.detail_data, ctx.detail_size);
    dr.pos = ctx.after_path_pos;
    bool is_delete = (dr.u8() != 0);
    jb.add_bool_str("Delete", is_delete);
}


/* --- SetDispositionInformationEx (op 26, sub_op 0x40) --- */
static void handle_fs_set_disposition_ex(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dr(ctx.detail_data, ctx.detail_size);
    dr.pos = ctx.after_path_pos;
    uint32_t flags = dr.u32();
    bool is_delete = (flags & 0x1) != 0;
    jb.add_bool_str("Delete", is_delete);
}


/* --- QueryBasicInformationFile (op 25, sub_op 4) --- */
static void handle_fs_query_basic_info(const FsDetailCtx &ctx, JsonBuilder &jb) {
    if (ctx.extra_size < 36) return;
    DetailReader exdr(ctx.extra_data, ctx.extra_size);
    emit_basic_info(exdr, jb, ctx.tz_offset_seconds);
}


/* --- QueryAllInformationFile (op 25, sub_op 0x12) --- */
static void handle_fs_query_all_info(const FsDetailCtx &ctx, JsonBuilder &jb) {
    if (ctx.extra_size < 56) return;
    DetailReader exdr(ctx.extra_data, ctx.extra_size);
    uint64_t creation_time    = exdr.u64();
    uint64_t last_access_time = exdr.u64();
    uint64_t last_write_time  = exdr.u64();
    uint64_t change_time      = exdr.u64();
    uint32_t file_attrs       = exdr.u32();
    exdr.skip(4);
    uint64_t alloc_size       = exdr.u64();
    uint64_t eof              = exdr.u64();
    jb.add_str("CreationTime",    format_filetime_local(creation_time,    ctx.tz_offset_seconds));
    jb.add_str("LastAccessTime",  format_filetime_local(last_access_time, ctx.tz_offset_seconds));
    jb.add_str("LastWriteTime",   format_filetime_local(last_write_time,  ctx.tz_offset_seconds));
    jb.add_str("ChangeTime",      format_filetime_local(change_time,      ctx.tz_offset_seconds));
    std::string attrs = format_file_attributes(file_attrs);
    jb.add_str("FileAttributes",  attrs.empty() ? "n/a" : attrs);
    jb.add_str("AllocationSize",  std::to_string(alloc_size));
    jb.add_str("EndOfFile",       std::to_string(eof));
}


/* --- QueryStandardInformationFile (op 25, sub_op 5) --- */
static void handle_fs_query_standard_info(const FsDetailCtx &ctx, JsonBuilder &jb) {
    if (ctx.extra_size < 18) return;
    DetailReader exdr(ctx.extra_data, ctx.extra_size);
    uint64_t alloc_size = exdr.u64();
    uint64_t eof        = exdr.u64();
    uint32_t num_links  = exdr.u32();
    uint8_t  del_pend   = exdr.u8();
    uint8_t  is_dir     = exdr.u8();
    jb.add_str("AllocationSize", std::to_string(alloc_size));
    jb.add_str("EndOfFile",      std::to_string(eof));
    jb.add_str("NumberOfLinks",  std::to_string(num_links));
    jb.add_bool_str("DeletePending", del_pend != 0);
    jb.add_bool_str("Directory",     is_dir != 0);
}


/* --- QueryFileInternalInformationFile (op 25, sub_op 6) --- */
static void handle_fs_query_internal_info(const FsDetailCtx &ctx, JsonBuilder &jb) {
    if (ctx.extra_size < 8) return;
    DetailReader exdr(ctx.extra_data, ctx.extra_size);
    uint64_t idx = exdr.u64();
    char tmp[24];
    std::snprintf(tmp, sizeof(tmp), "0x%llx", (unsigned long long)idx);
    jb.add_str("IndexNumber", tmp);
}


/* --- QueryNetworkOpenInformationFile (op 25, sub_op 0x22) --- */
static void handle_fs_query_network_open_info(const FsDetailCtx &ctx, JsonBuilder &jb) {
    if (ctx.extra_size < 52) return;
    DetailReader exdr(ctx.extra_data, ctx.extra_size);
    uint64_t creation_time    = exdr.u64();
    uint64_t last_access_time = exdr.u64();
    uint64_t last_write_time  = exdr.u64();
    uint64_t change_time      = exdr.u64();
    uint64_t alloc_size       = exdr.u64();
    uint64_t eof              = exdr.u64();
    uint32_t file_attrs       = exdr.u32();
    int tz = ctx.tz_offset_seconds;
    jb.add_str("CreationTime",   format_filetime_local(creation_time,    tz));
    jb.add_str("LastAccessTime", format_filetime_local(last_access_time, tz));
    jb.add_str("LastWriteTime",  format_filetime_local(last_write_time,  tz));
    jb.add_str("ChangeTime",     format_filetime_local(change_time,      tz));
    jb.add_str("AllocationSize", format_filetime_local(alloc_size, tz, true));
    jb.add_str("EndOfFile",      format_filetime_local(eof,        tz, true));
    std::string attrs = format_file_attributes(file_attrs);
    jb.add_str("FileAttributes", attrs.empty() ? "n/a" : attrs);
}


/* --- QueryNameInformationFile (op 25, sub_op 9) --- */
static void handle_fs_query_name_info(const FsDetailCtx &ctx, JsonBuilder &jb) {
    if (ctx.extra_size < 4) return;
    DetailReader exdr(ctx.extra_data, ctx.extra_size);
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


/* --- QueryAttributeTagFile (op 25, sub_op 35 = 0x23) --- */
static void handle_fs_query_attribute_tag(const FsDetailCtx &ctx, JsonBuilder &jb) {
    if (ctx.extra_size < 8) return;
    DetailReader exdr(ctx.extra_data, ctx.extra_size);
    uint32_t file_attrs = exdr.u32();
    uint32_t reparse_tag = exdr.u32();
    std::string attrs = format_file_attributes(file_attrs);
    jb.add_str("Attributes", attrs.empty() ? "n/a" : attrs);
    char tag_buf[12];
    std::snprintf(tag_buf, sizeof(tag_buf), "0x%x", reparse_tag);
    jb.add_str("ReparseTag", tag_buf);
}


/* --- QuerySecurityFile (op 40), SetSecurityFile (op 41) --- */
static void handle_fs_query_set_security(const FsDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dio(ctx.detail_data + ctx.details_io_offset, ctx.details_io_size);
    dio.skip(0x08);
    dio.skip(0x04);
    if (dio.has(4)) {
        uint32_t sec_info = dio.u32();
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


/* ================================================================
 * Handler dispatch table
 * ================================================================ */

static const FsOpEntry fs_handlers[] = {
    /* Entries with specific sub_op MUST come before entries with sub_op=-1
     * for the same operation number (though in practice there is no overlap). */

    /* QueryVolumeInformation (op 30) sub-operations */
    {30,  7, handle_fs_query_full_size_vol},
    {30,  4, handle_fs_query_device_info_vol},
    {30,  3, handle_fs_query_size_vol},
    {30,  5, handle_fs_query_attribute_vol},
    {30,  1, handle_fs_query_info_vol},

    /* DirectoryControl (op 32) sub-operations */
    {32,  1, handle_fs_query_directory},
    {32,  2, handle_fs_notify_change_dir},

    /* SetInformationFile (op 26) sub-operations */
    {26,  0x04, handle_fs_set_basic_info},
    {26,  0x13, handle_fs_set_allocation},
    {26,  0x14, handle_fs_set_eof},
    {26,  0x0a, handle_fs_set_rename_link},
    {26,  0x41, handle_fs_set_rename_link},
    {26,  0x42, handle_fs_set_rename_link},
    {26,  0x0b, handle_fs_set_rename_link},
    {26,  0x0d, handle_fs_set_disposition},
    {26,  0x40, handle_fs_set_disposition_ex},

    /* QueryInformationFile (op 25) sub-operations */
    {25,  4,    handle_fs_query_basic_info},
    {25,  0x12, handle_fs_query_all_info},
    {25,  5,    handle_fs_query_standard_info},
    {25,  6,    handle_fs_query_internal_info},
    {25,  0x22, handle_fs_query_network_open_info},
    {25,  9,    handle_fs_query_name_info},
    {25,  0x23, handle_fs_query_attribute_tag},

    /* Operations keyed by operation alone (sub_op = -1 = any) */
    {23, -1, handle_fs_read_write},
    {24, -1, handle_fs_read_write},
    { 5, -1, handle_fs_read_write},
    { 3, -1, handle_fs_read_write},
    {20, -1, handle_fs_create_file},
    {19, -1, handle_fs_create_file_mapping},
    { 6, -1, handle_fs_query_open},
    { 2, -1, handle_fs_mdl_complete},
    { 4, -1, handle_fs_mdl_complete},
    { 7, -1, handle_fs_check_if_possible},
    {17, -1, handle_fs_acquire_mod_write},
    {33, -1, handle_fs_sys_dev_ioctl},
    {34, -1, handle_fs_sys_dev_ioctl},
    {37, -1, handle_fs_lock_unlock},
    {40, -1, handle_fs_query_set_security},
    {41, -1, handle_fs_query_set_security},
};

static constexpr int FS_HANDLER_COUNT = sizeof(fs_handlers) / sizeof(fs_handlers[0]);


/* ================================================================
 * Public: extract_filesystem_detail_json
 * ================================================================ */

std::string extract_filesystem_detail_json(
    const uint8_t *detail_data, int detail_size,
    uint16_t operation,
    const uint8_t *extra_data, int extra_size,
    int pvoid_size, int tz_offset_seconds)
{
    DetailReader dr(detail_data, detail_size);
    JsonBuilder jb;

    /* Parse common filesystem detail header */
    uint8_t sub_op = dr.u8();
    dr.skip(3);

    int details_io_offset = dr.pos;  /* always 4 */
    int details_io_size = pvoid_size * 5 + 0x14;
    dr.skip(details_io_size);

    uint16_t path_info = dr.u16();
    dr.skip(2);
    bool path_is_ascii = (path_info >> 15) == 1;
    int path_count = path_info & 0x7FFF;
    int path_start_pos = dr.pos;
    dr.skip(path_is_ascii ? path_count : path_count * 2);
    int after_path_pos = dr.pos;

    /* Build context */
    FsDetailCtx ctx{
        detail_data, detail_size,
        extra_data, extra_size,
        sub_op, operation,
        details_io_offset, details_io_size,
        path_is_ascii, path_count,
        path_start_pos, after_path_pos,
        pvoid_size, tz_offset_seconds
    };

    /* Dispatch to handler */
    for (int i = 0; i < FS_HANDLER_COUNT; i++) {
        const FsOpEntry &e = fs_handlers[i];
        if (e.operation == operation && (e.sub_op < 0 || e.sub_op == sub_op)) {
            e.handler(ctx, jb);
            break;
        }
    }

    return jb.build();
}
