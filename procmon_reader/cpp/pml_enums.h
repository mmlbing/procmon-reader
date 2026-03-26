/*
 * pml_enums.h — PML enum lookup tables and bitmask formatters.
 *
 * Centralized enum-to-string tables and bitmask formatting functions
 * for registry types, file access masks, page protection, etc.
 *
 * Header-only; safe to include from multiple translation units.
 */

#pragma once

#include <cstdint>
#include <cstdio>
#include <string>


/* ================================================================
 * Registry enum lookups
 * ================================================================ */

inline const char* reg_type_name(uint32_t typ) {
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

inline const char* reg_key_info_class_name(uint32_t cls) {
    switch (cls) {
        case 0: return "Basic";     case 1: return "Node";
        case 2: return "Full";      case 3: return "Name";
        case 4: return "Cached";    case 5: return "Flags";
        case 6: return "Virtualization"; case 7: return "HandleTags";
        case 8: return "Trust";     case 9: return "Layer";
        default: return nullptr;
    }
}

inline const char* reg_disposition_name(uint32_t d) {
    switch (d) {
        case 1: return "REG_CREATED_NEW_KEY";
        case 2: return "REG_OPENED_EXISTING_KEY";
        default: return nullptr;
    }
}

inline const char* reg_set_info_class_name(uint32_t c) {
    switch (c) {
        case 0: return "KeyWriteTimeInformation";
        case 1: return "KeyWow64FlagsInformation";
        case 5: return "KeySetHandleTagsInformation";
        default: return nullptr;
    }
}


/* ================================================================
 * Filesystem enum lookups
 * ================================================================ */

inline const char* fs_disposition_name(uint32_t d) {
    switch (d) {
        case 0: return "Supersede"; case 1: return "Open";
        case 2: return "Create";    case 3: return "OpenIf";
        case 4: return "Overwrite"; case 5: return "OverwriteIf";
        default: return nullptr;
    }
}

inline const char* fs_open_result_name(uint32_t r) {
    switch (r) {
        case 0: return "Superseded"; case 1: return "Opened";
        case 2: return "Created";    case 3: return "Overwritten";
        case 4: return "Exists";     case 5: return "DoesNotExist";
        default: return nullptr;
    }
}

inline const char* sync_type_name(uint32_t t) {
    switch (t) {
        case 0: return "SyncTypeOther";
        case 1: return "SyncTypeCreateSection";
        case 2: return "SyncTypeCloseSection";
        default: return nullptr;
    }
}


/* ================================================================
 * File Desired Access → Procmon display string
 * ================================================================ */
inline std::string format_file_desired_access(uint32_t mask) {
    if (mask == 0x1F01FFu)  return "All Access";
    if (mask == 0xC0000000u || mask == 0x12019Fu ||
        mask == 0x80120116u || mask == 0x40120089u)
        return "Generic Read/Write";
    if (mask == 0xA0000000u || mask == 0x1200A9u) return "Generic Read/Execute";
    if (mask == 0x80000000u || mask == 0x120089u) return "Generic Read";
    if (mask == 0x40000000u || mask == 0x120116u) return "Generic Write";
    if (mask == 0x20000000u || mask == 0x1200A0u) return "Generic Execute";
    if (mask == 0x10000000u)                      return "Generic All";

    static const struct { uint32_t val; const char *name; } tbl[] = {
        {0xC0000000, "Generic Read/Write"},
        {0x12019F,   "Generic Read/Write"},
        {0x80120116, "Generic Read/Write"},
        {0x40120089, "Generic Read/Write"},
        {0xA0000000, "Generic Read/Execute"},
        {0x1200A9,   "Generic Read/Execute"},
        {0x80000000, "Generic Read"},
        {0x40000000, "Generic Write"},
        {0x20000000, "Generic Execute"},
        {0x10000000, "Generic All"},
        {0x2000000,  "Maximum Allowed"},
        {0x1000000,  "Access System Security"},
        {0x1F01FF,   "All Access"},
        {0x120116,   "Generic Write"},
        {0x120089,   "Generic Read"},
        {0x1200A0,   "Generic Execute"},
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


/* ================================================================
 * File Options → Procmon display string (NtCreateFile CreateOptions)
 * ================================================================ */
inline std::string format_file_options(uint32_t opts) {
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


/* ================================================================
 * File ShareMode → Procmon display string
 * ================================================================ */
inline std::string format_file_share_mode(uint32_t mode) {
    if (mode == 0) return "None";
    std::string r;
    if (mode & 0x1) r = "Read";
    if (mode & 0x2) { if (!r.empty()) r += ", "; r += "Write"; }
    if (mode & 0x4) { if (!r.empty()) r += ", "; r += "Delete"; }
    if (r.empty()) { char tmp[16]; std::snprintf(tmp, sizeof(tmp), "0x%x", mode); return tmp; }
    return r;
}


/* ================================================================
 * File Attributes → Procmon display string
 * ================================================================ */
inline std::string format_file_attributes(uint32_t attr) {
    if (attr == 0) return "n/a";
    std::string r;
    static const struct { uint32_t bit; char letter; } tbl[] = {
        {0x0001, 'R'}, {0x0002, 'H'}, {0x0004, 'S'}, {0x0008, 0},
        {0x0010, 'D'}, {0x0020, 'A'}, {0x0040, 'T'}, {0x0080, 0},
        {0x0100, 0},   {0x0200, 0},   {0x0400, 0},   {0x0800, 'C'},
        {0x1000, 'O'}, {0x2000, 0},   {0x4000, 'E'}, {0x8000, 0},
    };
    for (auto &e : tbl) {
        if (e.letter && (attr & e.bit)) r += e.letter;
    }
    if (attr & 0x80) { if (!r.empty()) r += "N"; else r = "N"; }
    if (attr & 0x2000) r += "NCI";
    if (attr & 0x200) r += "SF";
    if (attr & 0x400) r += "RP";
    if (r.empty()) { char tmp[16]; std::snprintf(tmp, sizeof(tmp), "0x%x", attr); return tmp; }
    return r;
}


/* ================================================================
 * Section page protection formatting
 * ================================================================ */
inline std::string format_section_page_protection(uint32_t prot_info) {
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
    if (prot_info & 0x200u) result += "|PAGE_NOCACHE";
    if (prot_info & 0x400u) result += "|PAGE_WRITECOMBINE";
    return result;
}

inline std::string format_page_protection(uint32_t prot) {
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


/* ================================================================
 * Registry access mask → display string
 * ================================================================ */
inline std::string get_reg_access_mask_string(uint32_t mask) {
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


/* ================================================================
 * I/O Flags → display string
 * ================================================================ */
inline std::string get_io_flags_string(uint32_t flags) {
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


/* ================================================================
 * SID → display name
 * ================================================================ */
inline std::string format_sid_name(const uint8_t *sid, int sid_len) {
    if (sid_len < 8) return {};
    uint8_t revision   = sid[0];
    uint8_t sub_count  = sid[1];
    uint64_t authority = 0;
    for (int i = 0; i < 6; i++) authority = (authority << 8) | sid[2 + i];
    if (sid_len < 8 + sub_count * 4) return {};

    uint32_t subs[8] = {};
    for (uint8_t i = 0; i < sub_count && i < 8; i++) {
        subs[i] = rd_u32(sid + 8 + i * 4);
    }

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
