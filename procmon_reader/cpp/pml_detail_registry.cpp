/*
 * pml_detail_registry.cpp — Registry event detail extraction.
 *
 * Each registry operation (RegOpenKey, RegCreateKey, RegQueryValue, etc.)
 * has a dedicated handler function. The public extract_registry_detail_json()
 * dispatches to the appropriate handler via a switch.
 */

#include "pml_detail.h"
#include "pml_detail_common.h"
#include "pml_enums.h"

#include <cctype>
#include <cstdint>
#include <string>


/* ================================================================
 * Internal helpers
 * ================================================================ */

static std::string format_reg_type_str(const char *tn, uint32_t rtype) {
    if (tn) return tn;
    return "<Unknown: " + std::to_string(rtype) + ">";
}

/* Read registry data from extra detail and add to JSON builder */
static void read_reg_data(DetailReader &dr, JsonBuilder &jb,
                          uint32_t reg_type, uint32_t length,
                          int multi_sz_entry_limit = 0x7FFFFFFF) {
    const char *tname = reg_type_name(reg_type);
    if (!tname) { jb.add_str("Data", ""); return; }
    if (length == 0) return;

    if (reg_type == 4 /* REG_DWORD */ && length >= 4) {
        jb.add_uint("Data", dr.u32());
    } else if (reg_type == 11 /* REG_QWORD */ && length >= 8) {
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
                        if (!joined.empty()) joined += ", ";
                    } else if (segment_len > 0) {
                        if (!joined.empty()) joined += ", ";
                        joined += utf16le_to_utf8(p + start * 2, segment_len);
                    } else if (next_start < chars) {
                        if (!joined.empty()) joined += ", ";
                    }
                    start = next_start;
                }
            }
            while (joined.size() >= 2 &&
                   joined.back() == ' ' && joined[joined.size()-2] == ',')
                joined.resize(joined.size() - 2);
            jb.add_str("Data", joined);
        }
    } else if (reg_type == 3 /* REG_BINARY */) {
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
 * Handler context — passed to all registry handlers
 * ================================================================ */

struct RegDetailCtx {
    DetailReader &dr;          /* positioned after path_info u16 */
    const uint8_t *extra_data;
    int extra_size;
    int extra_buf_avail;
    bool path_is_ascii;
    int path_count;
    uint16_t operation;
};


/* ================================================================
 * Registry operation handlers
 * ================================================================ */

/* --- RegOpenKey (op=0), RegCreateKey (op=1) --- */
static void handle_reg_open_create(RegDetailCtx &ctx, JsonBuilder &jb) {
    ctx.dr.skip(2);
    uint32_t desired_access = ctx.dr.u32();

    /* Skip path string */
    ctx.dr.skip(ctx.path_is_ascii ? ctx.path_count : ctx.path_count * 2);

    jb.add_str("Desired Access", get_reg_access_mask_string(desired_access));

    if (ctx.extra_size >= 8) {
        DetailReader exdr(ctx.extra_data, ctx.extra_size);
        uint32_t granted     = exdr.u32();
        uint32_t disposition = exdr.u32();
        static const uint32_t MAXIMUM_ALLOWED = 0x02000000;
        if (desired_access == MAXIMUM_ALLOWED && granted != desired_access)
            jb.add_str("Granted Access", get_reg_access_mask_string(granted));
        const char *dn = reg_disposition_name(disposition);
        if (dn) jb.add_str("Disposition", dn);
    } else if (ctx.extra_size >= 4) {
        DetailReader exdr(ctx.extra_data, ctx.extra_size);
        uint32_t disposition = exdr.u32();
        const char *dn = reg_disposition_name(disposition);
        if (dn) jb.add_str("Disposition", dn);
    }
}


/* --- RegQueryValue (op=5), RegEnumValue (op=6) --- */
static void handle_reg_query_enum_value(RegDetailCtx &ctx, JsonBuilder &jb) {
    ctx.dr.skip(2);
    uint32_t length     = ctx.dr.u32();
    uint32_t info_class = ctx.dr.u32();
    uint32_t index_val  = 0;

    if (ctx.operation == 6) {
        /* Re-read: op 6 layout is skip(2)+length(u32)+index(u32)+info_class(u32) */
        /* Undo the last two reads and re-parse correctly */
    }

    /* Actually, ops 5 and 6 have different pre-path layouts.
     * op 5: skip(2)+length(u32)+info_class(u32)
     * op 6: skip(2)+length(u32)+index(u32)+info_class(u32)
     * Since we already read from the stream, we need to handle this carefully.
     * We re-create a reader from the original position. */

    /* Start over from the correct position */
    /* The parent already read path_info (2 bytes), so dr.pos = 2.
     * Re-read the pre-path fields properly. */
    DetailReader dr2(ctx.dr.data, ctx.dr.size);
    dr2.pos = 2; /* after path_info */
    dr2.skip(2); /* padding */
    length = dr2.u32();

    if (ctx.operation == 6) {
        index_val  = dr2.u32();
    }
    info_class = dr2.u32();

    /* Compute is_hku_default from path content */
    bool is_hku_default = false;
    {
        int path_bytes = ctx.path_is_ascii ? ctx.path_count : ctx.path_count * 2;
        if (ctx.path_count > 0 && dr2.has(path_bytes)) {
            std::string p;
            if (ctx.path_is_ascii)
                p.assign(reinterpret_cast<const char*>(dr2.data + dr2.pos), ctx.path_count);
            else
                p = utf16le_to_utf8(dr2.data + dr2.pos, ctx.path_count);
            std::string lower;
            lower.reserve(p.size());
            for (unsigned char c : p)
                lower.push_back(static_cast<char>(tolower(c)));
            is_hku_default = (lower.find(".default") != std::string::npos);
        }
    }

    /* Skip path string */
    dr2.skip(ctx.path_is_ascii ? ctx.path_count : ctx.path_count * 2);

    /* Build JSON */
    DetailReader exdr(ctx.extra_data, ctx.extra_size);

    if (ctx.operation == 6) jb.add_str("Index", std::to_string(index_val));

    if (ctx.extra_size > 0) {
        if (!exdr.has(12)) return;
        exdr.skip(4);                      /* TitleIndex */
        uint32_t rtype = exdr.u32();       /* Type */
        const char *tn = reg_type_name(rtype);

        if (info_class == 1) {
            /* KeyValueFullInformation */
            if (!exdr.has(12)) return;
            uint32_t data_offset   = exdr.u32();
            uint32_t data_length   = exdr.u32();
            uint32_t name_len_bytes = exdr.u32();

            bool has_exact_fit = (static_cast<uint32_t>(ctx.extra_size) ==
                                  data_offset + data_length);
            bool show_data;
            if (data_length == 0 || data_offset >= static_cast<uint32_t>(ctx.extra_size)) {
                show_data = false;
            } else if (ctx.operation == 6 && rtype == 7) {
                show_data = true;
            } else if (ctx.operation == 6 && rtype == 2) {
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

            if (show_data && !has_exact_fit && rtype == 2) {
                uint32_t pad_off = data_offset + data_length;
                uint32_t pad_end = static_cast<uint32_t>(ctx.extra_size);
                if (pad_end - pad_off == 2 &&
                    ctx.extra_data[pad_off] == 0xFF && ctx.extra_data[pad_off + 1] == 0xFF)
                    show_data = false;
            }

            size_t data_est = 0;
            if (show_data) {
                if (rtype == 3)
                    data_est = (size_t)data_length * 3;
                else if (rtype == 4)
                    data_est = 10;
                else if (rtype == 11)
                    data_est = 0;
                else if (rtype == 7)
                    data_est = (data_length > 4) ? (data_length - 4) / 2 : 0;
                else
                    data_est = (data_length > 2) ? (data_length - 2) / 2 : 0;
            }

            if (name_len_bytes > 0 && exdr.has(static_cast<int>(name_len_bytes))) {
                if (ctx.operation == 6) {
                    std::string name_str = utf16le_to_utf8(exdr.data + exdr.pos,
                                           static_cast<int>(name_len_bytes / 2));
                    if (rtype == 7) {
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
            } else if (ctx.operation == 6) {
                jb.add_str("Name", "");
            }
            jb.add_str("Type", format_reg_type_str(tn, rtype));
            jb.add_str("Length", std::to_string(data_length));
            if (show_data) {
                int read_cap = ctx.extra_size - 24;
                int to_show = (static_cast<uint32_t>(read_cap) < data_length)
                              ? read_cap : static_cast<int>(data_length);
                int ext_avail = (ctx.extra_buf_avail > 0)
                                ? (ctx.extra_buf_avail - static_cast<int>(data_offset))
                                : (ctx.extra_size - static_cast<int>(data_offset));
                int avail = std::min(to_show, ext_avail);
                if (avail > 0) {
                    DetailReader data_dr(ctx.extra_data + data_offset, avail);
                    int msz_limit = (ctx.operation == 6) ? 48 : 0x7FFFFFFF;
                    read_reg_data(data_dr, jb, rtype, avail, msz_limit);
                }
            } else {
                jb.add_str("Data", "");
            }
        } else {
            /* KeyValuePartialInformation (info_class==2) and others */
            jb.add_str("Type", format_reg_type_str(tn, rtype));
            if (info_class == 2 || ctx.operation == 5) {
                uint32_t dl = exdr.u32();
                jb.add_str("Length", std::to_string(dl));
                int avail_after = exdr.size - exdr.pos;
                bool is_truncated = (static_cast<uint32_t>(avail_after) < dl);
                bool partial_exact_fit = (static_cast<uint32_t>(avail_after) == dl);
                bool partial_show;
                if (rtype == 7) {
                    partial_show = true;
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
}


/* --- RegQueryKey (op=3), RegEnumKey (op=7) --- */
static void handle_reg_query_enum_key(RegDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dr2(ctx.dr.data, ctx.dr.size);
    dr2.pos = 2; /* after path_info */
    dr2.skip(2); /* padding */

    uint32_t length = dr2.u32();
    uint32_t index_val = 0;
    uint32_t info_class;

    if (ctx.operation == 7) {
        index_val  = dr2.u32();
        info_class = dr2.u32();
    } else {
        info_class = dr2.u32();
    }

    /* Skip path string */
    dr2.skip(ctx.path_is_ascii ? ctx.path_count : ctx.path_count * 2);

    DetailReader exdr(ctx.extra_data, ctx.extra_size);

    if (ctx.operation == 7) {
        jb.add_str("Index", std::to_string(index_val));
    } else {
        const char *qn = reg_key_info_class_name(info_class);
        if (qn) jb.add_str("Query", qn);
    }

    if (ctx.extra_size > 0 && ctx.operation == 7) {
        auto read_name = [&](DetailReader &r, int skip_prefix) {
            if (!r.has(skip_prefix + 4)) return;
            r.skip(skip_prefix);
            uint32_t nsz = r.u32();
            if (nsz > 0 && r.has(static_cast<int>(nsz)))
                jb.add_str("Name", utf16le_to_utf8(r.data + r.pos, static_cast<int>(nsz / 2)));
        };
        if (info_class == 0) {
            read_name(exdr, 8 + 4);
        } else if (info_class == 1) {
            read_name(exdr, 8 + 4 + 4 + 4);
        } else if (info_class == 3) {
            read_name(exdr, 0);
        } else {
            jb.add_str("Length", std::to_string(length));
        }
    } else if (ctx.extra_size > 0 && ctx.operation == 3) {
        auto read_name = [&](DetailReader &r, int skip_prefix) {
            if (!r.has(skip_prefix + 4)) return;
            r.skip(skip_prefix);
            uint32_t nsz = r.u32();
            if (nsz > 0 && r.has(static_cast<int>(nsz)))
                jb.add_str("Name", utf16le_to_utf8(r.data + r.pos, static_cast<int>(nsz / 2)));
        };
        if (info_class == 0) {
            read_name(exdr, 8 + 4);
        } else if (info_class == 1) {
            read_name(exdr, 8 + 4 + 4 + 4);
        } else if (info_class == 2) {
            if (exdr.has(28)) {
                exdr.skip(16);
                exdr.skip(4);
                uint32_t sub_keys = exdr.u32();
                exdr.skip(4);
                exdr.skip(4);
                uint32_t values   = exdr.u32();
                jb.add_uint("SubKeys", sub_keys);
                jb.add_uint("Values",  values);
            }
        } else if (info_class == 4) {
            if (exdr.has(20)) {
                exdr.skip(12);
                uint32_t sub_keys = exdr.u32();
                exdr.skip(4);
                uint32_t values   = exdr.u32();
                jb.add_uint("SubKeys", sub_keys);
                jb.add_uint("Values",  values);
            }
        } else if (info_class == 7) {
            jb.add_hex("HandleTags", exdr.u32());
        } else if (info_class == 5) {
            jb.add_hex("UserFlags", exdr.u32());
        }
    } else if (ctx.operation == 7) {
        jb.add_str("Length", std::to_string(length));
    } else if (ctx.operation == 3) {
        if (info_class <= 7)
            jb.add_str("Length", std::to_string(length));
    }
}


/* --- RegSetValue (op=4) --- */
static void handle_reg_set_value(RegDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dr2(ctx.dr.data, ctx.dr.size);
    dr2.pos = 2;
    dr2.skip(2);
    uint32_t reg_type_val = dr2.u32();
    uint32_t length       = dr2.u32();
    uint32_t data_length  = dr2.u16();
    dr2.skip(2);

    /* Skip path string */
    dr2.skip(ctx.path_is_ascii ? ctx.path_count : ctx.path_count * 2);

    const char *tn = reg_type_name(reg_type_val);
    jb.add_str("Type", format_reg_type_str(tn, reg_type_val));
    jb.add_str("Length", std::to_string(length));

    DetailReader exdr(ctx.extra_data, ctx.extra_size);
    bool data_emitted = false;
    if (tn && ctx.extra_size > 0) {
        uint32_t read_len = std::min(length, data_length);
        if (read_len > 0) { read_reg_data(exdr, jb, reg_type_val, read_len); data_emitted = true; }
    } else if (tn && dr2.has(1)) {
        uint32_t read_len = std::min(length, data_length);
        if (read_len > 0) { read_reg_data(dr2, jb, reg_type_val, read_len); data_emitted = true; }
    }
    if (!data_emitted && tn && length > 0) jb.add_str("Data", "");
}


/* --- RegSetInfoKey (op=8) --- */
static void handle_reg_set_info_key(RegDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dr2(ctx.dr.data, ctx.dr.size);
    dr2.pos = 2;
    dr2.skip(2);
    uint32_t info_class = dr2.u32();
    dr2.skip(4);
    uint16_t set_info_length = dr2.u16();
    dr2.skip(2);

    /* Skip path string */
    dr2.skip(ctx.path_is_ascii ? ctx.path_count : ctx.path_count * 2);

    const char *cn = reg_set_info_class_name(info_class);
    jb.add_str("KeySetInformationClass", cn ? cn : "<Unknown>");
    jb.add_uint("Length", set_info_length);

    DetailReader exdr(ctx.extra_data, ctx.extra_size);
    if (ctx.extra_size > 0 && set_info_length > 0) {
        if (info_class == 0) jb.add_uint("LastWriteTime", exdr.u64());
        else if (info_class == 1) jb.add_uint("Wow64Flags", exdr.u32());
        else if (info_class == 5) jb.add_uint("HandleTags", exdr.u32());
    } else if (dr2.has(1) && set_info_length > 0) {
        if (info_class == 0) jb.add_uint("LastWriteTime", dr2.u64());
        else if (info_class == 1) jb.add_uint("Wow64Flags", dr2.u32());
        else if (info_class == 5) jb.add_uint("HandleTags", dr2.u32());
    }
}


/* --- RegRenameKey (op=14) --- */
static void handle_reg_rename_key(RegDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dr2(ctx.dr.data, ctx.dr.size);
    dr2.pos = 2;
    uint16_t ni = dr2.u16();
    bool new_path_is_ascii = (ni >> 15) == 1;
    int new_path_count = ni & 0x7FFF;

    /* Skip path string */
    dr2.skip(ctx.path_is_ascii ? ctx.path_count : ctx.path_count * 2);

    if (new_path_count > 0) {
        int needed = new_path_is_ascii ? new_path_count : new_path_count * 2;
        if (dr2.has(needed)) {
            std::string new_name;
            if (new_path_is_ascii) {
                new_name = std::string(reinterpret_cast<const char*>(dr2.data+dr2.pos),
                                       static_cast<size_t>(new_path_count));
                dr2.skip(new_path_count);
            } else {
                new_name = utf16le_to_utf8(dr2.data+dr2.pos, new_path_count);
                dr2.skip(new_path_count * 2);
            }
            jb.add_str("New Name", new_name);
        }
    }
}


/* --- RegLoadKey (op=12) --- */
static void handle_reg_load_key(RegDetailCtx &ctx, JsonBuilder &jb) {
    DetailReader dr2(ctx.dr.data, ctx.dr.size);
    dr2.pos = 2;
    uint16_t ni = dr2.u16();
    bool new_path_is_ascii = (ni >> 15) == 1;
    int new_path_count = ni & 0x7FFF;

    /* Skip path string */
    dr2.skip(ctx.path_is_ascii ? ctx.path_count : ctx.path_count * 2);

    if (new_path_count > 0) {
        int needed = new_path_is_ascii ? new_path_count : new_path_count * 2;
        if (dr2.has(needed)) {
            std::string hive_path;
            if (new_path_is_ascii) {
                hive_path = std::string(reinterpret_cast<const char*>(dr2.data+dr2.pos),
                                        static_cast<size_t>(new_path_count));
                dr2.skip(new_path_count);
            } else {
                hive_path = utf16le_to_utf8(dr2.data+dr2.pos, new_path_count);
                dr2.skip(new_path_count * 2);
            }
            jb.add_str("Hive Path", hive_path);
        }
    }
}


/* ================================================================
 * Public: extract_registry_detail_json
 * ================================================================ */

std::string extract_registry_detail_json(
    const uint8_t *detail_data, int detail_size,
    uint16_t operation,
    const uint8_t *extra_data, int extra_size,
    int buf_avail)
{
    DetailReader dr(detail_data, detail_size);
    JsonBuilder jb;

    /* Read path_info (first u16) */
    uint16_t path_info; dr.read_path_info(path_info);
    bool path_is_ascii = (path_info >> 15) == 1;
    int path_count = path_info & 0x7FFF;

    RegDetailCtx ctx{dr, extra_data, extra_size, buf_avail,
                     path_is_ascii, path_count, operation};

    switch (operation) {
        case 0: case 1:
            handle_reg_open_create(ctx, jb);
            break;
        case 5: case 6:
            handle_reg_query_enum_value(ctx, jb);
            break;
        case 3: case 7:
            handle_reg_query_enum_key(ctx, jb);
            break;
        case 4:
            handle_reg_set_value(ctx, jb);
            break;
        case 8:
            handle_reg_set_info_key(ctx, jb);
            break;
        case 14:
            handle_reg_rename_key(ctx, jb);
            break;
        case 12:
            handle_reg_load_key(ctx, jb);
            break;
        default:
            break;
    }

    return jb.build();
}
