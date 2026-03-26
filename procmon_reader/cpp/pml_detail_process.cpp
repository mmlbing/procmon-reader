/*
 * pml_detail_process.cpp — Process event detail extraction.
 *
 * Handlers for Process_Defined, Process_Create, Process_Exit,
 * Thread_Create, Thread_Exit, Load_Image, Process_Start, etc.
 */

#include "pml_detail.h"
#include "pml_detail_common.h"

#include <cstdint>
#include <string>


/* ================================================================
 * Process operation handlers
 * ================================================================ */

/* --- Process_Defined (op=0), Process_Create (op=1) --- */
static void handle_process_defined_create(
    const uint8_t *detail_data, int detail_size, JsonBuilder &jb)
{
    DetailReader dr(detail_data, detail_size);
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
}


/* --- Process_Exit (op=2), Process_Statistics (op=8) --- */
static void handle_process_exit_stats(
    const uint8_t *detail_data, int detail_size, JsonBuilder &jb)
{
    DetailReader dr(detail_data, detail_size);
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
}


/* --- Thread_Create (op=3) --- */
static void handle_thread_create(
    const uint8_t *detail_data, int detail_size, JsonBuilder &jb)
{
    DetailReader dr(detail_data, detail_size);
    jb.add_uint("Thread ID", dr.u32());
}


/* --- Thread_Exit (op=4) --- */
static void handle_thread_exit(
    const uint8_t *detail_data, int detail_size,
    uint32_t tid, JsonBuilder &jb)
{
    DetailReader dr(detail_data, detail_size);
    jb.add_uint("Thread ID", tid);
    dr.skip(4);
    uint64_t kernel_ticks = dr.u64();
    uint64_t user_ticks = dr.u64();
    jb.add_str("User Time", format_cpu_ticks(user_ticks));
    jb.add_str("Kernel Time", format_cpu_ticks(kernel_ticks));
}


/* --- Load_Image (op=5) --- */
static void handle_load_image(
    const uint8_t *detail_data, int detail_size, int pvoid_size, JsonBuilder &jb)
{
    DetailReader dr(detail_data, detail_size);
    uint64_t image_base = (pvoid_size == 8) ? dr.u64() : dr.u32();
    uint32_t image_size = dr.u32();
    jb.add_hex("Image Base", image_base);
    jb.add_hex("Image Size", image_size);
}


/* --- Process_Start (op=7) --- */
static void handle_process_start(
    const uint8_t *detail_data, int detail_size, JsonBuilder &jb)
{
    DetailReader dr(detail_data, detail_size);
    uint32_t ppid = dr.u32();
    jb.add_uint("Parent PID", ppid);
    uint16_t cmd_info = dr.u16();
    bool cmd_is_ascii = (cmd_info >> 15) == 1;
    int cmd_count = cmd_info & 0x7FFF;
    uint16_t dir_info = dr.u16();
    bool dir_is_ascii = (dir_info >> 15) == 1;
    int dir_count = dir_info & 0x7FFF;
    uint32_t env_count = dr.u32();

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
}


/* ================================================================
 * Public: extract_process_detail_json
 * ================================================================ */

std::string extract_process_detail_json(
    const uint8_t *detail_data, int detail_size,
    uint16_t operation, uint32_t tid, int pvoid_size)
{
    JsonBuilder jb;

    switch (operation) {
        case 0: case 1:
            handle_process_defined_create(detail_data, detail_size, jb);
            break;
        case 2: case 8:
            handle_process_exit_stats(detail_data, detail_size, jb);
            break;
        case 3:
            handle_thread_create(detail_data, detail_size, jb);
            break;
        case 4:
            handle_thread_exit(detail_data, detail_size, tid, jb);
            break;
        case 5:
            handle_load_image(detail_data, detail_size, pvoid_size, jb);
            break;
        case 7:
            handle_process_start(detail_data, detail_size, jb);
            break;
        default:
            break;
    }

    return jb.build();
}
