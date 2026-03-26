/*
 * pml_detail.h — PML event detail extraction function declarations.
 *
 * Each function extracts operation-specific detail fields from a PML
 * event's detail section and returns them as a JSON string.
 * Implementations are in separate per-event-class .cpp files.
 */

#pragma once

#include <cstdint>
#include <string>


/* Extract registry event detail as a JSON string. */
std::string extract_registry_detail_json(
    const uint8_t *detail_data, int detail_size,
    uint16_t operation,
    const uint8_t *extra_data, int extra_size,
    int buf_avail = -1);

/* Extract filesystem event detail as a JSON string. */
std::string extract_filesystem_detail_json(
    const uint8_t *detail_data, int detail_size,
    uint16_t operation,
    const uint8_t *extra_data, int extra_size,
    int pvoid_size, int tz_offset_seconds);

/* Extract process event detail as a JSON string. */
std::string extract_process_detail_json(
    const uint8_t *detail_data, int detail_size,
    uint16_t operation, uint32_t tid, int pvoid_size);

/* Extract network event detail as a JSON string. */
std::string extract_network_detail_json(
    const uint8_t *detail_data, int detail_size, uint16_t operation);

/* Extract profiling event detail as a JSON string. */
std::string extract_profiling_detail_json(
    const uint8_t *detail_data, int detail_size);
