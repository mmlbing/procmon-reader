"""Generate pml_consts_ntstatus.h from Windows SDK ntstatus.h.

Usage:
    python gen_ntstatus_lut.py <path-to-ntstatus.h> [-o <output-path>]

If -o is not given, writes to ../cpp/pml_consts_ntstatus.h relative to this script.
"""

import argparse
import os
import re

DEFINE_RE = re.compile(
    r'^\s*#define\s+STATUS_(\w+)\s+\(\(NTSTATUS\)0x([0-9A-Fa-f]+)L\)'
)

# Facility codes relevant to Process Monitor (file/reg/net/process operations).
# NTSTATUS layout: [Sev:2][C:1][R:1][Facility:12][Code:16]
# Facility = (code >> 16) & 0x0FFF
PROCMON_FACILITIES = {
    0x000,  # generic / default (covers the vast majority)
    0x007,  # NTWIN32
    0x019,  # TRANSACTION
    0x01A,  # COMMONLOG
    0x01C,  # FILTER_MANAGER
    0x022,  # FWP (Windows Filtering Platform – network)
    0x023,  # NDIS (network)
    0x040,  # RESUME_KEY_FILTER
    0x041,  # RDBSS (redirected file systems / SMB)
    0x05D,  # SMB
}


def _facility(code: int) -> int:
    return (code >> 16) & 0x0FFF


def parse_ntstatus_h(path: str) -> list[tuple[int, str]]:
    # code → (raw_name, index_in_list)
    best: dict[int, tuple[str, int]] = {}
    entries: list[tuple[int, str]] = []

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = DEFINE_RE.match(line)
            if not m:
                continue
            raw = m.group(1)           # e.g. "WAIT_0", "SUCCESS"
            code = int(m.group(2), 16)
            if _facility(code) not in PROCMON_FACILITIES:
                continue
            # For duplicate codes, prefer the name with fewer underscores
            # (e.g. SUCCESS over WAIT_0, ABANDONED over ABANDONED_WAIT_0)
            if code in best:
                prev_raw, idx = best[code]
                if raw.count("_") < prev_raw.count("_"):
                    name = raw.replace("_", " ")
                    entries[idx] = (code, name)
                    best[code] = (raw, idx)
            else:
                name = raw.replace("_", " ")
                best[code] = (raw, len(entries))
                entries.append((code, name))

    entries.sort(key=lambda x: x[0])
    return entries


def emit_header(entries: list[tuple[int, str]]) -> str:
    lines = [
        "#pragma once",
        "",
        "#include <cstdint>",
        "#include <string>",
        "#include <unordered_map>",
        "",
        "/* ================================================================",
        " * Error LUT: NTSTATUS code \u2192 display name",
        " * ================================================================ */",
        "",
        "static inline std::unordered_map<uint32_t, std::string>",
        "build_error_lut() {",
        "    return {",
    ]
    for code, name in entries:
        lines.append(f'        {{0x{code:08x}, "{name}"}},')
    lines.append("    };")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate pml_consts_ntstatus.h from Windows SDK ntstatus.h"
    )
    parser.add_argument("input", help="Path to ntstatus.h")
    parser.add_argument(
        "-o", "--output",
        default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "cpp", "pml_consts_ntstatus.h",
        ),
        help="Output path (default: ../cpp/pml_consts_ntstatus.h)",
    )
    args = parser.parse_args()

    entries = parse_ntstatus_h(args.input)
    header = emit_header(entries)

    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write(header)

    print(f"Wrote {len(entries)} entries to {args.output}")


if __name__ == "__main__":
    main()
