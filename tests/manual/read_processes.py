#!/usr/bin/env python3
"""
Simple example: list all processes recorded in a PML file.

Usage
-----
    python read_processes.py <pml_file> [name_filter]

Arguments
---------
    pml_file     Path to the .pml capture file.
    name_filter  Optional case-insensitive substring to filter process names.

Examples
--------
    python read_processes.py capture.pml
    python read_processes.py capture.pml chrome
"""

import sys
from pathlib import Path

# Allow running from the tests/ directory without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from procmon_reader import ProcmonReader


def main():
    if len(sys.argv) < 2:
        print("Usage: python read_processes.py <pml_file> [name_filter]")
        sys.exit(1)

    pml_file = sys.argv[1]
    name_filter = sys.argv[2].lower() if len(sys.argv) >= 3 else None

    with ProcmonReader(pml_file) as reader:
        # --- System info ---
        details = reader.system_details()
        print("=== System Details ===")
        for k, v in details.items():
            print(f"  {k}: {v}")
        print()

        # --- Process list ---
        procs = reader.processes()

        # Save to file for debug
        # with open("processes.txt", "w", encoding="utf-8") as f:
        #     for p in procs:
        #         f.write(f"{p}\n")

        if name_filter:
            procs = [p for p in procs if name_filter in p.get("process_name", "").lower()]

        print(f"=== Processes ({len(procs)} total) ===")
        print(f"{'#':<6} {'PID':<7} {'PPID':<7} {'64b':<4} {'Integrity':<12} {'Process Name':<30} {'User'}")
        print("-" * 110)

        for p in procs:
            idx        = p.get("process_index", "")
            pid        = p.get("pid", "")
            ppid       = p.get("parent_pid", "")
            is64       = "Y" if p.get("is_64_bit") else "N"
            integrity  = p.get("integrity", "")
            name       = p.get("process_name", "")
            user       = p.get("user", "")
            print(f"{idx:<6} {pid:<7} {ppid:<7} {is64:<4} {integrity:<12} {name:<30} {user}")

        if name_filter and not procs:
            print(f"  (no processes matching '{name_filter}')")

        print()

        # --- Verbose detail for filtered results ---
        if name_filter and procs:
            print("=== Detail ===")
            for p in procs:
                print(f"  process_index  : {p.get('process_index')}")
                print(f"  pid            : {p.get('pid')}")
                print(f"  parent_pid     : {p.get('parent_pid')}")
                print(f"  process_name   : {p.get('process_name')}")
                print(f"  image_path     : {p.get('image_path')}")
                print(f"  command_line   : {p.get('command_line')}")
                print(f"  user           : {p.get('user')}")
                print(f"  integrity      : {p.get('integrity')}")
                print(f"  is_64_bit      : {p.get('is_64_bit')}")
                print(f"  company        : {p.get('company', '')}")
                print(f"  version        : {p.get('version', '')}")
                print(f"  description    : {p.get('description', '')}")
                print()


if __name__ == "__main__":
    main()
