#!/usr/bin/env python3
"""
ProcmonReader — system info and PML metadata tests.

Tests system_details() and event_count property
against known values from the test PML file (Logfile.zip).
"""

import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import List, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from procmon_reader import ProcmonReader

PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"

ZIP_PATH = Path(__file__).parent / "res" / "Logfile.zip"


def _extract_pml() -> str:
    with zipfile.ZipFile(str(ZIP_PATH)) as zf:
        pml_names = [n for n in zf.namelist() if n.lower().endswith(".pml")]
        tmpdir = tempfile.mkdtemp(prefix="procmon_test_")
        return zf.extract(pml_names[0], tmpdir)


def _run_test(name: str, func) -> Tuple[str, str, float]:
    t0 = time.perf_counter()
    try:
        result = func()
        elapsed = time.perf_counter() - t0
        if result is True:
            return (PASS, "OK", elapsed)
        else:
            return (FAIL, str(result), elapsed)
    except Exception as exc:
        return (ERROR, str(exc), time.perf_counter() - t0)


def main() -> int:
    if not ZIP_PATH.exists():
        print(f"ERROR: Test file not found: {ZIP_PATH}", file=sys.stderr)
        return 1

    pml_path = _extract_pml()
    reader = ProcmonReader(pml_path)

    tests: List[Tuple[str, callable]] = []

    # --- system_details tests ---
    sd = reader.system_details()

    def test_sd_computer_name():
        v = sd.get("Computer Name")
        if v != "DESKTOP-IFKRIMS":
            return f"Computer Name: expected 'DESKTOP-IFKRIMS', got {v!r}"
        return True

    def test_sd_logical_processors():
        v = sd.get("Logical Processors")
        if str(v) != '4':
            return f"Logical Processors: expected '4', got {v!r}"
        return True

    def test_sd_os():
        v = sd.get("Operating System")
        if "Windows 10" not in str(v):
            return f"Operating System: expected 'Windows 10' substring, got {v!r}"
        return True

    def test_sd_system_type():
        v = sd.get("System Type")
        if v != "64-bit":
            return f"System Type: expected '64-bit', got {v!r}"
        return True

    def test_sd_system_root():
        v = sd.get("System Root")
        if v != "C:\\Windows":
            return f"System Root: expected 'C:\\Windows', got {v!r}"
        return True

    def test_sd_memory():
        v = sd.get("Memory (RAM)")
        if "8 GB" not in str(v):
            return f"Memory (RAM): expected '8 GB' substring, got {v!r}"
        return True

    def test_sd_keys():
        expected_keys = {"Computer Name", "Logical Processors", "Operating System",
                         "System Type", "System Root", "Memory (RAM)"}
        actual_keys = set(sd.keys())
        if expected_keys != actual_keys:
            return f"system_details keys: expected {expected_keys}, got {actual_keys}"
        return True

    # --- event_count property ---
    def test_event_count_property():
        v = reader.event_count
        if v != 108239:
            return f"event_count property: expected 108239, got {v!r}"
        return True

    tests = [
        ("system_details.computer_name", test_sd_computer_name),
        ("system_details.logical_processors", test_sd_logical_processors),
        ("system_details.operating_system", test_sd_os),
        ("system_details.system_type", test_sd_system_type),
        ("system_details.system_root", test_sd_system_root),
        ("system_details.memory", test_sd_memory),
        ("system_details.keys", test_sd_keys),
        ("event_count_property", test_event_count_property),
    ]

    max_name_len = max(len(t[0]) for t in tests)
    passed = failed = errored = 0

    print(f"\n  Running {len(tests)} common test(s)\n")
    print(f"  {'Name':<{max_name_len}}  {'Status':<7}  {'Time':>8}  Details")
    print("  " + "-" * (max_name_len + 40))

    for name, func in tests:
        status, msg, elapsed = _run_test(name, func)
        status_tag = f"[{status}]"
        print(f"  {name:<{max_name_len}}  {status_tag:<7}  {elapsed:>7.3f}s  {msg}")
        if status == PASS:
            passed += 1
        elif status == FAIL:
            failed += 1
        else:
            errored += 1

    print()
    print(f"  Common tests: {len(tests)} total  |  {passed} passed  |  {failed} failed  |  {errored} error(s)")

    reader.close()
    return 0 if (failed == 0 and errored == 0) else 1


if __name__ == "__main__":
    sys.exit(main())