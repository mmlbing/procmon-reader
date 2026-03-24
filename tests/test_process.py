#!/usr/bin/env python3
"""
ProcmonReader — process list tests.

Tests the processes() method against known values from the test PML file (Logfile.zip).
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
    procs = reader.processes()

    tests: List[Tuple[str, callable]] = []

    # --- Process count ---
    def test_process_count():
        if len(procs) != 149:
            return f"process count: expected 149, got {len(procs)}"
        return True

    # --- Process list has required keys ---
    def test_process_keys():
        required = {"process_index", "pid", "parent_pid", "process_name",
                     "image_path", "command_line", "user", "integrity", "is_64_bit"}
        p = procs[0]
        missing = required - set(p.keys())
        if missing:
            return f"Missing keys in process dict: {missing}"
        if "modules" in p:
            return "process dict should not contain 'modules' key"
        return True

    # --- Known process: lsass.exe ---
    def test_lsass_process():
        lsass = [p for p in procs if p["process_name"] == "lsass.exe"]
        if not lsass:
            return "lsass.exe not found in process list"
        p = lsass[0]
        if p["pid"] != 744:
            return f"lsass.exe pid: expected 744, got {p['pid']}"
        if p["parent_pid"] != 596:
            return f"lsass.exe parent_pid: expected 596, got {p['parent_pid']}"
        if p["integrity"] != "System":
            return f"lsass.exe integrity: expected 'System', got {p['integrity']!r}"
        if "NT AUTHORITY\\SYSTEM" not in p.get("user", ""):
            return f"lsass.exe user: expected 'NT AUTHORITY\\SYSTEM', got {p['user']!r}"
        if p.get("is_64_bit") is not True:
            return f"lsass.exe is_64_bit: expected True, got {p.get('is_64_bit')!r}"
        return True

    # --- Known process: Procmon64.exe ---
    def test_procmon_process():
        procmon = [p for p in procs if p["process_name"] == "Procmon64.exe"]
        if not procmon:
            return "Procmon64.exe not found in process list"
        p = procmon[0]
        if "ProcessMonitor" not in p.get("image_path", ""):
            return f"Procmon64.exe image_path: expected 'ProcessMonitor' substring, got {p['image_path']!r}"
        if p.get("company") != "Sysinternals - www.sysinternals.com":
            return f"Procmon64.exe company: expected Sysinternals, got {p.get('company')!r}"
        return True

    # --- Known process: Explorer.EXE ---
    def test_explorer_process():
        explorer = [p for p in procs if p["process_name"] == "Explorer.EXE"]
        if not explorer:
            return "Explorer.EXE not found in process list"
        p = explorer[0]
        if p["pid"] != 5012:
            return f"Explorer.EXE pid: expected 5012, got {p['pid']}"
        if "Sol" not in p.get("user", ""):
            return f"Explorer.EXE user: expected 'Sol' substring, got {p['user']!r}"
        if p.get("integrity") != "Medium":
            return f"Explorer.EXE integrity: expected 'Medium', got {p.get('integrity')!r}"
        return True

    # --- Known process: MicrosoftEdgeUpdate.exe (32-bit) ---
    def test_edge_update_process():
        edge = [p for p in procs if p["process_name"] == "MicrosoftEdgeUpdate.exe"]
        if not edge:
            return "MicrosoftEdgeUpdate.exe not found in process list"
        p = edge[0]
        if p.get("is_64_bit") is not False:
            return f"MicrosoftEdgeUpdate.exe is_64_bit: expected False, got {p.get('is_64_bit')!r}"
        if p.get("company") != "Microsoft Corporation":
            return f"MicrosoftEdgeUpdate.exe company: expected 'Microsoft Corporation', got {p.get('company')!r}"
        return True

    # --- Verify process modules via process_modules() API ---
    def test_process_modules():
        lsass = [p for p in procs if p["process_name"] == "lsass.exe"]
        if not lsass:
            return "lsass.exe not found"
        proc_idx = lsass[0]["process_index"]
        mods = reader.process_modules(proc_idx)
        if len(mods) < 5:
            return f"lsass.exe modules: expected at least 5, got {len(mods)}"
        m = mods[0]
        if "path" not in m or "size" not in m:
            return f"module missing 'path' or 'size' keys: {list(m.keys())}"
        return True

    # --- Unique process names check ---
    def test_unique_process_names():
        names = set(p["process_name"] for p in procs)
        if "svchost.exe" not in names:
            return "svchost.exe not in process names"
        if "System" not in names:
            return "System not in process names"
        if "Idle" not in names:
            return "Idle not in process names"
        return True

    # --- smartscreen.exe (Medium integrity, session 1) ---
    def test_smartscreen_process():
        ss = [p for p in procs if p["process_name"] == "smartscreen.exe"]
        if not ss:
            return "smartscreen.exe not found in process list"
        p = ss[0]
        if p["pid"] != 7020:
            return f"smartscreen.exe pid: expected 7020, got {p['pid']}"
        if p.get("integrity") != "Medium":
            return f"smartscreen.exe integrity: expected 'Medium', got {p.get('integrity')!r}"
        if p.get("session") != 1:
            return f"smartscreen.exe session: expected 1, got {p.get('session')!r}"
        return True

    tests = [
        ("process_count", test_process_count),
        ("process_keys", test_process_keys),
        ("lsass_process", test_lsass_process),
        ("procmon_process", test_procmon_process),
        ("explorer_process", test_explorer_process),
        ("edge_update_process", test_edge_update_process),
        ("process_modules", test_process_modules),
        ("unique_process_names", test_unique_process_names),
        ("smartscreen_process", test_smartscreen_process),
    ]

    max_name_len = max(len(t[0]) for t in tests)
    passed = failed = errored = 0

    print(f"\n  Running {len(tests)} process test(s)\n")
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
    print(f"  Process tests: {len(tests)} total  |  {passed} passed  |  {failed} failed  |  {errored} error(s)")

    reader.close()
    return 0 if (failed == 0 and errored == 0) else 1


if __name__ == "__main__":
    sys.exit(main())