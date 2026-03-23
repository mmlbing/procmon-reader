#!/usr/bin/env python3
"""
ProcmonReader — JSON-driven event test runner.

Usage
-----
    python test_event.py [config.json] [-v] [-f NAME]

    config.json   Path to the test-case config file.
                  Defaults to test_event_cases.json next to this script.
    -v / --verbose  Print each matched event for every test case.
    -f / --filter   Run only the test case with this name.

Exit code
---------
    0  All tests passed.
    1  One or more tests failed.
"""

import argparse
import json
import os
import sys
import tempfile
import time
import traceback
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from procmon_reader import ProcmonReader


PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"

# Cache: zip_path → extracted_pml_path (avoids re-extracting per test case)
_zip_cache: dict = {}


def _resolve_pml(pml_path: str, config_dir: Path) -> Path:
    """Return an absolute Path for pml_path, resolving relative paths against config_dir.

    If the path points to a .zip file, extract the first .PML inside it
    to a temp directory and return the extracted path (cached).
    """
    p = Path(pml_path)
    if not p.is_absolute():
        p = config_dir / p
    p = p.resolve()

    if p.suffix.lower() == ".zip":
        cache_key = str(p)
        if cache_key in _zip_cache:
            cached = Path(_zip_cache[cache_key])
            if cached.exists():
                return cached
        with zipfile.ZipFile(str(p)) as zf:
            pml_names = [n for n in zf.namelist() if n.lower().endswith(".pml")]
            if not pml_names:
                raise FileNotFoundError(f"No .pml file found inside {p}")
            tmpdir = tempfile.mkdtemp(prefix="procmon_test_")
            extracted = zf.extract(pml_names[0], tmpdir)
            _zip_cache[cache_key] = extracted
            return Path(extracted)

    return p


def _check_event_fields(event: dict, expected_fields: dict, context: str) -> List[str]:
    failures = []
    for key, expected_val in expected_fields.items():
        actual_val = event.get(key)
        if actual_val != expected_val:
            failures.append(
                f"  [{context}] field '{key}': expected {expected_val!r}, got {actual_val!r}"
            )
    return failures


def _run_assertions(
    total_count: int,
    events: List[dict],
    expected: dict,
) -> List[str]:
    failures: List[str] = []
    n = len(events)

    if "total_count" in expected:
        exp = expected["total_count"]
        if total_count != exp:
            failures.append(f"  total_count: expected {exp}, got {total_count}")

    if "min_count" in expected:
        exp = expected["min_count"]
        if n < exp:
            failures.append(f"  min_count: expected >= {exp}, got {n}")

    if "max_count" in expected:
        exp = expected["max_count"]
        if n > exp:
            failures.append(f"  max_count: expected <= {exp}, got {n}")

    if "all_events" in expected and events:
        for i, ev in enumerate(events):
            failures.extend(
                _check_event_fields(ev, expected["all_events"], f"event[{i}]")
            )

    if "first_event" in expected:
        if not events:
            failures.append("  first_event: no events returned")
        else:
            failures.extend(
                _check_event_fields(events[0], expected["first_event"], "first_event")
            )

    if "last_event" in expected:
        if not events:
            failures.append("  last_event: no events returned")
        else:
            failures.extend(
                _check_event_fields(events[-1], expected["last_event"], "last_event")
            )

    if "event_at" in expected:
        for spec in expected["event_at"]:
            idx = spec.get("index", 0)
            fields = spec.get("fields", {})
            if idx >= n:
                failures.append(
                    f"  event_at[{idx}]: index out of range (only {n} events returned)"
                )
            else:
                failures.extend(
                    _check_event_fields(events[idx], fields, f"event_at[{idx}]")
                )

    return failures


def run_test_case(tc: dict, config_dir: Path, verbose: bool) -> Tuple[str, str, float]:
    name = tc.get("name", "<unnamed>")
    pml_path_str = tc.get("pml_file", "")
    filters = tc.get("filters")
    select_fields = tc.get("select_fields")
    expected: dict = tc.get("expected", {})

    t0 = time.perf_counter()

    try:
        pml_path = _resolve_pml(pml_path_str, config_dir)
        if not pml_path.exists():
            return (ERROR, f"PML file not found: {pml_path}", time.perf_counter() - t0)

        reader = ProcmonReader(str(pml_path))
        reader.apply_filters(filters=filters, select_fields=select_fields)
        total_count = len(reader)
        events = reader[:]

    except (RuntimeError, FileNotFoundError) as exc:
        return (ERROR, f"PmlError: {exc}", time.perf_counter() - t0)
    except ValueError as exc:
        return (ERROR, f"ValueError (bad filter/field?): {exc}", time.perf_counter() - t0)
    except Exception as exc:
        tb = traceback.format_exc()
        return (ERROR, f"Unexpected error: {exc}\n{tb}", time.perf_counter() - t0)

    elapsed = time.perf_counter() - t0

    failures = _run_assertions(total_count, events, expected)

    if verbose and events:
        print(f"    [verbose] {len(events)} events returned (total_count={total_count})")
        for ev in events[:10]:
            print(f"      {ev}")
        if len(events) > 10:
            print(f"      ... ({len(events) - 10} more)")

    if failures:
        return (FAIL, "\n".join(failures), elapsed)

    summary = f"{len(events)} events returned"
    return (PASS, summary, elapsed)


def main(config_file: str = None, verbose: bool = False, filter_name: str = None) -> int:
    if config_file is None:
        config_file = str(Path(__file__).parent / "test_event_cases.json")

    config_path = Path(config_file).resolve()
    if not config_path.exists():
        print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
        return 1

    with config_path.open(encoding="utf-8") as fh:
        config: dict = json.load(fh)

    test_cases: List[dict] = config.get("test_cases", [])
    if not test_cases:
        print("No test cases found in config.", file=sys.stderr)
        return 1

    if filter_name:
        test_cases = [tc for tc in test_cases if tc.get("name") == filter_name]
        if not test_cases:
            print(f"No test case named '{filter_name}'.", file=sys.stderr)
            return 1

    config_dir = config_path.parent
    max_name_len = max(len(tc.get("name", "")) for tc in test_cases)

    passed = failed = errored = 0
    results: List[Tuple[str, str, str, float]] = []

    print(f"\n  Running {len(test_cases)} event test case(s) from: {config_path.name}\n")
    print(f"  {'Name':<{max_name_len}}  {'Status':<7}  {'Time':>8}  Details")
    print("  " + "-" * (max_name_len + 40))

    for tc in test_cases:
        name = tc.get("name", "<unnamed>")
        status, msg, elapsed = run_test_case(tc, config_dir, verbose)

        status_tag = f"[{status}]"
        print(f"  {name:<{max_name_len}}  {status_tag:<7}  {elapsed:>7.3f}s  {msg.splitlines()[0]}")
        if "\n" in msg:
            for line in msg.splitlines()[1:]:
                print(f"  {'':>{max_name_len}}           {line}")

        results.append((name, status, msg, elapsed))
        if status == PASS:
            passed += 1
        elif status == FAIL:
            failed += 1
        else:
            errored += 1

    total = len(test_cases)
    print()
    print(f"  Event tests: {total} total  |  {passed} passed  |  {failed} failed  |  {errored} error(s)")

    return 0 if (failed == 0 and errored == 0) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run ProcmonReader event tests.")
    parser.add_argument("config", nargs="?", default=None)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-f", "--filter", dest="filter_name")
    args = parser.parse_args()
    sys.exit(main(config_file=args.config, verbose=args.verbose, filter_name=args.filter_name))
