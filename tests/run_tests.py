#!/usr/bin/env python3
"""
ProcmonReader — master test runner.

Runs all test suites:
  1. test_commom  — system info, PML metadata, event_count
  2. test_process — process list validation
  3. test_event   — JSON-driven event & filter tests

Usage:
    python run_tests.py [-v]
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def main() -> int:
    from test_commom import main as run_common
    from test_process import main as run_process
    from test_event import main as run_event

    verbose = "-v" in sys.argv or "--verbose" in sys.argv

    print("=" * 70)
    print("  ProcmonReader — Test Suite")
    print("=" * 70)

    t0 = time.perf_counter()
    results = {}

    # 1. Common tests (system info, pml details)
    print("\n" + "─" * 70)
    print("  [1/3] Common Tests (system_details, event_count)")
    print("─" * 70)
    results["common"] = run_common()

    # 2. Process tests
    print("\n" + "─" * 70)
    print("  [2/3] Process Tests (processes)")
    print("─" * 70)
    results["process"] = run_process()

    # 3. Event tests (JSON-driven)
    print("\n" + "─" * 70)
    print("  [3/3] Event Tests (filters, fields, combinations)")
    print("─" * 70)
    results["event"] = run_event(verbose=verbose)

    elapsed = time.perf_counter() - t0

    # Summary
    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    all_pass = True
    for suite, rc in results.items():
        status = "PASS" if rc == 0 else "FAIL"
        if rc != 0:
            all_pass = False
        print(f"  {suite:<12}  [{status}]")

    print(f"\n  Total time: {elapsed:.1f}s")
    print(f"  Overall: {'ALL PASSED' if all_pass else 'SOME FAILED'}")
    print("=" * 70)

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())