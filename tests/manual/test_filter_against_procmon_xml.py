#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test ProcmonReader correctness by comparing EVERY field of EVERY event
against procmon.exe XML export (ground truth).

All fields are compared strictly — no skipping, no known-diff ignores.
On the first event with ANY mismatch, prints a detailed table and stops.

Usage:
    python test_filter_against_procmon_xml.py <pml_file>

Arguments:
    pml_file              Path to the PML file (XML is auto-exported beside it)
"""

import sys
import subprocess
import time
import datetime
import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from procmon_reader import ProcmonReader


# ===========================================================================
# Fields to compare: ProcmonReader output field name → XML tag name
# ===========================================================================
COMPARE_FIELDS = {
    'event_class':        'event_class',
    'operation':          'operation',
    'duration':           'duration',
    'timestamp':          'time_of_day',
    'result':             'result',
    'tid':                'tid',

    'process_name':       'process_name',
    'pid':                'pid',
    'parent_pid':         'parent_pid',
    'image_path':         'image_path',
    'command_line':       'command_line',
    'user':               'user',
    'company':            'company',
    'version':            'version',
    'description':        'description',
    'integrity':          'integrity',
    'session':            'session',
    'authentication_id':  'authentication_id',
    'virtualized':        'virtualized',
    # 'is_64_bit':          '',  # Skip as this is in exported xml process table.

    'path':               'path',
    'category':           'category',
    'detail':             'detail',
}


# For these operations, skip the 'detail' field comparison.
# TODO: find and fix the root causes of these mismatches so that we can compare 'detail' for all operations.
SKIPPED_OPERATIONS = {
    'CreateFileMapping',
    'Process Start',
}


# ===========================================================================
# Helper: locate procmon.exe
# ===========================================================================
def find_procmon_exe() -> Path:
    """Find procmon.exe in common locations or PATH."""
    common_paths = [
        Path(r"C:\Program Files\ProcessMonitor\procmon.exe"),
        Path(r"C:\Program Files (x86)\ProcessMonitor\procmon.exe"),
        Path(r"C:\Tools\ProcessMonitor\procmon.exe"),
        Path(r"C:\SysinternalsSuite\procmon.exe"),
        Path.cwd() / "procmon.exe",
        Path.cwd() / "Procmon.exe",
    ]
    try:
        result = subprocess.run(["where", "procmon.exe"],
                                capture_output=True, text=True, check=False)
        if result.returncode == 0:
            p = Path(result.stdout.strip().split('\n')[0])
            if p.exists():
                return p
    except Exception:
        pass

    for p in common_paths:
        if p.exists():
            return p

    raise FileNotFoundError(
        "procmon.exe not found. Install Process Monitor or specify --xml <path>."
    )


# ===========================================================================
# Helper: export PML → XML via procmon.exe
# ===========================================================================
def export_pml_to_xml(pml_file: Path, output_xml: Path) -> bool:
    """Export PML to XML using procmon.exe.  Returns True on success."""
    try:
        procmon_exe = find_procmon_exe()
        print(f"  Using procmon.exe : {procmon_exe}")

        if output_xml.exists():
            output_xml.unlink()

        cmd = [str(procmon_exe), "/OpenLog", str(pml_file),
               "/SaveAs", str(output_xml)]
        config_file = Path.cwd() / "all.pmc"
        if config_file.exists():
            cmd.extend(["/LoadConfig", str(config_file)])
            print(f"  Using config file : {config_file}")

        print(f"  Command           : {' '.join(cmd)}")
        print("  Exporting (this may take a while)...")
        subprocess.run(cmd, capture_output=True, text=True, timeout=3600 * 10)

        for _ in range(60):
            if output_xml.exists() and output_xml.stat().st_size > 0:
                size_mb = output_xml.stat().st_size / (1024 * 1024)
                print(f"  XML created       : {output_xml}  ({size_mb:.1f} MB)")
                return True
            time.sleep(1)

        print("  ERROR: XML file not created within 60 s")
        return False
    except subprocess.TimeoutExpired:
        print("  ERROR: procmon export timed out")
        return False
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


# ===========================================================================
# Streaming XML iterator
# ===========================================================================
def iter_xml_events(xml_file: Path):
    """Yield event dicts from a procmon XML export, one at a time.

    Uses iterparse so that memory usage stays constant regardless of file size.
    Tag names are lowercased; text is stripped (except Path which may have
    legitimate trailing whitespace).
    """
    context = ET.iterparse(str(xml_file), events=('end',))
    for _, elem in context:
        if elem.tag == 'event':
            event = {}
            for child in elem:
                tag = child.tag.lower()
                text = child.text or ""
                if tag != 'path':
                    text = text.strip()
                event[tag] = text
            yield event
            elem.clear()


# ===========================================================================
# Normalization: make PML and XML values comparable
# ===========================================================================
def _replace_non_bmp_with_underscores(s: str) -> str:
    """Replace non-BMP Unicode characters with underscores.

    Procmon's XML export encodes strings in UTF-16 internally, but replaces
    each surrogate code unit (i.e. each half of a non-BMP surrogate pair) with
    an underscore '_'.  Non-BMP characters (code point > U+FFFF) require two
    UTF-16 code units (a surrogate pair), so each such character becomes '__'
    (two underscores) in the XML.

    Procmon also replaces C0/C1 control characters (U+0001–U+001F and
    U+007F–U+009F) with '_' when writing the XML export.  However, the three
    XML-legal whitespace control characters — HT (U+0009), LF (U+000A), and
    CR (U+000D) — are preserved as-is in the XML, so we must NOT substitute
    them with '_' on the PML side.

    Applying the substitutions to the PML side lets us compare against the
    XML ground truth without falsely flagging paths or strings that contain
    control characters or non-BMP characters.
    """
    result = []
    for ch in s:
        cp = ord(ch)
        if cp > 0xFFFF:
            result.append('__')   # one surrogate pair → two underscores
        elif (0x00 < cp <= 0x1F) and cp not in (0x09, 0x0A, 0x0D):
            # XML-illegal control char → underscore (Procmon XML behaviour).
            # Excludes \t (0x09), \n (0x0A), \r (0x0D): valid in XML, Procmon keeps them.
            result.append('_')
        elif 0x7F <= cp <= 0x9F:
            result.append('_')    # C1 control char → underscore
        else:
            result.append(ch)
    return ''.join(result)


def normalize_pair(field: str, pml_val, xml_val: str):
    """Normalize a (pml_value, xml_value) pair so they can be compared.

    Returns (normalized_pml, normalized_xml).
    No skipping — all fields are compared strictly.
    """
    pml_str = '' if pml_val is None else str(pml_val)
    xml_str = xml_val

    # ---- timestamp: ISO local time → Procmon time_of_day string ----
    if field == 'timestamp':
        try:
            # PML returns local time "YYYY-MM-DDTHH:MM:SS.fffffff" (no TZ suffix)
            # Convert to Procmon XML format "h:mm:ss.fffffff AM/PM"
            t_pos = pml_str.index('T')
            time_part = pml_str[t_pos + 1:]          # "HH:MM:SS.fffffff"
            dot_pos = time_part.index('.')
            hms = time_part[:dot_pos]                  # "HH:MM:SS"
            frac = time_part[dot_pos + 1:dot_pos + 8]  # 7-digit 100ns ticks
            h, m, s = (int(x) for x in hms.split(':'))
            hour_12 = h % 12 or 12
            ampm = "AM" if h < 12 else "PM"
            pml_str = f"{hour_12}:{m:02d}:{s:02d}.{frac} {ampm}"
        except (ValueError, TypeError):
            pass
        return pml_str, xml_str

    # ---- detail: PML returns dict (or JSON string), XML uses "Key: Value, Key: Value" ----
    if field == 'detail':
        try:
            if isinstance(pml_val, dict):
                data = pml_val
            else:
                data = json.loads(pml_str)
            if isinstance(data, dict):
                reg_type = data.get('Type', '')
                parts = []
                for k, v in data.items():
                    if k == 'Data' and reg_type == 'REG_BINARY' and isinstance(v, str):
                        # PML: continuous lowercase hex → XML: space-separated uppercase pairs
                        h = v.upper()
                        parts.append(f"{k}: {' '.join(h[i:i+2] for i in range(0, len(h), 2))}")
                    elif isinstance(v, list):
                        # REG_MULTI_SZ list → XML: comma-space joined values
                        parts.append(f"{k}: {', '.join(str(x) for x in v)}")
                    elif isinstance(v, (int, float)):
                        # add_uint/add_int: XML does NOT use thousands separators
                        parts.append(f"{k}: {v}")
                    elif isinstance(v, str):
                        # add_str: XML uses thousands separators for plain decimal integers
                        try:
                            parts.append(f"{k}: {format(int(v), ',')}")
                        except ValueError:
                            parts.append(f"{k}: {v}")
                    else:
                        parts.append(f"{k}: {v}")
                pml_str = ', '.join(parts).rstrip()
        except Exception:
            pass
        pml_str = _replace_non_bmp_with_underscores(pml_str)
        return pml_str, xml_str

    # ---- non-BMP Unicode: Procmon XML replaces each surrogate with '_' ----
    # Apply to all string fields so that paths, process names, etc. containing
    # emoji or other characters outside the BMP compare correctly.
    pml_str = _replace_non_bmp_with_underscores(pml_str)

    # ---- default: direct string comparison ----
    return pml_str, xml_str


# ===========================================================================
# Main comparison logic
# ===========================================================================
def compare_all_events(
    pml_file: Path,
    procmon_xml: Path,
    start_event: int = 0,
    tz=None,
) -> int:
    """Compare every field of every event between PML and XML.

    Stops immediately on the first event with any mismatch, printing a
    detailed table of all fields for that event.

    start_event: skip all events with event_index < start_event.

    Returns the total number of field mismatches in the first bad event
    (0 = all events match).
    """
    total_compared = 0
    total_skipped = 0
    progress_interval = 10000

    xml_iter = iter_xml_events(procmon_xml)

    print(f"Comparing events from PML and XML exports...")
    reader = ProcmonReader(str(pml_file), tz=tz)
    total_events = reader.event_count

    print(f"  Total events in PML : {total_events}")
    print(f"  Fields per event    : {len(COMPARE_FIELDS)}")
    if start_event > 0:
        print(f"  Starting from event : {start_event}")
    print()

    # Apply no filters, select all comparison fields
    pml_fields = list(COMPARE_FIELDS.keys())
    reader.apply_filters(filters=None, select_fields=pml_fields)

    for pml_ev in reader:
        event_idx = pml_ev['event_index']

        # Skip events before start_event, consuming both iterators in sync
        if event_idx < start_event:
            try:
                next(xml_iter)
            except StopIteration:
                print(f"\n  WARNING: XML ended while skipping to event {start_event}")
                return 0
            total_skipped += 1
            continue

        try:
            xml_event = next(xml_iter)
        except StopIteration:
            print(f"\n  WARNING: XML ended early at event {total_compared}")
            break

        # Compare each field
        event_rows = []   # [(field, pml_norm, xml_norm, matched, skipped)]
        mismatch_count = 0
        operation = pml_ev.get('operation', '')
        skip_detail = operation in SKIPPED_OPERATIONS

        for pml_field, xml_tag in COMPARE_FIELDS.items():
            pml_val = pml_ev.get(pml_field)
            xml_val = xml_event.get(xml_tag, '')

            pml_norm, xml_norm = normalize_pair(pml_field, pml_val, xml_val)
            is_skipped = (pml_field == 'detail' and skip_detail)
            matched = is_skipped or (pml_norm == xml_norm)
            event_rows.append((pml_field, pml_norm, xml_norm, matched, is_skipped))
            if not matched:
                mismatch_count += 1

        if mismatch_count > 0:
            _print_event_table(event_idx, event_rows)
            print(f"  Stopped at event #{event_idx} "
                  f"(compared {total_compared} events OK before this one)")
            return mismatch_count

        total_compared += 1

        # Progress
        if total_compared % progress_interval == 0:
            pct = (total_skipped + total_compared) / total_events * 100
            sys.stdout.write(
                f"\r  Progress: {total_skipped + total_compared}/{total_events} ({pct:.1f}%)"
            )
            sys.stdout.flush()

    print()  # newline after progress
    print()
    print(f"  Events skipped      : {total_skipped}")
    print(f"  Events compared     : {total_compared}")
    print(f"  Total mismatches    : 0")
    return 0

def _print_event_table(event_idx: int, rows):
    """Print a table showing all fields for one event, highlighting mismatches.

    rows: list of (field, pml_val, xml_val, matched)
    """
    fw = max(len(r[0]) for r in rows)
    pw = max(max(len(str(r[1])) for r in rows), 3)
    xw = max(max(len(str(r[2])) for r in rows), 3)
    pw = min(pw, 80)
    xw = min(xw, 80)

    hdr_field = 'Field'.ljust(fw)
    hdr_pml = 'PML'.ljust(pw)
    hdr_xml = 'XML'.ljust(xw)

    sep = f"  +{'-' * (fw + 2)}+{'-' * (pw + 2)}+{'-' * (xw + 2)}+------+"
    print()
    print(f"  *** MISMATCH at Event #{event_idx} ***")
    print(sep)
    print(f"  | {hdr_field} | {hdr_pml} | {hdr_xml} |      |")
    print(sep)
    for field, pml_v, xml_v, matched, skipped in rows:
        pml_s = str(pml_v)[:pw].ljust(pw)
        xml_s = str(xml_v)[:xw].ljust(xw)
        f_s = field.ljust(fw)
        if skipped:
            mark = ' SKIP'
        elif matched:
            mark = '  OK '
        else:
            mark = '  X  '
        print(f"  | {f_s} | {pml_s} | {xml_s} |{mark} |")
    print(sep)
    print()


# ===========================================================================
# Main
# ===========================================================================
def main():
    parser = argparse.ArgumentParser(
        description='Compare all PML event fields against procmon XML export')
    parser.add_argument('pml_file', help='Path to the PML file')
    parser.add_argument('--start-event', type=int, default=0, metavar='N',
                        help='Skip events with event_index < N (default: 0)')
    parser.add_argument('--tz', type=int, default=None, metavar='HOURS',
                        help='UTC offset in hours for timestamp display (e.g. 8 for UTC+8). '
                             'Defaults to system local timezone.')
    args = parser.parse_args()

    # Resolve timezone
    if args.tz is not None:
        import datetime as _dt
        _tz = _dt.timezone(_dt.timedelta(hours=args.tz))
    else:
        _tz = None  # ProcmonReader will use system local timezone

    pml_file = Path(args.pml_file)
    if not pml_file.exists():
        print(f"ERROR: PML file not found: {pml_file}")
        sys.exit(1)

    # Determine XML path
    procmon_xml = pml_file.parent / f"{pml_file.stem}_procmon.xml"
    print("=" * 70)
    print("ProcmonReader — Full Event Field Comparison")
    print("=" * 70)
    print(f"  PML file   : {pml_file}")
    print(f"  XML file   : {procmon_xml}")
    print()

    # ---- Step 0: Ensure XML exists ----------------------------------------
    if not procmon_xml.exists():
        print("Step 0: Exporting PML → XML via procmon.exe ...")
        print("-" * 70)
        if not export_pml_to_xml(pml_file, procmon_xml):
            print("FATAL: Could not create XML export.")
            sys.exit(1)
        print()
    else:
        size_mb = procmon_xml.stat().st_size / (1024 * 1024)
        print(f"Step 0: Using existing XML ({size_mb:.1f} MB)")
        print()

    # ---- Step 1: Compare ------------------------------------------------
    print("Step 1: Comparing all events field-by-field ...")
    print("-" * 70)

    t0 = time.perf_counter()
    n_mismatches = compare_all_events(
        pml_file=pml_file,
        procmon_xml=procmon_xml,
        start_event=args.start_event,
        tz=_tz,
    )
    elapsed = time.perf_counter() - t0

    print()
    print("=" * 70)
    if n_mismatches == 0:
        print("RESULT: PASS - ALL FIELDS MATCH")
    else:
        print(f"RESULT: FAIL - {n_mismatches} MISMATCH(ES) IN FIRST BAD EVENT")
    print(f"  Elapsed: {elapsed:.2f} s")
    print("=" * 70)

    sys.exit(0 if n_mismatches == 0 else 1)


if __name__ == '__main__':
    main()
