#!/usr/bin/env python3
"""
Filter events from a PML file using ProcmonReader.

Usage
-----
    python filter_event.py <pml_file> [--no-default-filters]

Edit the FILTERS, SELECT_FIELDS, LIMIT, and AS_JSON constants below to
configure what to match and what to output.

Common fields for SELECT_FIELDS:
    event_class, operation, duration, timestamp, result, tid,
    process_name, pid, parent_pid, image_path, command_line, user,
    company, version, description, integrity, session, authentication_id,
    virtualized, is_64_bit, path, category, detail

Filter rule format:  [field, operator, value, 'include'|'exclude']
  Operators: '==' / 'is', '!=' / 'is_not', '>=' / 'ge', '<=' / 'le', 'regex'
  Examples:
    ['process_name', 'regex', '^notepad', 'include']
    ['event_class',  'regex', r'^File System$', 'include']
    ['pid',          '==',    1234, 'include']
    ['result',       'regex', 'ACCESS DENIED', 'include']
    ['operation',    'regex', 'RegSetValue', 'exclude']
    ['path',         'regex', r'\\AppData\\', 'include']
"""

import argparse
import sys
import json
import time
import datetime
from pathlib import Path

# Allow running from the tests/ directory without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from procmon_reader import ProcmonReader

# ============================================================
# Edit these to configure the filter
# ============================================================

DEFAULT_FILTERS = [
    # --- Process Name ---
    ['process_name', 'regex', r'^Procmon\.exe$',    'exclude'],
    ['process_name', 'regex', r'^Procexp\.exe$',    'exclude'],
    ['process_name', 'regex', r'^Autoruns\.exe$',   'exclude'],
    ['process_name', 'regex', r'^Procmon64\.exe$',  'exclude'],
    ['process_name', 'regex', r'^Procexp64\.exe$',  'exclude'],
    ['process_name', 'regex', r'^System$',           'exclude'],
    # --- Operation ---
    ['operation',    'regex', r'^IRP_MJ_',      'exclude'],
    ['operation',    'regex', r'^FASTIO_',      'exclude'],
    # --- Result ---
    ['result',       'regex', r'^FAST IO',      'exclude'],
    # --- Path ---
    ['path',         'regex', r'pagefile\.sys$', 'exclude'],
    ['path',         'regex', r'\$Mft$',        'exclude'],
    ['path',         'regex', r'\$MftMirr$',    'exclude'],
    ['path',         'regex', r'\$LogFile$',    'exclude'],
    ['path',         'regex', r'\$Volume$',     'exclude'],
    ['path',         'regex', r'\$AttrDef$',    'exclude'],
    ['path',         'regex', r'\$Root$',       'exclude'],
    ['path',         'regex', r'\$Bitmap$',     'exclude'],
    ['path',         'regex', r'\$Boot$',       'exclude'],
    ['path',         'regex', r'\$BadClus$',    'exclude'],
    ['path',         'regex', r'\$Secure$',     'exclude'],
    ['path',         'regex', r'\$UpCase$',     'exclude'],
    ['path',         'regex', r'\$Extend',      'exclude'],
    # --- Event Class ---
    ['event_class',  '==', 'Profiling',    'exclude'],
]

FILTERS = [
   ['event_class', '==',    'File System', 'include'],
   ['path',        'regex', r'\\AppData\\Local', 'include'],
#    ['detail',      'regex', r'open', 'include'],
#    ['timestamp',   '>=',    '2025-12-30T19:44:29.81', 'include'],
#    ['timestamp',   '<=',    '2025-12-30T19:43:29.81', 'include'],
#    ['result',      'regex', r'DENIED', 'include'],
]

SELECT_FIELDS = [
    'timestamp',
    'operation',
    'result',
    'detail',
]

LIMIT = 10          # Maximum number of events to return (None = no limit)
AS_JSON = False      # True = one JSON object per line; False = table
TZ = datetime.timezone(datetime.timedelta(hours=9))            # Timezone: None = local system tz; or e.g. datetime.timezone(datetime.timedelta(hours=8))

# ============================================================

COLUMN_WIDTHS = {
    'event_index': 8,
    'event_class': 12,
    'process_name': 24,
    'pid': 7,
    'tid': 7,
    'operation': 20,
    'result': 12,
    'path': 52,
    'detail': 60,
    'timestamp': 30,
    'duration': 14,
    'user': 24,
    'command_line': 40,
    'image_path': 40,
}


def _col(value, field: str) -> str:
    width = COLUMN_WIDTHS.get(field, 20)
    text = str(value) if value is not None else ''
    if len(text) > width:
        text = text[:width - 1] + '…'
    return text.ljust(width)


def print_table(events: list, fields: list) -> None:
    all_fields = ['event_index'] + fields
    header = ' | '.join(_col(f, f) for f in all_fields)
    sep = '-+-'.join('-' * COLUMN_WIDTHS.get(f, 20) for f in all_fields)
    print(header)
    print(sep)
    for ev in events:
        row = ' | '.join(_col(ev.get(f, ''), f) for f in all_fields)
        print(row)


def main():
    t_start = time.perf_counter()

    parser = argparse.ArgumentParser(description='Filter events from a PML file.')
    parser.add_argument('pml_file', help='Path to the PML file')
    parser.add_argument('--no-default-filters', action='store_true',
                        help='Disable the built-in DEFAULT_FILTERS (Procmon noise exclusions)')
    args = parser.parse_args()

    pml_file = args.pml_file

    try:
        reader = ProcmonReader(pml_file, tz=TZ)
    except FileNotFoundError:
        print(f"Error: file not found: {pml_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Error opening PML file: {exc}", file=sys.stderr)
        sys.exit(1)

    total_events = reader.event_count

    active_filters = (FILTERS if args.no_default_filters else DEFAULT_FILTERS + FILTERS) or None

    try:
        applied = reader.apply_filters(filters=active_filters, select_fields=SELECT_FIELDS)
    except ValueError as exc:
        print(f"Filter error: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        matched_count = len(reader)
        if LIMIT is not None:
            events = reader[0:LIMIT]
        else:
            events = reader[:]
    except Exception as exc:
        print(f"Error reading events: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"File   : {pml_file}")
    print(f"Events : {total_events} total, {matched_count} matched after filtering")
    if applied:
        print(f"Filters: {applied}")
    print(f"Fields : {SELECT_FIELDS}")
    print()

    display_count = len(events)
    was_limited = LIMIT is not None and display_count == LIMIT
    print(f"Showing: {display_count}" + (f" (limit={LIMIT}; increase LIMIT to see more)" if was_limited else ""))
    print()

    if not events:
        print("No matching events.")
        print(f"\nElapsed: {time.perf_counter() - t_start:.3f}s")
        return

    if AS_JSON:
        for ev in events:
            print(json.dumps(ev, default=str))
    else:
        print_table(events, SELECT_FIELDS)

    print(f"\nElapsed: {time.perf_counter() - t_start:.3f}s")


if __name__ == '__main__':
    main()
