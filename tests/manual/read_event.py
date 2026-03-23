#!/usr/bin/env python3
"""
Simple example: read a single event from a PML file using ProcmonReader.

Usage
-----
    python read_event.py <pml_file> [event_index_1based]

If no event index is given, the first event is printed.
"""

import sys
from pathlib import Path

# Allow running from the tests/ directory without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from procmon_reader import ProcmonReader

SELECT_FIELDS = [
    'event_class',
    'operation',
    'duration',
    'timestamp',
    'result',
    'tid',

    'process_name',
    'pid',
    'parent_pid',
    'image_path',
    'command_line',
    'user',
    'company',
    'version',
    'description',
    'integrity',
    'session',
    'authentication_id',
    'virtualized',
    'is_64_bit',

    'path',
    'category',
    'detail',
]

def main():
    if len(sys.argv) < 2:
        print("Usage: python read_event.py <pml_file> [event_index_0based]")
        sys.exit(1)

    pml_file = sys.argv[1]
    event_index = int(sys.argv[2]) if len(sys.argv) >= 3 else 0  # 0-based

    reader = ProcmonReader(pml_file)

    total = reader.event_count
    print(f"File  : {pml_file}")
    print(f"Events: {total}")
    print()

    if event_index < 0 or event_index >= total:
        print(f"Event index {event_index} out of range (0–{total-1})")
        sys.exit(1)

    # Apply no filters; select all common fields
    reader.apply_filters(
        filters=[['event_index', '==', event_index, 'include']],
        select_fields=SELECT_FIELDS,
    )

    # Use indexed access to get the single matching event
    if len(reader) == 0:
        print("No events returned.")
        sys.exit(1)

    event = reader[0]
    print(f"=== Event #{event_index} ===")
    for key, value in event.items():
        print(f"  {key:<20} {value}")


if __name__ == "__main__":
    main()
