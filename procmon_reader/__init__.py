"""
procmon_reader — standalone C++-accelerated PML file reader.

Quick Start:
    from procmon_reader import ProcmonReader

    reader = ProcmonReader("capture.pml")
    reader.apply_filters(
        filters=[['process_name', 'regex', 'notepad', 'include']],
        select_fields=['process_name', 'operation', 'path', 'result'],
    )
    for event in reader:
        print(event)
"""

from procmon_reader.reader import ProcmonReader

__all__ = [
    "ProcmonReader",
]
