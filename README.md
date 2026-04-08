# procmon-reader

A fast, C++-accelerated Python library for reading and filtering [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) PML files.

> **Acknowledgement:** The PML file format reverse-engineering in this project was informed by [procmon-parser](https://github.com/eronnen/procmon-parser).

## How It Works

The heavy lifting (file parsing, filtering, and field extraction) is implemented in C++ and exposed to Python via [pybind11](https://github.com/pybind/pybind11). Key techniques:

- **Multi-threaded C++ filter engine** that evaluates events in parallel.
- **Cost based field parsing** — cheaper fields are parsed first to short circuit more expensive ones.
- **Lazy, selective field reading** — only fields referenced in filters or selected for output are parsed, minimizing overhead.
- etc.

## Installation

### From PyPI

```bash
pip install procmon-reader
```

### From Source

```bash
pip install .
```

Requires Python >= 3.8, a C++17 compiler, and pybind11.

## Quick Start

```python
from procmon_reader import ProcmonReader

reader = ProcmonReader("capture.pml")

# System info
print(reader.system_details())
print(reader.event_count)

# Process info
processes = reader.processes()
print(processes[0])  # first process

process_modules = reader.process_modules(processes[0]['process_index'])
print(process_modules)

# Filter events
reader.apply_filters(
    filters=[
        ['process_name', 'regex', '^notepad', 'include'],
        ['event_class', '==', 'File System', 'include'],
    ],
    select_fields=['process_name', 'operation', 'path', 'result'],
)

# Iterate
for event in reader:
    print(event)

# Or use indexing / slicing
print(len(reader))        # number of matched events
print(reader[0])           # first match
print(reader[-1])          # last match
print(reader[10:20])       # slice
```

## Timezone

By default, timestamps use local system timezone. Pass a custom one:

```python
import datetime
tz = datetime.timezone(datetime.timedelta(hours=6))
reader = ProcmonReader("capture.pml", tz=tz)
```

## Filter Formats

### Procmon Format (simple)

List of `[field, operator, value, 'include'|'exclude']` rules.

This behaves same as Procmon's built-in filters:
- Include rules on the same field are OR'd, different fields are AND'd
- Exclude rules remove matches from the include set

```python
filters = [
    ['process_name', 'regex', '^notepad', 'include'],
    ['process_name', 'regex', '^chrome',  'include'],
    ['path',         'regex', 'AppData',  'include'],
    ['operation',    'regex', 'WriteFile', 'exclude'],
]
```

### Dict DSL (advanced)

Explicit `AND` / `OR` / `NOT` combinators with arbitrary nesting:

```python
filters = {"AND": [
    ['event_class', '==', 'File System'],
    {"OR": [
        ['process_name', 'regex', '^notepad'],
        ['process_name', 'regex', '^chrome'],
    ]},
]}
```

## Operators

- **Comparison:** `==`, `!=`, `<`, `<=`, `>`, `>=` (and aliases `eq`, `equals`, `is`, `ne`, `not_equals`, `is_not`, `lt`, `less_than`, `le`, `less_equal`, `lte`, `gt`, `greater_than`, `more_than`, `ge`, `greater_equal`, `more_equal`, `gte`)
- **String match:** `contains`, `starts_with`, `ends_with`, `excludes`
- **String regex:** `regex`

All string operators are case-insensitive.

## Supported Fields

All fields below can be used in `select_fields`. The **Filter Operators** column shows which operators are supported for filtering — `—` means the field is select-only.

| Field | Filter Operators | Filter Value Type | Example | Note |
|-------|-----------------|-------------------|---------|-----|
| `event_index` | `==` `!=` `<` `<=` `>` `>=` | `int` （PML internal event index） | `['event_index', '>=', 1000, 'include']` | |
| `event_class` | `==` `!=` `<` `<=` `>` `>=` | `str` — `File System`, `Registry`, `Network`, `Process`, `Profiling` (aliases: `fs`, `reg`, `net`, `proc`, `prof`) | `['event_class', '==', 'Registry', 'include']` | |
| `operation` | `==` `!=` `contains` `starts_with` `ends_with` `excludes` `regex` | `str` | `['operation', '==', 'ReadFile', 'include']` | |
| `duration` | `==` `!=` `<` `<=` `>` `>=` | `float` (seconds) | `['duration', '>=', 1.5, 'include']` | |
| `timestamp` | `==` `!=` `<` `<=` `>` `>=` | `str` (ISO 8601) | `['timestamp', '>=', '2025-12-30T19:50:58', 'include']` | |
| `result` | `==` `!=` `contains` `starts_with` `ends_with` `excludes` `regex` | `str` | `['result', '==', 'SUCCESS', 'include']` | |
| `tid` | `==` `!=` `<` `<=` `>` `>=` | `int` | `['tid', '==', 1234, 'include']` | |
| `process_index` | — | — （PML internal process index） | — | |
| `process_name` | `==` `!=` `contains` `starts_with` `ends_with` `excludes` `regex` | `str` | `['process_name', 'contains', 'notepad', 'include']` | |
| `pid` | `==` `!=` `<` `<=` `>` `>=` | `int` | `['pid', '==', 5678, 'include']` | |
| `parent_pid` | `==` `!=` `<` `<=` `>` `>=` | `int` | `['parent_pid', '==', 1000, 'include']` | |
| `image_path` | `==` `!=` `contains` `starts_with` `ends_with` `excludes` `regex` | `str` | `['image_path', 'contains', 'System32', 'include']` | |
| `command_line` | `==` `!=` `contains` `starts_with` `ends_with` `excludes` `regex` | `str` | `['command_line', 'contains', '--verbose', 'include']` | |
| `user` | `==` `!=` `contains` `starts_with` `ends_with` `excludes` `regex` | `str` | `['user', 'contains', 'SYSTEM', 'include']` | |
| `company` | `==` `!=` `contains` `starts_with` `ends_with` `excludes` `regex` | `str` | `['company', 'contains', 'Microsoft', 'include']` | |
| `version` | `==` `!=` `contains` `starts_with` `ends_with` `excludes` `regex` | `str` | `['version', 'regex', '^10\\.', 'include']` | |
| `description` | `==` `!=` `contains` `starts_with` `ends_with` `excludes` `regex` | `str` | `['description', 'contains', 'Notepad', 'include']` | |
| `integrity` | `==` `!=` `contains` `starts_with` `ends_with` `excludes` `regex` | `str` | `['integrity', '==', 'High', 'include']` | |
| `session` | `==` `!=` `<` `<=` `>` `>=` | `int` | `['session', '==', 1, 'include']` | |
| `authentication_id` | `==` `!=` `<` `<=` `>` `>=` | `int` or hex | `['authentication_id', '==', 0x3e7, 'include']` | |
| `virtualized` | `==` `!=` `<` `<=` `>` `>=` | `bool` | `['virtualized', '==', False, 'include']` | |
| `is_64_bit` | `==` `!=` `<` `<=` `>` `>=` | `bool` | `['is_64_bit', '==', True, 'include']` | |
| `path` | `==` `!=` `contains` `starts_with` `ends_with` `excludes` `regex` | `str` | `['path', 'contains', 'AppData', 'include']` | |
| `category` | `==` `!=` `contains` `starts_with` `ends_with` `excludes` `regex` | `str` | `['category', 'contains', 'Read', 'include']` | |
| `detail` | `==` `!=` `contains` `starts_with` `ends_with` `excludes` `regex` | `str` | `['detail', 'contains', 'Desired Access', 'include']` | |
| `stacktrace` | — | — | — | |

NOTE: `category`, `detail`, and `stacktrace` are not fully tested yet and may have mistakes. Use with caution.

## Testing

### Field Read Correctness

This verifies that every field is parsed correctly from the PML binary format.

The `test_filter_against_procmon_xml.py` script automatically exports a PML file to XML via `procmon.exe`, then compares **every field of every event** between `ProcmonReader` output and the XML ground truth.

```bash
python tests/manual/test_filter_against_procmon_xml.py capture.pml
```

### Filter & API Correctness

This verifies that filters correctly filter events, and that the API returns expected results.

```bash
python tests/run_tests.py
```

## License

MIT