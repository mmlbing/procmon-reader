"""
ProcmonReader — main public API for reading and filtering PML files.

Usage:
    from procmon_reader import ProcmonReader

    reader = ProcmonReader("capture.pml")

    # Or specify timezone (defaults to local timezone)
    # import datetime
    # reader = ProcmonReader("capture.pml", tz=datetime.timezone(datetime.timedelta(hours=8)))

    # Basic info
    print(reader.system_details())
    print(reader.event_count)

    # Filter and iterate
    reader.apply_filters(
        filters=[
            ['process_name', 'regex', '^notepad', 'include'],
            ['event_class', '==', 'File System', 'include'],
        ],
        select_fields=['process_name', 'operation', 'path', 'result'],
    )

    for event in reader:
        print(event)

    # Or access results by index or slice
    print(len(reader))
    first_100 = reader[0:100]
"""
import datetime
from typing import Dict, List, Optional, Tuple

from procmon_reader._pml_core import ProcmonReaderCore
from procmon_reader.filters import build_filter_tree


_DEFAULT_SELECT_FIELDS = ['process_name', 'operation', 'result']

# Number of events to prefetch per C++ batch call during iteration
_PREFETCH_CHUNK = 256


def _tz_offset_seconds(tz) -> int:
    """Convert a tzinfo to an integer UTC offset in seconds."""
    ref = datetime.datetime(2000, 1, 1, tzinfo=tz)
    off = tz.utcoffset(ref)
    return int(off.total_seconds())


class ProcmonReader:
    """Read and filter events from PML files."""

    def __init__(self, file_path: str, tz=None):
        """Initialize ProcmonReader with a PML file.

        Args:
            file_path: Path to the PML file.
            tz: Timezone for timestamp output. Accepts a
                ``datetime.timezone`` or ``datetime.tzinfo`` instance.
                Defaults to the local system timezone if not provided.

        Raises:
            RuntimeError: If the file is not a valid PML file or is corrupt.
            FileNotFoundError: If the file does not exist.
        """
        self._cpp = ProcmonReaderCore(file_path)
        self._tz = tz if tz is not None else datetime.datetime.now(datetime.timezone.utc).astimezone().tzinfo
        self._tz_offset = _tz_offset_seconds(self._tz)
        self._event_count: int = self._cpp.event_count

        # Filter state (set by apply_filters)
        self._filter_tree = None  # Python dict/list tree or None
        self._select_fields: List[str] = list(_DEFAULT_SELECT_FIELDS)

        # Cached matched indices (invalidated by apply_filters)
        self._matched_indices: Optional[List[int]] = None

        # Iterator prefetch state
        self._iter_pos: int = 0
        self._prefetch_buf: List[dict] = []
        self._prefetch_pos: int = 0

    # ===================================================================
    # Resource management
    # ===================================================================
    def close(self):
        """Release all resources (mmap handles, file descriptors)."""
        if self._cpp is not None:
            self._cpp.close()
            self._cpp = None
        self._matched_indices = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    # ===================================================================
    # system_details
    # ===================================================================
    def system_details(self) -> dict:
        """Return system information parsed from the PML file header.

        Returns:
            dict with keys: Computer Name, Operating System, System Root,
            Logical Processors, Memory (RAM), System Type
        """
        return dict(self._cpp.system_details())

    # ===================================================================
    # processes
    # ===================================================================
    def processes(self) -> List[dict]:
        """Return a list of all processes recorded in the PML file."""
        return list(self._cpp.processes())

    # ===================================================================
    # event_count
    # ===================================================================
    @property
    def event_count(self) -> int:
        """Total number of events in the PML file."""
        return self._event_count

    # ===================================================================
    # apply_filters
    # ===================================================================
    def apply_filters(self, filters=None,
                      select_fields: list = None):
        """Validate, preprocess and store filter rules for subsequent queries.

        This method does NOT execute the filter — iterate, or use
        indexed/sliced access (``len(reader)``, ``reader[i]``,
        ``reader[a:b]``) to actually apply them.

        Args:
            filters: Filter specification. Accepts two formats:

                1. **Procmon format** (primary) — list of 4-element rules::

                       [['process_name', 'regex', '^notepad', 'include'],
                        ['process_name', 'regex', '^chrome',  'include'],
                        ['path',         'regex', 'AppData',  'include'],
                        ['operation',    'regex', 'WriteFile', 'exclude']]

                   Same-field include rules are OR'd, different fields are
                   AND'd. Exclude rules remove matching events from the
                   include results.

                2. **Nested dict DSL** — explicit AND/OR combinators::

                       {"AND": [rule1, rule2, {"OR": [rule3, rule4]}]}
                       {"OR": [rule1, rule2]}

                   Each element is either a ``[field, op, value]`` leaf or
                   another ``{"AND": ...}`` / ``{"OR": ...}`` dict.

                ``None`` or ``[]`` clears filters (return all events).

            select_fields: List of field names to include in results. Default is
                ``['process_name', 'operation', 'result']``. ``event_index``
                is always included regardless of this setting.

        Returns:
            The filter tree representation (for inspection).

        Raises:
            ValueError: If any filter rule or select field is invalid.
        """
        # Reset state
        self._matched_indices = None
        self._iter_pos = 0

        # Build filter tree (Python dict/list with raw string values)
        self._filter_tree = build_filter_tree(filters)

        # Store select_fields
        if select_fields is None:
            self._select_fields = list(_DEFAULT_SELECT_FIELDS)
        else:
            self._select_fields = list(select_fields)

        return self._filter_tree

    # ===================================================================
    # Internal: ensure matched indices are cached
    # ===================================================================
    def _ensure_matched(self):
        """Run the filter engine if results are not yet cached."""
        if self._matched_indices is not None:
            return
        self._matched_indices = list(self._cpp.filter_events(
            self._filter_tree, self._tz_offset))

    def _read_and_format(self, indices):
        """Read output fields for *indices* and return formatted dicts."""
        return list(self._cpp.read_events_batch(
            indices, self._select_fields, self._tz_offset))

    # ===================================================================
    # Iterator support
    # ===================================================================
    def __iter__(self):
        """Return an iterator over matched events."""
        self._ensure_matched()
        self._iter_pos = 0
        self._prefetch_buf = []
        self._prefetch_pos = 0
        return self

    def __next__(self) -> dict:
        """Return the next matched event dict."""
        if self._prefetch_pos >= len(self._prefetch_buf):
            indices = self._matched_indices
            if indices is None or self._iter_pos >= len(indices):
                raise StopIteration
            end = min(self._iter_pos + _PREFETCH_CHUNK, len(indices))
            chunk = indices[self._iter_pos:end]
            self._prefetch_buf = self._read_and_format(chunk)
            self._prefetch_pos = 0
            self._iter_pos = end

        event = self._prefetch_buf[self._prefetch_pos]
        self._prefetch_pos += 1
        return event

    # ===================================================================
    # __len__
    # ===================================================================
    def __len__(self) -> int:
        """Return the number of matched events."""
        self._ensure_matched()
        return len(self._matched_indices)

    # ===================================================================
    # __getitem__ — indexed and sliced access
    # ===================================================================
    def __getitem__(self, index):
        """Return matched event(s) by int index or slice."""
        self._ensure_matched()
        n = len(self._matched_indices)

        if isinstance(index, slice):
            indices = [self._matched_indices[i] for i in range(*index.indices(n))]
            if not indices:
                return []
            return self._read_and_format(indices)

        if not isinstance(index, int):
            raise TypeError(f"Index must be an integer or slice, got {type(index).__name__}")

        if index < -n or index >= n:
            raise IndexError(
                f"Index {index} out of range. "
                f"Only {n} events match the current filters."
            )
        return self._read_and_format([self._matched_indices[index]])[0]
