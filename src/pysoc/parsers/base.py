"""
Base class for all parsers.

A parser is a *callable* that takes an iterable of raw lines (or JSON
records) and yields :class:`~pysoc.models.Event` instances. The base class
provides:

* :meth:`parse_text` — convenience wrapper that splits a string into lines.
* :meth:`parse_file` — convenience wrapper that reads a file from disk.
* :meth:`parse_line` — abstract; subclasses implement the actual parsing.

All parsers are stateless; a single instance can be reused across files.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterable, Iterator, Union

from ..models import Event


_LOG = logging.getLogger(__name__)


class BaseParser:
    """Abstract base class for log parsers.

    Subclasses MUST override :meth:`parse_line`. They MAY override
    :meth:`parse_file` if the format requires multi-line awareness (e.g.,
    XML-wrapped EVTX JSON exports).
    """

    #: Name of this parser; must match the key in :data:`pysoc.parsers.PARSERS`.
    name: str = "base"

    #: ``source_type`` value to stamp on every emitted :class:`Event`.
    source_type: str = "unknown"

    def parse_line(self, line: str) -> Union[Event, None]:
        """Parse a single raw log line into an :class:`Event`.

        Returns ``None`` for blank lines or unparseable content. **Must be
        overridden by subclasses.**

        Parameters
        ----------
        line:
            A single line of the log file, *without* the trailing newline.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Iteration helpers
    # ------------------------------------------------------------------
    def parse_lines(self, lines: Iterable[str]) -> Iterator[Event]:
        """Parse an iterable of raw lines, yielding :class:`Event` objects.

        Blank lines and unparseable lines are silently skipped (the latter
        also counted; see :attr:`skipped`).
        """
        self.parsed = 0
        self.skipped = 0
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            try:
                evt = self.parse_line(line)
            except Exception as exc:
                # A single bad line must not abort the whole parse.
                _LOG.debug("Skipping unparsable line in %s: %s", self.__class__.__name__, exc, exc_info=True)
                self.skipped += 1
                continue
            if evt is None:
                self.skipped += 1
                continue
            self.parsed += 1
            yield evt

    def parse_text(self, text: str) -> Iterator[Event]:
        """Parse a multi-line string."""
        yield from self.parse_lines(text.splitlines())

    def parse_file(self, path: Union[str, Path]) -> Iterator[Event]:
        """Parse a file from disk, yielding :class:`Event` objects.

        For JSON-array files (e.g., Windows EVTX exports), the entire file
        is read and dispatched through :meth:`_parse_json_records`.
        """
        path = Path(path)
        suffix = path.suffix.lower()
        if suffix == ".json":
            # Whole-file JSON (array of records) — e.g. Windows EVTX export.
            yield from self._parse_json_file(path)
        else:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                yield from self.parse_lines(fh)

    # ------------------------------------------------------------------
    # JSON helper
    # ------------------------------------------------------------------
    def _parse_json_file(self, path: Path) -> Iterator[Event]:
        """Default JSON loader: file must be a JSON array of records."""
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data = [data]
        self.parsed = 0
        self.skipped = 0
        for record in data:
            try:
                evt = self.parse_record(record)  # type: ignore[attr-defined]
            except (AttributeError, Exception) as exc:  # noqa: BLE001
                _LOG.debug("Skipping unparsable JSON record in %s: %s", self.__class__.__name__, exc, exc_info=True)
                self.skipped += 1
                continue
            if evt is None:
                self.skipped += 1
                continue
            self.parsed += 1
            yield evt

    # Subclasses that consume JSON override this instead of parse_line.
    def parse_record(self, record: dict) -> Union[Event, None]:  # pragma: no cover
        """Parse a JSON record dict into an :class:`Event`.

        Only relevant for JSON-based parsers. The default implementation
        raises :class:`NotImplementedError` so that text-only parsers can
        ignore it.
        """
        raise NotImplementedError
