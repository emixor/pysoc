"""
Ingestor: read files from disk, dispatch to the right parser, and yield
:class:`~pysoc.models.Event` objects.

The ingestor is deliberately simple — it does no deduplication, no
enrichment, no rate-limiting. Those concerns live in the pipeline. The
ingestor's only job is: *read file → emit normalised events*.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Union

from .models import Event
from .parsers import PARSERS, get_parser_for_path


def sniff_parser(path: Path) -> Optional[str]:
    """Sniff a parser name from the first non-blank line of ``path``.

    Used when the file extension is ambiguous. Returns ``None`` if no parser
    recognises the content.
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            first = ""
            for line in fh:
                if line.strip():
                    first = line
                    break
    except OSError:
        return None
    if not first:
        return None
    # Heuristics:
    if first.lstrip().startswith("{"):
        return "windows_json" if '"EventID"' in first or '"event_id"' in first else "json"
    if "sshd[" in first and ("Failed password" in first or "Accepted" in first or "Invalid user" in first):
        return "linux_auth"
    if " - - [" in first and ('"GET ' in first or '"POST ' in first):
        return "nginx"
    return None


def ingest_file(path: Union[str, Path], parser_name: Optional[str] = None) -> Iterator[Event]:
    """Read a single file and yield :class:`Event` objects.

    Parameters
    ----------
    path:
        Path to the log file.
    parser_name:
        Explicit parser name. If ``None``, the parser is auto-detected from
        the file extension, then by content sniffing.
    """
    p = Path(path)
    parser_cls = PARSERS[parser_name] if parser_name else get_parser_for_path(str(p))
    if parser_cls is None:
        sniffed = sniff_parser(p)
        if sniffed:
            parser_cls = PARSERS[sniffed]
    if parser_cls is None:
        raise ValueError(f"No parser matched {p} (use --parser to specify one explicitly)")
    yield from parser_cls().parse_file(p)


def ingest_paths(
    paths: Iterable[Union[str, Path]],
    parser_name: Optional[str] = None,
) -> Iterator[Event]:
    """Ingest multiple files, yielding a single stream of events."""
    for p in paths:
        yield from ingest_file(p, parser_name=parser_name)


def ingest_to_list(
    paths: Iterable[Union[str, Path]],
    parser_name: Optional[str] = None,
) -> List[Event]:
    """Eager version of :func:`ingest_paths` — returns a list."""
    return list(ingest_paths(paths, parser_name=parser_name))


def ingest_logs(input_path: str | Path) -> list[NormalizedEvent]:
    """Legacy compatibility wrapper that returns NormalizedEvent objects."""
    from .parser import parse_line

    path = Path(input_path)
    events: list[NormalizedEvent] = []

    if path.is_file():
        files = [path]
    else:
        files = sorted(p for p in path.rglob("*") if p.is_file())

    for file_path in files:
        with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                event = parse_line(line)
                if event is not None:
                    events.append(event)

    events.sort(key=lambda e: e.timestamp)
    return events
