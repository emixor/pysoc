"""
Log parsers.

Each parser converts a raw log line (or JSON record) into a normalised
:class:`~pysoc.models.Event`. All parsers share a common interface so that
the ingestor can dispatch by file extension / sniffing without knowing the
specific format.

Public API
----------
``get_parser(path)``
    Auto-detect the right parser for a file based on extension and content.

``PARSERS``
    Registry of all available parsers, keyed by name.
"""

from __future__ import annotations

from .base import BaseParser  # noqa: F401
from .linux_auth import LinuxAuthParser
from .nginx import NginxParser
from .apache import ApacheParser
from .json_parser import JSONLinesParser
from .windows_json import WindowsJsonParser

# Registry: name → parser class. The ingestor uses this to pick a parser
# (either explicitly via ``--parser`` or implicitly via file extension).
PARSERS = {
    "linux_auth": LinuxAuthParser,
    "nginx": NginxParser,
    "apache": ApacheParser,
    "json": JSONLinesParser,
    "windows_json": WindowsJsonParser,
}

# File extension → parser name lookup table.
EXTENSION_MAP = {
    ".auth.log": "linux_auth",
    ".log": "linux_auth",  # default for .log
    ".nginx": "nginx",
    ".access.log": "nginx",
    ".apache": "apache",
    ".jsonl": "json",
    ".json": "windows_json",
    ".evtx.json": "windows_json",
}


def get_parser_for_path(path: str):
    """Pick a parser class for ``path`` based on its extension.

    Returns ``None`` if no parser matches. Callers should fall back to
    content sniffing (see :func:`pysoc.ingest.sniff_parser`) in that case.
    """
    p = path.lower()
    # Filename-prefix special case: distinguish ``nginx_access.log`` from
    # ``apache_access.log`` — both end in ``.access.log`` but should be
    # tagged with the correct source_type.
    base = p.rsplit("/", 1)[-1]
    if base.startswith("apache"):
        return ApacheParser
    if base.startswith("nginx"):
        return NginxParser
    # Otherwise: sort extensions by length DESCENDING so the longest match
    # wins. E.g. "auth.log" must match ".auth.log" before ".log".
    for ext, name in sorted(EXTENSION_MAP.items(), key=lambda kv: len(kv[0]), reverse=True):
        if p.endswith(ext):
            return PARSERS[name]
    return None


__all__ = [
    "BaseParser",
    "LinuxAuthParser",
    "NginxParser",
    "ApacheParser",
    "JSONLinesParser",
    "WindowsJsonParser",
    "PARSERS",
    "EXTENSION_MAP",
    "get_parser_for_path",
]
