"""
Parser for Apache HTTPD combined access logs.

Apache's combined format is byte-compatible with Nginx's combined format, so
this parser delegates to :class:`~pysoc.parsers.nginx.NginxParser`. The class
exists as a distinct type so that downstream code can branch on
``event.source_type == "apache"`` if it needs to.
"""

from __future__ import annotations

from .nginx import NginxParser


class ApacheParser(NginxParser):
    """Parse Apache combined access logs (same format as Nginx combined)."""

    name = "apache"
    source_type = "apache"
