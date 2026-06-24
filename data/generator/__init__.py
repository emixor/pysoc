"""
Data generator package: synthetic mock log generator for PySOC.

Public entry point: :func:`generate_all`.
"""

from .generate_logs import generate_all, main  # noqa: F401

__all__ = ["generate_all", "main"]
