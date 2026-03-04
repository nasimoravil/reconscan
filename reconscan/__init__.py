"""
reconscan - Advanced Web & JavaScript Reconnaissance Tool

This package exposes a CLI entry point via ``python -m reconscan``.
The implementation is modular and rule-based; no AI reasoning is used
inside the tool itself.
"""

from .cli import main

__all__ = ["main"]

