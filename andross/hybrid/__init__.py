"""Hybrid analysis mode - combines dynamic and static analysis

This module orchestrates a two-phase analysis:
1. Dynamic phase: Runs Frida hooks with DEX interception
2. Static phase: Analyzes the intercepted DEX using static string extraction
"""

from .engine import run_hybrid_analysis

__all__ = [
    "run_hybrid_analysis",
]
