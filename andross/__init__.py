"""Andross - APK Analysis Tool

A comprehensive APK analysis tool supporting static, dynamic, and hybrid analysis modes.
"""

from andross.cli.main import main
from andross.static.engine import run_static_analysis
from andross.dynamic.engine import run_dynamic_analysis
from andross.hybrid.engine import run_hybrid_analysis

__version__ = "1.0.0"

__all__ = [
    "main",
    "run_static_analysis",
    "run_dynamic_analysis",
    "run_hybrid_analysis",
]
