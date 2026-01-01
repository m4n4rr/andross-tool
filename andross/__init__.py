"""Andross - APK Analysis Tool

A comprehensive APK analysis tool supporting static and dynamic analysis modes.
"""

from andross.cli.main import main
from andross.static.engine import run_static_analysis
from andross.dynamic.engine import run_dynamic_analysis

__version__ = "1.0.0"

__all__ = [
    "main",
    "run_static_analysis",
    "run_dynamic_analysis",
]
