"""Dynamic analysis module for Andross APK Analysis Tool

Provides Frida-based dynamic analysis and APK manifest parsing capabilities.
"""

from andross.dynamic.engine import run_dynamic_analysis
from andross.dynamic.manifest_parser import extract_package_from_apk
from andross.dynamic.event_processor import StringEventProcessor
from andross.dynamic.zip_evasion import skip_zip_evasion

__all__ = [
    "run_dynamic_analysis",
    "extract_package_from_apk",
    "StringEventProcessor",
    "skip_zip_evasion",
]
