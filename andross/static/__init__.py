"""Static analysis module for Andross APK Analysis Tool

Provides string extraction and pattern matching capabilities for APK analysis.
"""

from andross.static.engine import run_static_analysis
from andross.static.patterns import get_available_patterns, filter_by_pattern
from andross.static.dex_parser import extract_strings_from_dex_bytes
from andross.static.xml_parser import extract_strings_from_xml_bytes
from andross.static.arsc_parser import extract_strings_from_arsc
from andross.static.filters import is_useful_string

__all__ = [
    "run_static_analysis",
    "get_available_patterns",
    "filter_by_pattern",
    "extract_strings_from_dex_bytes",
    "extract_strings_from_xml_bytes",
    "extract_strings_from_arsc",
    "is_useful_string",
]
