"""Utilities module for Andross APK Analysis Tool

Provides device preparation, ADB management, and deployment utilities.
Organized in strict layers:
  - adb.py: Low-level ADB command execution (only place that runs adb)
  - emulator.py: Emulator status checking and device classification
  - frida_server.py: Frida-server deployment and management
  - app_installer.py: APK installation and verification
  - device.py: Device readiness orchestration (main entry point)
"""

from andross.utils.device import ensure_device_ready
from andross.utils.emulator import (
    is_device_connected, get_device_type,
    is_emulator_online, is_emulator_available, ensure_emulator_online, ensure_device_rooted
)
from andross.utils.frida_server import ensure_frida_server_running, is_frida_server_running
from andross.utils.app_installer import ensure_app_installed, is_app_installed
from andross.utils.adb import run_adb_command, run_adb_shell_command

__all__ = [
    # Main entry point
    "ensure_device_ready",
    
    # Emulator utilities
    "is_device_connected",
    "get_device_type",
    "is_emulator_online",
    "is_emulator_available",
    "ensure_emulator_online",
    "ensure_device_rooted",
    
    # Frida-server utilities
    "ensure_frida_server_running",
    "is_frida_server_running",
    
    # App installation utilities
    "ensure_app_installed",
    "is_app_installed",
    
    # Low-level ADB (use sparingly)
    "run_adb_command",
    "run_adb_shell_command",
]

