"""Device readiness orchestration layer

Exposes a single ensure_device_ready() entry point that guarantees:
1. Emulator is running
2. ADB is online
3. Frida-server is running
4. App installation has succeeded

No mixing of analysis logic - pure device setup.
"""

import os
import sys

from .emulator import ensure_emulator_online, ensure_device_rooted
from .frida_server import ensure_frida_server_running
from .app_installer import ensure_app_installed

def debug_print(message: str, debug_mode: bool = False):
    """Print debug message to stderr"""
    if debug_mode:
        print(f"[DEBUG] {message}", file=sys.stderr)


def ensure_device_ready(apk_path: str = None, frida_server_path: str = None, debug_mode: bool = False) -> bool:
    """
    Ensure device is ready for analysis.
    
    Guarantees the following in order:
    1. Emulator is running and adb is online
    2. Device is rooted (adb root)
    3. Frida-server is running on device
    4. App is installed (if apk_path provided)
    
    Args:
        apk_path: Optional path to APK to install and verify
        frida_server_path: Optional path to frida-server binary to deploy
        debug_mode: Enable debug output when True
    
    Returns:
        True if all checks pass and device is ready
        False if any check fails
        
    Raises:
        No exceptions - returns False for any failure
    """
    debug_print(f"ensure_device_ready called with apk_path={apk_path}, frida_server_path={frida_server_path}", debug_mode)
    print("\033[93m[*] Preparing device for dynamic analysis...\033[0m")
    print("\033[93m[*] Ensuring device is ready...\033[0m")
    
    # Step 1: Ensure emulator is online and adb is online
    print("\033[93m[*] Checking emulator status and ADB connection...\033[0m")
    debug_print("Step 1: Checking emulator status and ADB connection...", debug_mode)
    if not ensure_emulator_online():
        print("\033[91m[ERROR] Emulator is not online\033[0m")
        debug_print("Step 1: Emulator/ADB check failed", debug_mode)
        return False
    print("\033[92m[OK] Emulator is online and ADB is ready\033[0m")
    debug_print("Step 1: Emulator is online and ADB is ready - OK", debug_mode)
    
    # Step 2: Ensure device is rooted
    print("\033[93m[*] Ensuring device is rooted...\033[0m")
    debug_print("Step 2: Ensuring device is rooted...", debug_mode)
    if not ensure_device_rooted():
        print("\033[91m[ERROR] Failed to root device\033[0m")
        debug_print("Step 2: Device rooting failed", debug_mode)
        return False
    print("\033[92m[OK] Device is rooted\033[0m")
    debug_print("Step 2: Device is rooted - OK", debug_mode)
    
    # Step 3: Ensure frida-server is running
    print("\033[93m[*] Checking frida-server...\033[0m")
    debug_print(f"Step 3: Checking frida-server (path={frida_server_path})...", debug_mode)
    if not ensure_frida_server_running(frida_server_path):
        print("\033[91m[ERROR] Failed to ensure frida-server is running\033[0m")
        debug_print("Step 3: Frida-server check failed", debug_mode)
        return False
    print("\033[92m[OK] Frida-server is running\033[0m")
    debug_print("Step 3: Frida-server is running - OK", debug_mode)
    
    # Step 4: Ensure app is installed (if path provided)
    if apk_path:
        print("\033[93m[*] Checking app installation...\033[0m")
        debug_print(f"Step 4: Checking app installation (apk={apk_path})...", debug_mode)
        if not ensure_app_installed(apk_path):
            print("\033[91m[ERROR] Failed to ensure app is installed\033[0m")
            debug_print("Step 4: App installation check failed", debug_mode)
            return False
        print("\033[92m[OK] App is installed\033[0m")
        debug_print("Step 4: App is installed - OK", debug_mode)
    
    print("\033[92m[OK] Device is ready for analysis\033[0m")
    debug_print("All device readiness checks passed", debug_mode)
    return True


__all__ = [
    "ensure_device_ready",
]
