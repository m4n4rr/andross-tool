from .emulator import ensure_emulator_online, ensure_device_rooted
from .frida_server import ensure_frida_server_running
from .app_installer import ensure_app_installed
from .logger import error, info, ok, debug

def ensure_device_ready(apk_path: str = None, frida_server_path: str = None, debug_mode: bool = False) -> bool:

    debug(f"ensure_device_ready called with apk_path={apk_path}, frida_server_path={frida_server_path}", debug_mode)
    info("Preparing device for dynamic analysis...")
    info("Ensuring device is ready...")
    
    # Step 1: Ensure emulator is online and adb is online
    info("Checking emulator status and ADB connection...")
    debug("Step 1: Checking emulator status and ADB connection...", debug_mode)
    if not ensure_emulator_online():
        error("Emulator is not online")
        debug("Step 1: Emulator/ADB check failed", debug_mode)
        return False
    ok("Emulator is online and ADB is ready")
    debug("Step 1: Emulator is online and ADB is ready - OK", debug_mode)
    
    # Step 2: Ensure device is rooted
    info("Ensuring device is rooted...")
    debug("Step 2: Ensuring device is rooted...", debug_mode)
    if not ensure_device_rooted():
        error("Failed to root device")
        debug("Step 2: Device rooting failed", debug_mode)
        return False
    ok("Device is rooted")
    debug("Step 2: Device is rooted - OK", debug_mode)
    
    # Step 3: Ensure frida-server is running
    info("Checking frida-server...")
    debug(f"Step 3: Checking frida-server (path={frida_server_path})...", debug_mode)
    if not ensure_frida_server_running(frida_server_path):
        error("Failed to ensure frida-server is running")
        debug("Step 3: Frida-server check failed", debug_mode)
        return False
    ok("Frida-server is running")
    debug("Step 3: Frida-server is running - OK", debug_mode)
    
    # Step 4: Ensure app is installed (if path provided)
    if apk_path:
        info("Checking app installation...")
        debug(f"Step 4: Checking app installation (apk={apk_path})...", debug_mode)
        if not ensure_app_installed(apk_path):
            error("Failed to ensure app is installed")
            debug("Step 4: App installation check failed", debug_mode)
            return False
        ok("App is installed")
        debug("Step 4: App is installed - OK", debug_mode)
    
    ok("Device is ready for analysis")
    debug("All device readiness checks passed", debug_mode)
    return True


__all__ = [
    "ensure_device_ready",
]
