import os
from .adb import run_adb_shell_command, run_adb_push
from .logger import error, info, ok, debug as logger_debug

# Debug flag - set via environment variable
DEBUG = os.getenv('FRIDA_DEBUG', 'false').lower() == 'true'

def debug_print(message: str):
    logger_debug(message, DEBUG)


def is_frida_server_running() -> bool:

    try:
        stdout, stderr, exit_code = run_adb_shell_command('ps -A')
        
        if exit_code != 0:
            debug_print(f"ps command failed: {stderr}")
            return False
        
        if 'frida-server' in stdout or 'frida' in stdout:
            return True
        
        return False
    except Exception as e:
        debug_print(f"Exception checking frida-server: {e}")
        return False


def push_frida_server(local_frida_path: str) -> bool:
    if not os.path.exists(local_frida_path):
        error(f"Frida server binary not found at {local_frida_path}")
        return False
    
    try:
        stdout, stderr, exit_code = run_adb_push(local_frida_path, '/data/local/tmp/frida-server')
        
        if exit_code != 0:
            error(f"Failed to push frida-server: {stderr}")
            return False
        ok("Frida-server pushed to device")
        return True
    except Exception as e:
        error(f"Failed to push frida-server: {e}")
        return False


def chmod_frida_server() -> bool:
    try:
        stdout, stderr, exit_code = run_adb_shell_command('chmod +x /data/local/tmp/frida-server')
        
        if exit_code != 0:
            error(f"Failed to chmod frida-server: {stderr}")
            return False
        ok("Frida-server made executable")
        return True
    except Exception as e:
        error(f"Failed to chmod frida-server: {e}")
        return False


def start_frida_server() -> bool:
    try:
        # Verify file exists before starting
        check_stdout, _, check_code = run_adb_shell_command('test -f /data/local/tmp/frida-server && echo EXISTS || echo MISSING')
        
        if 'MISSING' in check_stdout:
            debug_print("ERROR: File not found on device!")
            return False
        
        # Start frida-server in background - use nohup to ensure it persists
        stdout, stderr, exit_code = run_adb_shell_command('nohup /data/local/tmp/frida-server > /dev/null 2>&1 &')
        
        ok("Frida-server start command executed")
        return True
    except Exception as e:
        error(f"Failed to start frida-server: {e}")
        return False


def verify_frida_server_responds() -> bool:
    result = is_frida_server_running()
    if result:
        ok("Frida-server is responding")
    return result


def ensure_frida_server_running(local_frida_path: str = None) -> bool:
    # First check if already running
    if is_frida_server_running():
        info("Frida-server is already running")
        return True
    
    # If not running and local path provided, deploy it
    if local_frida_path:
        info("Frida-server not running, deploying...")
        
        if not push_frida_server(local_frida_path):
            return False
        
        if not chmod_frida_server():
            return False
        
        if not start_frida_server():
            return False
        
        # Give it a moment to start
        import time
        time.sleep(2)
        
        if not verify_frida_server_responds():
            error("Frida-server failed to respond after startup")
            # Collect diagnostic info
            try:
                # Check device architecture
                stdout, _, _ = run_adb_shell_command('getprop ro.product.cpu.abi')
                device_abi = stdout.strip()
                
                # Try to run frida-server and capture error
                stdout, stderr, _ = run_adb_shell_command('/data/local/tmp/frida-server -v')
                
                # Print helpful diagnostic message
                print("\n" + "="*70)
                print("[!] FRIDA-SERVER DEPLOYMENT DIAGNOSTIC")
                print("="*70)
                print(f"Device CPU ABI: {device_abi}")
                print(f"Frida binary provided: {local_frida_path}")
                print("\nPossible causes:")
                print("1. Architecture mismatch:")
                print("   - Device is x86 but binary is x86_64")
                print("   - Device is ARM but binary is x86")
                print("   - Download the correct frida-server for your device:")
                print("     https://github.com/frida/frida/releases")
                print("\n2. Binary corruption during transfer")
                print("   - Try: adb shell 'file /data/local/tmp/frida-server'")
                print("\n3. SELinux restrictions")
                print("   - Try: adb shell 'setenforce 0' (if available)")
                print("="*70 + "\n")
                
            except Exception as e:
                debug_print(f"Could not get troubleshooting info: {e}")
            return False
        
        info("Frida-server deployed and started successfully")
        return True
    
    error("Frida-server not running and no binary path provided")
    return False


__all__ = [
    "is_frida_server_running",
    "push_frida_server",
    "chmod_frida_server",
    "start_frida_server",
    "verify_frida_server_responds",
    "ensure_frida_server_running",
]
