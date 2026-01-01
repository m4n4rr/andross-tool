"""Frida server management layer

Uses adb.py to check if frida-server is running, and if not, deploys and starts it.
"""

import os
import sys
from .adb import run_adb_shell_command, run_adb_push

# Debug flag - set via environment variable
DEBUG = os.getenv('FRIDA_DEBUG', 'false').lower() == 'true'

def debug_print(message: str):
    """Print debug message to stderr"""
    if DEBUG:
        print(f"[DEBUG] {message}", file=sys.stderr)


def is_frida_server_running() -> bool:
    """
    Check if frida-server is running on the device using adb shell ps.
    
    Returns:
        True if frida-server process is found, False otherwise
    """
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
    """
    Push frida-server binary to device.
    
    Args:
        local_frida_path: Path to local frida-server binary
    
    Returns:
        True if successful, False otherwise
    """
    if not os.path.exists(local_frida_path):
        print(f"\033[91m[ERROR] Frida server binary not found at {local_frida_path}\033[0m")
        return False
    
    try:
        stdout, stderr, exit_code = run_adb_push(local_frida_path, '/data/local/tmp/frida-server')
        
        if exit_code != 0:
            print(f"\033[91m[ERROR] Failed to push frida-server: {stderr}\033[0m")
            return False
        print("\033[92m[OK] Frida-server pushed to device\033[0m")
        return True
    except Exception as e:
        print(f"\033[91m[ERROR] Failed to push frida-server: {e}\033[0m")
        return False


def chmod_frida_server() -> bool:
    """
    Make frida-server executable on the device.
    
    Returns:
        True if successful, False otherwise
    """
    try:
        stdout, stderr, exit_code = run_adb_shell_command('chmod +x /data/local/tmp/frida-server')
        
        if exit_code != 0:
            print(f"\033[91m[ERROR] Failed to chmod frida-server: {stderr}\033[0m")
            return False
        print("\033[92m[OK] Frida-server made executable\033[0m")
        return True
    except Exception as e:
        print(f"\033[91m[ERROR] Failed to chmod frida-server: {e}\033[0m")
        return False


def start_frida_server() -> bool:
    """
    Start frida-server on the device.
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # Verify file exists before starting
        check_stdout, _, check_code = run_adb_shell_command('test -f /data/local/tmp/frida-server && echo EXISTS || echo MISSING')
        
        if 'MISSING' in check_stdout:
            debug_print("ERROR: File not found on device!")
            return False
        
        # Start frida-server in background - use nohup to ensure it persists
        stdout, stderr, exit_code = run_adb_shell_command('nohup /data/local/tmp/frida-server > /dev/null 2>&1 &')
        
        print("\033[92m[OK] Frida-server start command executed\033[0m")
        return True
    except Exception as e:
        print(f"\033[91m[ERROR] Failed to start frida-server: {e}\033[0m")
        return False


def verify_frida_server_responds() -> bool:
    """
    Verify that frida-server is responding to connections.
    
    Returns:
        True if frida-server is running and responding, False otherwise
    """
    result = is_frida_server_running()
    if result:
        print("\033[92m[OK] Frida-server is responding\033[0m")
    return result


def ensure_frida_server_running(local_frida_path: str = None) -> bool:
    """
    Ensure frida-server is running on the device. If not, deploy and start it.
    
    Args:
        local_frida_path: Optional path to frida-server binary. If not provided,
                         assumes it's already deployed or just checks if running.
    
    Returns:
        True if frida-server is running, False otherwise
    """
    # First check if already running
    if is_frida_server_running():
        print("\033[93m[*] Frida-server is already running\033[0m")
        return True
    
    # If not running and local path provided, deploy it
    if local_frida_path:
        print("\033[93m[*] Frida-server not running, deploying...\033[0m")
        
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
            print("\033[91m[ERROR] Frida-server failed to respond after startup\033[0m")
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
        
        print("\033[93m[*] Frida-server deployed and started successfully\033[0m")
        return True
    
    print("\033[91m[ERROR] Frida-server not running and no binary path provided\033[0m")
    return False


__all__ = [
    "is_frida_server_running",
    "push_frida_server",
    "chmod_frida_server",
    "start_frida_server",
    "verify_frida_server_responds",
    "ensure_frida_server_running",
]
