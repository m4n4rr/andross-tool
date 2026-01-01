"""App installation management layer

Uses adb.py and extract_package_from_apk to verify and install APKs.
"""

from .adb import run_adb_install, run_adb_shell_command
from andross.dynamic import extract_package_from_apk


def is_app_installed(package_name: str) -> bool:
    """
    Check if an app is installed on the device.
    
    Args:
        package_name: Package name to check (e.g., 'com.example.app')
    
    Returns:
        True if app is installed, False if not installed or error occurs
    """
    try:
        stdout, stderr, exit_code = run_adb_shell_command(f'pm list packages | grep {package_name}')
        if exit_code != 0:
            # grep returns non-zero if no match found
            return False
        
        # If we get output, package is installed
        return len(stdout.strip()) > 0
    except Exception:
        return False


def install_apk(apk_path: str) -> bool:
    """
    Install an APK on the device.
    
    Args:
        apk_path: Path to the APK file
    
    Returns:
        True if installation successful, False otherwise
    """
    try:
        stdout, stderr, exit_code = run_adb_install(apk_path)
        if exit_code != 0:
            print(f"\033[91m[ERROR] APK installation failed: {stderr}\033[0m")
            return False
        
        # Check if output contains success indicator
        if 'Success' in stdout or 'success' in stdout:
            return True
        
        # Some adb versions may not show explicit success, check stderr
        if 'Failure' in stderr or 'failure' in stderr or 'Error' in stderr:
            return False
        
        return True
    except Exception as e:
        print(f"\033[91m[ERROR] Failed to install APK: {e}\033[0m")
        return False


def ensure_app_installed(apk_path: str) -> bool:
    """
    Ensure an app is installed. Installs it if not already present.
    
    Args:
        apk_path: Path to the APK file
    
    Returns:
        True if app is installed (was already installed or successfully installed),
        False if installation failed
    """
    # First extract package name from APK
    try:
        package_name = extract_package_from_apk(apk_path, debug=False)
        if not package_name:
            print(f"\033[91m[ERROR] Failed to extract package name from {apk_path}\033[0m")
            return False
    except Exception as e:
        print(f"\033[91m[ERROR] Failed to extract package name: {e}\033[0m")
        return False
    
    # Check if already installed
    if is_app_installed(package_name):
        print(f"\033[93m[*] App {package_name} is already installed\033[0m")
        return True
    
    # Not installed, install it
    print(f"\033[93m[*] Installing {package_name} from {apk_path}...\033[0m")
    if not install_apk(apk_path):
        print(f"\033[91m[ERROR] Failed to install {package_name}\033[0m")
        return False
    
    # Verify installation
    if not is_app_installed(package_name):
        print("\033[91m[ERROR] Installation reported success but app not found after install\033[0m")
        return False
    
    print(f"\033[93m[*] Successfully installed {package_name}\033[0m")
    return True


__all__ = [
    "is_app_installed",
    "install_apk",
    "ensure_app_installed",
]
