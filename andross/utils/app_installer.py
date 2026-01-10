from .adb import run_adb_install, run_adb_shell_command
from .logger import error, info
from andross.dynamic import extract_package_from_apk


def is_app_installed(package_name: str) -> bool:

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

    try:
        stdout, stderr, exit_code = run_adb_install(apk_path)
        if exit_code != 0:
            error(f"APK installation failed: {stderr}")
            return False
        
        # Check if output contains success indicator
        if 'Success' in stdout or 'success' in stdout:
            return True
        
        # Some adb versions may not show explicit success, check stderr
        if 'Failure' in stderr or 'failure' in stderr or 'Error' in stderr:
            return False
        
        return True
    except Exception as e:
        error(f"Failed to install APK: {e}")
        return False


def ensure_app_installed(apk_path: str) -> bool:

    # First extract package name from APK
    try:
        package_name = extract_package_from_apk(apk_path, debug_mode=False)
        if not package_name:
            error(f"Failed to extract package name from {apk_path}")
            return False
    except Exception as e:
        error(f"Failed to extract package name: {e}")
        return False
    
    # Check if already installed
    if is_app_installed(package_name):
        info(f"App {package_name} is already installed")
        return True
    
    # Not installed, install it
    info(f"Installing {package_name} from {apk_path}...")
    if not install_apk(apk_path):
        error(f"Failed to install {package_name}")
        return False
    
    # Verify installation
    if not is_app_installed(package_name):
        error("Installation reported success but app not found after install")
        return False
    
    info(f"Successfully installed {package_name}")
    return True


__all__ = [
    "is_app_installed",
    "install_apk",
    "ensure_app_installed",
]
