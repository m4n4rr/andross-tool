"""ADB command execution layer

Low-level ADB interface. Executes adb commands and returns raw output without
interpretation or assumptions. This is the only place that directly executes
adb commands in the entire utils module.
"""

import subprocess
from typing import Tuple


def run_adb_command(command: list, shell_command: str = None) -> Tuple[str, str, int]:
    """
    Execute an ADB command and return stdout, stderr, and exit code.
    
    Args:
        command: List of command arguments for subprocess (e.g., ['adb', 'shell', 'ls'])
        shell_command: Optional raw shell command string (alternative to command list)
    
    Returns:
        Tuple of (stdout, stderr, exit_code)
        
    Raises:
        FileNotFoundError: If adb is not found in PATH
    """
    try:
        if shell_command:
            process = subprocess.Popen(
                shell_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        else:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        
        stdout, stderr = process.communicate()
        return stdout, stderr, process.returncode
    except FileNotFoundError:
        raise FileNotFoundError("adb not found in PATH")


def run_adb_shell_command(shell_cmd: str) -> Tuple[str, str, int]:
    """
    Execute an ADB shell command.
    
    Args:
        shell_cmd: Shell command to run on the device (e.g., 'ps -A')
    
    Returns:
        Tuple of (stdout, stderr, exit_code)
    """
    command = ['adb', 'shell', shell_cmd]
    return run_adb_command(command)


def run_adb_push(local_path: str, remote_path: str) -> Tuple[str, str, int]:
    """
    Push a file to the device.
    
    Args:
        local_path: Path to local file
        remote_path: Destination path on device
    
    Returns:
        Tuple of (stdout, stderr, exit_code)
    """
    command = ['adb', 'push', local_path, remote_path]
    return run_adb_command(command)


def run_adb_install(apk_path: str) -> Tuple[str, str, int]:
    """
    Install an APK on the device.
    
    Args:
        apk_path: Path to APK file
    
    Returns:
        Tuple of (stdout, stderr, exit_code)
    """
    command = ['adb', 'install', apk_path]
    return run_adb_command(command)


__all__ = [
    "run_adb_command",
    "run_adb_shell_command",
    "run_adb_push",
    "run_adb_install",
]
