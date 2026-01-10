import subprocess
from typing import Tuple


def run_adb_command(command: list, shell_command: str = None) -> Tuple[str, str, int]:
    
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
  
    command = ['adb', 'shell', shell_cmd]
    return run_adb_command(command)


def run_adb_push(local_path: str, remote_path: str) -> Tuple[str, str, int]:
    
    command = ['adb', 'push', local_path, remote_path]
    return run_adb_command(command)


def run_adb_install(apk_path: str) -> Tuple[str, str, int]:
   
    command = ['adb', 'install', apk_path]
    return run_adb_command(command)


__all__ = [
    "run_adb_command",
    "run_adb_shell_command",
    "run_adb_push",
    "run_adb_install",
]
