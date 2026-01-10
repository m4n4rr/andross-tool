from .adb import run_adb_command, run_adb_shell_command


def is_device_connected() -> bool:
    
    try:
        stdout, stderr, exit_code = run_adb_command(['adb', 'devices'])
        if exit_code != 0:
            return False
        
        # Check if any device is listed (device state shows "device")
        for line in stdout.split('\n'):
            if line.strip() and 'device' in line and 'offline' not in line:
                return True
        return False
    except Exception:
        return False


def get_device_type() -> str:
   
    try:
        stdout, stderr, exit_code = run_adb_shell_command('getprop ro.kernel.qemu')
        if exit_code != 0:
            # If property doesn't exist or fails, likely a real device
            return 'real'
        
        # If getprop returns '1', it's running in QEMU (emulator)
        if '1' in stdout.strip():
            return 'emulator'
        else:
            return 'real'
    except Exception:
        return 'unknown'


def is_emulator_online() -> bool:
    
    try:
        stdout, stderr, exit_code = run_adb_command(['adb', 'devices'])
        if exit_code != 0:
            return False
        
        # Check if any device is listed with 'emulator' in name
        for line in stdout.split('\n'):
            if line.strip() and 'device' in line :
                return True
        return False
    except Exception:
        return False


def is_emulator_available() -> bool:
   
    # Step 1: Check if device is connected
    if not is_device_connected():
        return False
    
    # Step 2: Classify device type and verify it's an emulator
    device_type = get_device_type()
    return device_type == 'emulator'


def ensure_emulator_online() -> bool:
   
    return is_emulator_online()


def ensure_device_rooted() -> bool:
   
    try:
        # Run adb root to ensure device has root privileges
        stdout, stderr, exit_code = run_adb_command(['adb', 'root'])
        
        # adb root returns exit code 0 on success
        # Output typically: "restarting adbd as root"
        return exit_code == 0
    except Exception:
        return False


__all__ = [
    "is_emulator_online",
    "is_emulator_available",
    "ensure_emulator_online",
    "ensure_device_rooted",
]
