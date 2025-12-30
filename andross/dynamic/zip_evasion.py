"""
ZIP Evasion Technique Handler

Handles ZIP evasion techniques commonly used in malware, such as:
- Setting encryption flag bits without actually encrypting files
- Adding malformed extra fields to confuse ZIP parsers
"""

import zipfile
from io import BytesIO


def skip_zip_evasion(apk_path, debug=False):
    """
    Skip ZIP evasion techniques by clearing flag bits and extra fields
    
    This function creates a normalized APK by:
    1. Reading the original APK
    2. Clearing the General Purpose Bit Flag (flag_bits = 0)
    3. Removing extra fields
    4. Writing to a BytesIO buffer
    
    Args:
        apk_path: Path to the potentially evaded APK file
        debug: If True, print debug information
        
    Returns:
        BytesIO: Normalized APK file in memory, or None if failed
    """
    try:
        if debug:
            print(f"[DEBUG] Attempting to skip ZIP evasion techniques...")
        
        normalized_apk = BytesIO()
        
        with zipfile.ZipFile(apk_path, 'r') as zin:
            with zipfile.ZipFile(normalized_apk, 'w', zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    # Clear flag bits (0 = no special handling)
                    item.flag_bits = 0
                    # Remove extra fields that may contain evasion data
                    item.extra = b''
                    
                    # Read file content and write with cleaned metadata
                    data = zin.read(item.filename)
                    zout.writestr(item, data)
        
        if debug:
            print(f"[DEBUG] Successfully normalized APK, buffer size: {len(normalized_apk.getvalue())} bytes")
        
        return normalized_apk
        
    except Exception as e:
        if debug:
            print(f"[DEBUG] Failed to skip ZIP evasion: {type(e).__name__}: {e}")
        return None
