import zipfile
from io import BytesIO

from ..utils.logger import debug


def skip_zip_evasion(apk_path, debug_mode=False):
    try:
        debug("Attempting to skip ZIP evasion techniques...", debug_mode)
        
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
        
        debug(f"Successfully normalized APK, buffer size: {len(normalized_apk.getvalue())} bytes", debug_mode)
        
        return normalized_apk
        
    except Exception as e:
        debug(f"Failed to skip ZIP evasion: {type(e).__name__}: {e}", debug_mode)
        return None
