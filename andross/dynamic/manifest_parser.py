import zipfile
import xml.etree.ElementTree as ET
import tempfile
import os
import re

from androguard.core.axml import AXMLPrinter
from androguard.core.apk import APK

from .zip_evasion import skip_zip_evasion


def extract_package_from_apk(apk_path, debug=False):
    """
    Extract package name from APK by parsing AndroidManifest.xml
    
    Attempts normal extraction first, then falls back to ZIP evasion
    skipping if encryption or other evasion techniques are detected.
    
    Args:
        apk_path: Path to the APK file
        debug: If True, print debug information
        
    Returns:
        str: Package name if found, None otherwise
    """
    print("\033[93m[*] Extracting package name from APK...\033[0m")
    
    # First attempt: normal extraction
    result = _extract_from_zipfile(apk_path, None, debug)
    if result is not None:
        return result
    
    # Second attempt: skip ZIP evasion techniques
    print("\033[93m[*] Detected ZIP evasion technique, attempting to skip...\033[0m")
    normalized_apk = skip_zip_evasion(apk_path, debug)
    
    if normalized_apk is not None:
        result = _extract_from_zipfile(None, normalized_apk, debug)
        if result is not None:
            print("\033[92m[OK] Successfully bypassed ZIP evasion technique\033[0m")
            return result
    
    # Both attempts failed
    print("\033[91m[ERROR] Failed to extract package name from APK\033[0m")
    return None


def _extract_from_zipfile(apk_path, apk_buffer, debug=False):
    """
    Internal helper to extract package name from either a file path or BytesIO buffer
    
    Args:
        apk_path: Path to APK file (or None if using buffer)
        apk_buffer: BytesIO buffer with APK (or None if using file path)
        debug: If True, print debug information
        
    Returns:
        str: Package name if found, None otherwise
    """
    try:
        # Use buffer if provided, otherwise open file
        if apk_buffer is not None:
            apk_buffer.seek(0)
            z = zipfile.ZipFile(apk_buffer, 'r')
        else:
            z = zipfile.ZipFile(apk_path, 'r')
        
        with z:
            if 'AndroidManifest.xml' not in z.namelist():
                if debug:
                    print("[DEBUG] AndroidManifest.xml not found in APK")
                return None
            
            manifest_bytes = z.read('AndroidManifest.xml')
            
            if debug:
                print("[DEBUG] Read {len(manifest_bytes)} bytes from AndroidManifest.xml")
                print("[DEBUG] First 20 bytes (hex): {manifest_bytes[:20].hex()}")
            
            # Check if it looks like binary AXML
            is_binary_axml = manifest_bytes[:4] == b'\x03\x00\x08\x00' or manifest_bytes[:4] == b'\x00\x03\x00\x08'
            
            if debug:
                print(f"[DEBUG] Detected binary AXML: {is_binary_axml}")
            
            manifest_string = None
            
            # Try to parse as binary AXML using AXMLPrinter
            if is_binary_axml:
                try:
                    if debug:
                        print("[DEBUG] Attempting AXMLPrinter parsing...")
                    printer = AXMLPrinter(manifest_bytes)
                    
                    # get_buff() returns UTF-8 encoded bytes
                    manifest_bytes_result = printer.get_buff()
                    manifest_string = manifest_bytes_result.decode('utf-8', errors='ignore')
                    
                    if debug:
                        print(f"[DEBUG] AXMLPrinter succeeded, got {len(manifest_string)} characters")
                        print(f"[DEBUG] First 150 chars: {manifest_string[:150]}")
                except Exception as e:
                    if debug:
                        print(f"[DEBUG] AXMLPrinter failed: {type(e).__name__}: {e}")
                    manifest_string = None
            
            # If AXMLPrinter failed, try using androguard's APK class
            if manifest_string is None and apk_path is not None:
                try:
                    if debug:
                        print("[DEBUG] Attempting androguard APK parser...")
                    apk = APK(apk_path)
                    package_name = apk.get_package()
                    
                    if package_name:
                        if debug:
                            print(f"[DEBUG] APK parser succeeded, got package: {package_name}")
                        return package_name
                    else:
                        if debug:
                            print("[DEBUG] APK parser found no package name")
                except Exception as e:
                    if debug:
                        print(f"[DEBUG] APK parser failed: {type(e).__name__}: {e}")
            
            # Also try APK parser with buffer if available
            if manifest_string is None and apk_buffer is not None:
                try:
                    if debug:
                        print("[DEBUG] Attempting androguard APK parser with buffer...")
                    
                    # Write buffer to temporary file since APK class requires a file path
                    with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as tmp_file:
                        apk_buffer.seek(0)
                        tmp_file.write(apk_buffer.getvalue())
                        tmp_path = tmp_file.name
                    
                    try:
                        apk = APK(tmp_path)
                        package_name = apk.get_package()
                        
                        if package_name:
                            if debug:
                                print(f"[DEBUG] APK parser (buffer) succeeded, got package: {package_name}")
                            return package_name
                        else:
                            if debug:
                                print("[DEBUG] APK parser (buffer) found no package name")
                    finally:
                        # Clean up temporary file
                        try:
                            os.unlink(tmp_path)
                        except Exception:
                            pass
                except Exception as e:
                    if debug:
                        print(f"[DEBUG] APK parser (buffer) failed: {type(e).__name__}: {e}")
            
            # If all parsing attempts failed, try binary pattern search for package name
            if manifest_string is None:
                try:
                    if debug:
                        print("[DEBUG] Attempting binary pattern search for package name...")
                    
                    # Search for common package name patterns in the binary data
                    # Package names typically follow Java naming: com.example.app
                    # Look for strings that match package name pattern
                    # Search for null-terminated ASCII strings that look like package names
                    pattern = rb'(com|org|net|io|dev|app)\.([a-zA-Z0-9_\.]+)'
                    matches = re.findall(pattern, manifest_bytes)
                    
                    if matches:
                        # Try to find the most likely package name (usually first or shortest valid one)
                        for match in matches:
                            potential_package = (match[0] + b'.' + match[1]).decode('utf-8', errors='ignore')
                            # Validate it looks like a real package name
                            if potential_package.count('.') >= 1 and len(potential_package) > 4 and len(potential_package) < 200:
                                if debug:
                                    print(f"[DEBUG] Binary search found potential package: {potential_package}")
                                return potential_package
                    
                    if debug:
                        print("[DEBUG] Binary pattern search found no valid package names")
                except Exception as e:
                    if debug:
                        print(f"[DEBUG] Binary pattern search failed: {type(e).__name__}: {e}")
            
            # If binary parsing failed or wasn't attempted, try text parsing
            # BUT: only attempt text parsing if it wasn't detected as binary AXML
            # (parsing binary data as text produces garbage)
            if manifest_string is None and not is_binary_axml:
                try:
                    if debug:
                        print("[DEBUG] Attempting text XML decoding...")
                    manifest_string = manifest_bytes.decode('utf-8', errors='ignore')
                    if debug:
                        print(f"[DEBUG] Text decode got {len(manifest_string)} characters")
                except Exception as e:
                    if debug:
                        print(f"[DEBUG] Text decode failed: {type(e).__name__}: {e}")
                    return None
            
            if not manifest_string or manifest_string.strip() == '':
                if debug:
                    print("[DEBUG] Manifest XML is empty after parsing")
                return None
            
            # Parse the XML
            try:
                root = ET.fromstring(manifest_string)
            except ET.ParseError as e:
                if debug:
                    print(f"[DEBUG] XML Parse Error: {e}")
                    print(f"[DEBUG] First 200 chars: {manifest_string[:200]}")
                return None
            
            # Extract package name
            package_name = root.get('package')
            
            if not package_name:
                if debug:
                    print("[DEBUG] Could not extract package name from manifest")
                    print(f"[DEBUG] Root tag: {root.tag}")
                    print(f"[DEBUG] Root attributes: {root.attrib}")
                return None
            
            if debug:
                print(f"[DEBUG] Successfully extracted package name: {package_name}")
            
            return package_name
            
    except zipfile.BadZipFile as e:
        if debug:
            print(f"[DEBUG] BadZipFile error: {e}")
        return None
    except FileNotFoundError as e:
        if debug:
            print(f"[DEBUG] File not found error: {e}")
        return None
    except Exception as e:
        if debug:
            print(f"[DEBUG] Unexpected error: {type(e).__name__}: {e}")
        return None
