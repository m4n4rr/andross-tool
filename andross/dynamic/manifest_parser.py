import zipfile
import xml.etree.ElementTree as ET
import tempfile
import os
import re

from androguard.core.axml import AXMLPrinter
from androguard.core.apk import APK

from .zip_evasion import skip_zip_evasion
from ..utils.logger import error, info, ok, debug


def extract_package_from_apk(apk_path, debug_mode=False):
    info("Extracting package name from APK...")
    
    # First attempt: normal extraction
    result = _extract_from_zipfile(apk_path, None, debug_mode)
    if result is not None:
        return result
    
    # Second attempt: skip ZIP evasion techniques
    info("Detected ZIP evasion technique, attempting to skip...")
    normalized_apk = skip_zip_evasion(apk_path, debug_mode)
    
    if normalized_apk is not None:
        result = _extract_from_zipfile(None, normalized_apk, debug_mode)
        if result is not None:
            ok("Successfully bypassed ZIP evasion technique")
            return result
    
    # Both attempts failed
    error("Failed to extract package name from APK")
    return None


def _extract_from_zipfile(apk_path, apk_buffer, debug_mode=False):
    try:
        # Use buffer if provided, otherwise open file
        if apk_buffer is not None:
            apk_buffer.seek(0)
            z = zipfile.ZipFile(apk_buffer, 'r')
        else:
            z = zipfile.ZipFile(apk_path, 'r')
        
        with z:
            if 'AndroidManifest.xml' not in z.namelist():
                debug("AndroidManifest.xml not found in APK", debug_mode)
                return None
            
            manifest_bytes = z.read('AndroidManifest.xml')
            
            debug(f"Read {len(manifest_bytes)} bytes from AndroidManifest.xml", debug_mode)
            debug(f"First 20 bytes (hex): {manifest_bytes[:20].hex()}", debug_mode)
            
            # Check if it looks like binary AXML
            is_binary_axml = manifest_bytes[:4] == b'\x03\x00\x08\x00' or manifest_bytes[:4] == b'\x00\x03\x00\x08'
            
            debug(f"Detected binary AXML: {is_binary_axml}", debug_mode)
            
            manifest_string = None
            
            # Try to parse as binary AXML using AXMLPrinter
            if is_binary_axml:
                try:
                    debug("Attempting AXMLPrinter parsing...", debug_mode)
                    printer = AXMLPrinter(manifest_bytes)
                    
                    # get_buff() returns UTF-8 encoded bytes
                    manifest_bytes_result = printer.get_buff()
                    manifest_string = manifest_bytes_result.decode('utf-8', errors='ignore')
                    
                    debug(f"AXMLPrinter succeeded, got {len(manifest_string)} characters", debug_mode)
                    debug(f"First 150 chars: {manifest_string[:150]}", debug_mode)
                except Exception as e:
                    debug(f"AXMLPrinter failed: {type(e).__name__}: {e}", debug_mode)
                    manifest_string = None
            
            # If AXMLPrinter failed, try using androguard's APK class
            if manifest_string is None and apk_path is not None:
                try:
                    debug("Attempting androguard APK parser...", debug_mode)
                    apk = APK(apk_path)
                    package_name = apk.get_package()
                    
                    if package_name:
                        debug(f"APK parser succeeded, got package: {package_name}", debug_mode)
                        return package_name
                    else:
                        debug("APK parser found no package name", debug_mode)
                except Exception as e:
                    debug(f"APK parser failed: {type(e).__name__}: {e}", debug_mode)
            
            # Also try APK parser with buffer if available
            if manifest_string is None and apk_buffer is not None:
                try:
                    debug("Attempting androguard APK parser with buffer...", debug_mode)
                    
                    # Write buffer to temporary file since APK class requires a file path
                    with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as tmp_file:
                        apk_buffer.seek(0)
                        tmp_file.write(apk_buffer.getvalue())
                        tmp_path = tmp_file.name
                    
                    try:
                        apk = APK(tmp_path)
                        package_name = apk.get_package()
                        
                        if package_name:
                            debug(f"APK parser (buffer) succeeded, got package: {package_name}", debug_mode)
                            return package_name
                        else:
                            debug("APK parser (buffer) found no package name", debug_mode)
                    finally:
                        # Clean up temporary file
                        try:
                            os.unlink(tmp_path)
                        except Exception:
                            pass
                except Exception as e:
                    debug(f"APK parser (buffer) failed: {type(e).__name__}: {e}", debug_mode)
            
            # If all parsing attempts failed, try binary pattern search for package name
            if manifest_string is None:
                try:
                    debug("Attempting binary pattern search for package name...", debug_mode)
                    
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
                                debug(f"Binary search found potential package: {potential_package}", debug_mode)
                                return potential_package
                    
                    debug("Binary pattern search found no valid package names", debug_mode)
                except Exception as e:
                    debug(f"Binary pattern search failed: {type(e).__name__}: {e}", debug_mode)
            
            # If binary parsing failed or wasn't attempted, try text parsing
            # BUT: only attempt text parsing if it wasn't detected as binary AXML
            # (parsing binary data as text produces garbage)
            if manifest_string is None and not is_binary_axml:
                try:
                    debug("Attempting text XML decoding...", debug_mode)
                    manifest_string = manifest_bytes.decode('utf-8', errors='ignore')
                    debug(f"Text decode got {len(manifest_string)} characters", debug_mode)
                except Exception as e:
                    debug(f"Text decode failed: {type(e).__name__}: {e}", debug_mode)
                    return None
            
            if not manifest_string or manifest_string.strip() == '':
                debug("Manifest XML is empty after parsing", debug_mode)
                return None
            
            # Parse the XML
            try:
                root = ET.fromstring(manifest_string)
            except ET.ParseError as e:
                debug(f"XML Parse Error: {e}", debug_mode)
                debug(f"First 200 chars: {manifest_string[:200]}", debug_mode)
                return None
            
            # Extract package name
            package_name = root.get('package')
            
            if not package_name:
                debug("Could not extract package name from manifest", debug_mode)
                debug(f"Root tag: {root.tag}", debug_mode)
                debug(f"Root attributes: {root.attrib}", debug_mode)
                return None
            
            debug(f"Successfully extracted package name: {package_name}", debug_mode)
            
            return package_name
            
    except (zipfile.BadZipFile, RuntimeError) as e:
        error_reason = "encrypted files detected" if isinstance(e, RuntimeError) and "encrypted" in str(e) else "BadZipFile error"
        debug(f"{error_reason}: {e}", debug_mode)
        return None
    except FileNotFoundError as e:
        debug(f"File not found error: {e}", debug_mode)
        return None
    except Exception as e:
        debug(f"Unexpected error: {type(e).__name__}: {e}", debug_mode)
        return None

