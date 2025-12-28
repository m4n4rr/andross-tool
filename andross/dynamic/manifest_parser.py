import zipfile
import xml.etree.ElementTree as ET
from androguard.core.bytecodes.axml import AXMLPrinter


def extract_package_from_apk(apk_path, debug=False):
    """
    Extract package name from APK by parsing AndroidManifest.xml
    
    Args:
        apk_path: Path to the APK file
        debug: If True, print debug information
        
    Returns:
        str: Package name if found, None otherwise
    """
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            if 'AndroidManifest.xml' not in z.namelist():
                print(f"[ERROR] AndroidManifest.xml not found in APK")
                return None
            
            manifest_bytes = z.read('AndroidManifest.xml')
            
            if debug:
                print(f"[DEBUG] Read {len(manifest_bytes)} bytes from AndroidManifest.xml")
                print(f"[DEBUG] First 20 bytes (hex): {manifest_bytes[:20].hex()}")
            
            # Check if it looks like binary AXML
            is_binary_axml = manifest_bytes[:4] == b'\x03\x00\x08\x00' or manifest_bytes[:4] == b'\x00\x03\x00\x08'
            
            if debug:
                print(f"[DEBUG] Detected binary AXML: {is_binary_axml}")
            
            manifest_string = None
            
            # Try to parse as binary AXML using AXMLPrinter
            if is_binary_axml:
                try:
                    if debug:
                        print(f"[DEBUG] Attempting AXMLPrinter parsing...")
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
            
            # If binary parsing failed or wasn't attempted, try text parsing
            if manifest_string is None:
                try:
                    if debug:
                        print(f"[DEBUG] Attempting text XML decoding...")
                    manifest_string = manifest_bytes.decode('utf-8', errors='ignore')
                    if debug:
                        print(f"[DEBUG] Text decode got {len(manifest_string)} characters")
                except Exception as e:
                    if debug:
                        print(f"[DEBUG] Text decode failed: {type(e).__name__}: {e}")
                    return None
            
            if not manifest_string or manifest_string.strip() == '':
                print(f"[ERROR] Manifest XML is empty after parsing")
                return None
            
            # Parse the XML
            try:
                root = ET.fromstring(manifest_string)
            except ET.ParseError as e:
                if debug:
                    print(f"[DEBUG] XML Parse Error: {e}")
                    print(f"[DEBUG] First 200 chars: {manifest_string[:200]}")
                print(f"[ERROR] Failed to parse manifest XML: {e}")
                return None
            
            # Extract package name
            package_name = root.get('package')
            
            if not package_name:
                print(f"[ERROR] Could not extract package name from manifest")
                if debug:
                    print(f"[DEBUG] Root tag: {root.tag}")
                    print(f"[DEBUG] Root attributes: {root.attrib}")
                return None
            
            if debug:
                print(f"[DEBUG] Successfully extracted package name: {package_name}")
            
            return package_name
            
    except zipfile.BadZipFile:
        print(f"[ERROR] Invalid APK file: {apk_path}")
        return None
    except FileNotFoundError:
        print(f"[ERROR] APK file not found: {apk_path}")
        return None
    except Exception as e:
        print(f"[ERROR] Failed to parse APK manifest: {type(e).__name__}: {e}")
        return None
