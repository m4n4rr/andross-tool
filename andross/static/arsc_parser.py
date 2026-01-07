import io
import tempfile
import os
from androguard.core.apk import APK
from .filters import is_useful_string


def extract_strings_from_arsc(data, debug=False, skip_filter=False):
    """
    Extract strings from resources.arsc using androguard.
    
    Args:
        data: Raw bytes from z.read('resources.arsc')
        debug: Enable debug output
        skip_filter: Skip is_useful_string() filtering
    
    Returns: list of dicts with format:
        {
            "string": <string_value>,
            "source": "resources.arsc",
            "resource_name": <resource_name>,  # e.g., "support_email"
            "resource_type": <resource_type>   # e.g., "string"
        }
    """
    all_strings = []
    tmp_path = None
    
    try:
        import sys
        import zipfile
        
        # Redirect stderr to suppress androguard's verbose logging
        old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        
        try:
            # Create temporary APK file from resources.arsc bytes
            with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp:
                with zipfile.ZipFile(tmp.name, 'w') as zf:
                    zf.writestr('resources.arsc', data)
                tmp_path = tmp.name
            
            # Load APK from temporary file
            apk = APK(tmp_path)
            
            # Get the resource parser from APK
            parser = apk.get_android_resources()
            if parser is None:
                if debug:
                    print("[ARSC DEBUG] No resources found in APK")
                return []
            
            # Get resolved strings (which gives us localized strings with resource IDs as keys)
            resolved = parser.get_resolved_strings()
            if not resolved:
                if debug:
                    print("[ARSC DEBUG] No resolved strings found")
                return []
            
            # Get package name
            packages = parser.get_packages_names()
            if not packages:
                if debug:
                    print("[ARSC DEBUG] No package names found")
                return []
            
            pkg = packages[0]
            strings_data = resolved.get(pkg, {})
            if not strings_data:
                if debug:
                    print(f"[ARSC DEBUG] No string data for package {pkg}")
                return []
            
            # Extract strings from the DEFAULT locale (or first available)
            locale = 'DEFAULT' if 'DEFAULT' in strings_data else next(iter(strings_data.keys()), None)
            if not locale or locale not in strings_data:
                if debug:
                    print("[ARSC DEBUG] No locale found in strings_data")
                return []
            
            locale_strings = strings_data[locale]
            
            # Extract each string with its resource name and type
            for res_id, res_value in locale_strings.items():
                try:
                    # Apply filter if needed
                    if not skip_filter and not is_useful_string(res_value):
                        continue
                    
                    # Get resource name and type using get_resource_xml_name
                    xml_name = parser.get_resource_xml_name(res_id)
                    # xml_name format: "@package:type/name"
                    res_type = ""
                    res_name = ""
                    
                    if ':' in xml_name:
                        parts = xml_name.split(':')
                        type_and_name = parts[1] if len(parts) > 1 else ''
                        if '/' in type_and_name:
                            res_type, res_name = type_and_name.split('/', 1)
                            res_name = res_name.strip()
                            res_type = res_type.strip()
                    
                    all_strings.append({
                        "string": res_value,
                        "source": "resources.arsc",
                        "resource_name": res_name,
                        "resource_type": res_type
                    })
                
                except Exception as e:
                    if debug:
                        print(f"[ARSC DEBUG] Error processing resource ID {res_id}: {e}")
                    continue
            
            if debug and all_strings:
                print(f"[ARSC DEBUG] {len(all_strings)} strings extracted from resources.arsc")
            
            return all_strings
        
        finally:
            # Restore stderr
            sys.stderr = old_stderr
    
    except Exception as e:
        if debug:
            import traceback
            print(f"[ERROR] ARSC extraction failed: {e}")
            traceback.print_exc()
        return []
    
    finally:
        # Clean up temporary file
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
