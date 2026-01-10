import os
import zipfile
import json
import tempfile

from .dex_parser import extract_strings_from_dex_bytes
from .xml_parser import extract_strings_from_xml_bytes
from .arsc_parser import extract_strings_from_arsc
from .patterns import filter_by_pattern
from andross.dynamic import skip_zip_evasion
from ..utils.logger import error, info, ok


def run_static_analysis(apk_path, output_file=None, debug_mode=False, skip_filter=False, pattern_filter=None):

    if not os.path.exists(apk_path):
        error("APK not found")
        return

    all_strings = []
    xml_strings = []
    dex_strings = []
    arsc_strings = []
    
    # Counters
    xml_files_found = 0
    xml_files_parsed = 0
    dex_files_found = 0
    arsc_found = False
    zip_evasion_detected = False

    # Try normal ZIP analysis first
    apk_to_use = apk_path
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            # Count and process DEX files
            for f in z.namelist():
                if f.endswith(".dex"):
                    dex_files_found += 1
                    dex_bytes = z.read(f)
                    extracted = extract_strings_from_dex_bytes(dex_bytes, f)
                    dex_strings.extend(extracted)
                    all_strings.extend(extracted)
            
            # Extract from resources.arsc
            if 'resources.arsc' in z.namelist():
                arsc_found = True
                arsc_bytes = z.read('resources.arsc')
                extracted = extract_strings_from_arsc(arsc_bytes, debug=debug_mode, skip_filter=skip_filter)
                arsc_strings.extend(extracted)
                all_strings.extend(extracted)
            
            # Count and process XML resource files
            for f in z.namelist():
                if f.startswith('res/') and f.endswith('.xml'):
                    xml_files_found += 1
                    xml_bytes = z.read(f)
                    extracted = extract_strings_from_xml_bytes(xml_bytes, f, debug=debug_mode, skip_filter=skip_filter)
                    if extracted:
                        xml_files_parsed += 1
                        xml_strings.extend(extracted)
                        all_strings.extend(extracted)
    except (zipfile.BadZipFile, RuntimeError) as e:
        # Normal ZIP parsing failed (BadZipFile) or files are encrypted (RuntimeError), try ZIP evasion bypass
        if debug_mode:
            error_reason = "encrypted files detected" if isinstance(e, RuntimeError) and "encrypted" in str(e) else "ZIP parsing failed"
            info(f"{error_reason}, attempting ZIP evasion bypass...")
        
        try:
            apk_buffer = skip_zip_evasion(apk_path, debug=debug_mode)
            if apk_buffer:
                zip_evasion_detected = True
                info("ZIP evasion technique detected - applying skip evasion bypass...")
                
                # Write to temporary file since zipfile requires a file path
                with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp:
                    tmp.write(apk_buffer.getvalue())
                    tmp_path = tmp.name
                apk_to_use = tmp_path
                
                # Retry analysis with normalized APK
                with zipfile.ZipFile(apk_to_use, 'r') as z:
                    # Count and process DEX files
                    for f in z.namelist():
                        if f.endswith(".dex"):
                            dex_files_found += 1
                            dex_bytes = z.read(f)
                            extracted = extract_strings_from_dex_bytes(dex_bytes, f)
                            dex_strings.extend(extracted)
                            all_strings.extend(extracted)
                    
                    # Extract from resources.arsc
                    if 'resources.arsc' in z.namelist():
                        arsc_found = True
                        arsc_bytes = z.read('resources.arsc')
                        extracted = extract_strings_from_arsc(arsc_bytes, debug=debug_mode, skip_filter=skip_filter)
                        arsc_strings.extend(extracted)
                        all_strings.extend(extracted)
                    
                    # Count and process XML resource files
                    for f in z.namelist():
                        if f.startswith('res/') and f.endswith('.xml'):
                            xml_files_found += 1
                            xml_bytes = z.read(f)
                            extracted = extract_strings_from_xml_bytes(xml_bytes, f, debug=debug_mode, skip_filter=skip_filter)
                            if extracted:
                                xml_files_parsed += 1
                                xml_strings.extend(extracted)
                                all_strings.extend(extracted)
        except Exception as e:
            if debug_mode:
                error(f"ZIP evasion bypass failed: {str(e)}")
            # Continue with original APK attempt already done above
    finally:
        # Clean up temporary file if created
        if apk_to_use != apk_path and os.path.exists(apk_to_use):

            os.unlink(apk_to_use)

    if debug_mode:
        info("\n=== EXTRACTION DEBUG SUMMARY ===")
        info(f"ZIP evasion detected: {zip_evasion_detected}")
        info(f"DEX files found: {dex_files_found}")
        info(f"Total DEX strings extracted: {len(dex_strings)}")
        info(f"resources.arsc found: {arsc_found}")
        info(f"Total ARSC strings extracted: {len(arsc_strings)}")
        info(f"XML files found: {xml_files_found}")
        info(f"XML files with extracted strings: {xml_files_parsed}")
        info(f"Total XML strings extracted: {len(xml_strings)}")
        info(f"Total combined strings: {len(all_strings)}\n")

    # Remove duplicates by string + source
    seen = set()
    unique_strings = []
    for s in all_strings:
        key = (s["string"], s.get("dex") or s.get("source"))
        if key not in seen:
            seen.add(key)
            unique_strings.append(s)

    # Save JSON for structured data
    if output_file is None:
        output_file = "useful_strings.json"
    
    # Create parent directory if it doesn't exist
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Apply pattern filter if specified
    strings_to_save = unique_strings
    if pattern_filter:
        # pattern_filter can be a list of patterns, a single pattern, or "all"
        filtered, applied_patterns = filter_by_pattern(unique_strings, pattern_filter)
        if filtered is None:
            # Find which pattern(s) are invalid
            filter_list = pattern_filter if isinstance(pattern_filter, list) else [pattern_filter]
            error(f"Unknown pattern(s): {', '.join(filter_list)}")
            return
        strings_to_save = filtered
        pattern_desc = ', '.join(applied_patterns)
        info(f"Filtered by pattern(s) '{pattern_desc}': {len(strings_to_save)} matches")
    
    # Save JSON
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(strings_to_save, f, indent=2, ensure_ascii=False)

    ok(f"Saved {len(strings_to_save)} strings to {output_file}")
