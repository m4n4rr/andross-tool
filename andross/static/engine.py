import os
import zipfile
import json
import tempfile
from .dex_parser import extract_strings_from_dex_bytes
from .xml_parser import extract_strings_from_xml_bytes
from .arsc_parser import extract_strings_from_arsc
from .patterns import filter_by_pattern
from ..dynamic.zip_evasion import skip_zip_evasion


def run_static_analysis(apk_path, output_file=None, debug_mode=False, skip_filter=False, pattern_filter=None):
    """Run static analysis on APK file
    
    Args:
        apk_path: Path to APK file
        output_file: Path where to save JSON results. If None, defaults to useful_strings.json
        debug_mode: Enable debug output
        skip_filter: Skip string filtering
        pattern_filter: Optional pattern name to filter results by
    """
    
    if not os.path.exists(apk_path):
        print("[ERROR] APK not found")
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

    # Apply ZIP evasion bypass to handle malware samples with encrypted flags
    try:
        apk_buffer = skip_zip_evasion(apk_path, debug=debug_mode)
        # Check if ZIP evasion was actually needed by comparing sizes or checking for modifications
        # If the buffer is created (not None), evasion was applied
        if apk_buffer:
            zip_evasion_detected = True
            print("[*] ZIP evasion technique detected - applying skip evasion bypass...")
        
        # Write to temporary file since zipfile requires a file path
        with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp:
            tmp.write(apk_buffer.getvalue())
            tmp_path = tmp.name
        apk_to_use = tmp_path
    except Exception as e:
        if debug_mode:
            print(f"[*] ZIP evasion bypass failed ({str(e)}), using original APK")
        apk_to_use = apk_path

    try:
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
    finally:
        # Clean up temporary file if created
        if apk_to_use != apk_path and os.path.exists(apk_to_use):
            os.unlink(apk_to_use)

    if debug_mode:
        CYAN = '\033[36m'
        YELLOW = '\033[33m'
        RESET = '\033[0m'
        print(f"{YELLOW}\n=== EXTRACTION DEBUG SUMMARY ==={RESET}")
        print(f"{CYAN}ZIP evasion detected:{RESET} {zip_evasion_detected}")
        print(f"{CYAN}DEX files found:{RESET} {dex_files_found}")
        print(f"{CYAN}Total DEX strings extracted:{RESET} {len(dex_strings)}")
        print(f"{CYAN}resources.arsc found:{RESET} {arsc_found}")
        print(f"{CYAN}Total ARSC strings extracted:{RESET} {len(arsc_strings)}")
        print(f"{CYAN}XML files found:{RESET} {xml_files_found}")
        print(f"{CYAN}XML files with extracted strings:{RESET} {xml_files_parsed}")
        print(f"{CYAN}Total XML strings extracted:{RESET} {len(xml_strings)}")
        print(f"{CYAN}Total combined strings:{RESET} {len(all_strings)}\n")

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
            print(f"[ERROR] Unknown pattern(s): {', '.join(filter_list)}")
            return
        strings_to_save = filtered
        pattern_desc = ', '.join(applied_patterns)
        print(f"[*] Filtered by pattern(s) '{pattern_desc}': {len(strings_to_save)} matches")
    
    # Save JSON
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(strings_to_save, f, indent=2, ensure_ascii=False)

    YELLOW = '\033[33m'
    RESET = '\033[0m'
    print(f"{YELLOW}[OK] Saved {len(strings_to_save)} strings to {output_file}{RESET}")
