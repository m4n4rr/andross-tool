import os
import zipfile
import json
from .dex_parser import extract_strings_from_dex_bytes
from .xml_parser import extract_strings_from_xml_bytes
from .arsc_parser import extract_strings_from_arsc
from .patterns import detect_patterns


def run_static_analysis(apk_path, debug_mode=False, skip_filter=False):
    """Run static analysis on APK file"""
    
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

    if debug_mode:
        print(f"\n=== EXTRACTION DEBUG SUMMARY ===")
        print(f"DEX files found: {dex_files_found}")
        print(f"Total DEX strings extracted: {len(dex_strings)}")
        print(f"resources.arsc found: {arsc_found}")
        print(f"Total ARSC strings extracted: {len(arsc_strings)}")
        print(f"XML files found: {xml_files_found}")
        print(f"XML files with extracted strings: {xml_files_parsed}")
        print(f"Total XML strings extracted: {len(xml_strings)}")
        print(f"Total combined strings: {len(all_strings)}\n")

    # Remove duplicates by string + source
    seen = set()
    unique_strings = []
    for s in all_strings:
        key = (s["string"], s.get("dex") or s.get("source"))
        if key not in seen:
            seen.add(key)
            unique_strings.append(s)

    # Save JSON for structured data
    output_file = "useful_strings.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(unique_strings, f, indent=2, ensure_ascii=False)

    print(f"[OK] Saved {len(unique_strings)} unique strings to {output_file}")
    
    # Detect patterns
    detect_patterns(unique_strings)
