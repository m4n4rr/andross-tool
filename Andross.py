import sys
import os
import zipfile
import json
import subprocess
from dex_parser import extract_strings_from_dex_bytes
from xml_parser import extract_strings_from_xml_bytes
from arsc_parser import extract_strings_from_arsc
from patterns import detect_patterns


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


def run_dynamic_analysis(output_dir):
    """Run dynamic analysis using Frida"""
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Get the script path
    script_path = os.path.join(os.path.dirname(__file__), 'string_hook.js')
    
    if not os.path.exists(script_path):
        print("[ERROR] string_hook.js not found in the script directory")
        return
    
    # Run frida in USB mode with the script
    frida_output_file = os.path.join(output_dir, 'frida_output.txt')
    
    print(f"[*] Starting Frida dynamic analysis...")
    print(f"[*] Target package: com.example.decryption")
    print(f"[*] Saving output to: {frida_output_file}")
    print(f"[*] Press Ctrl+C to stop the analysis")
    
    process = None
    try:
        with open(frida_output_file, 'w', encoding='utf-8') as outfile:
            process = subprocess.Popen(
                ['frida', '-U', '-f', 'com.example.decryption', '-l', script_path],
                stdout=outfile,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Poll the process to allow KeyboardInterrupt to be caught
            while process.poll() is None:
                try:
                    import time
                    time.sleep(0.1)
                except KeyboardInterrupt:
                    raise
            
            if process.returncode == 0:
                print(f"[OK] Frida output saved to {frida_output_file}")
            else:
                print(f"[ERROR] Frida exited with code {process.returncode}")
                
    except KeyboardInterrupt:
        print("\n[*] Stopping Frida analysis...")
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
                print("[OK] Frida stopped gracefully")
            except subprocess.TimeoutExpired:
                process.kill()
                print("[OK] Frida killed forcefully")
        print(f"[OK] Output saved to {frida_output_file}")
    except FileNotFoundError:
        print("[ERROR] frida command not found. Make sure Frida is installed and in PATH")
    except Exception as e:
        print(f"[ERROR] Failed to run Frida: {e}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python Andross.py --static <path/to/app.apk> [--debug] [--skip-filter]")
        print("   or: python Andross.py --dynamic --output <output_dir>")
        sys.exit(1)
    
    # Check if first argument is a mode flag
    first_arg = sys.argv[1]
    
    # Determine mode - MUST be --static or --dynamic
    if first_arg == '--static':
        mode = '--static'
    elif first_arg == '--dynamic':
        mode = '--dynamic'
    else:
        print("[ERROR] Must specify either --static or --dynamic mode as the first argument")
        print("Usage: python Andross.py --static <path/to/app.apk> [--debug] [--skip-filter]")
        print("   or: python Andross.py --dynamic --output <output_dir>")
        sys.exit(1)
    
    # Handle static mode
    if mode == '--static':
        if len(sys.argv) < 3:
            print("[ERROR] Static mode requires APK path")
            print("Usage: python Andross.py --static <path/to/app.apk> [--debug] [--skip-filter]")
            sys.exit(1)
        
        apk_path = sys.argv[2]
        debug_mode = '--debug' in sys.argv
        skip_filter = '--skip-filter' in sys.argv
        
        run_static_analysis(apk_path, debug_mode, skip_filter)
    
    # Handle dynamic mode
    elif mode == '--dynamic':
        if '--output' not in sys.argv:
            print("[ERROR] Dynamic mode requires --output argument")
            print("Usage: python Andross.py --dynamic --output <output_dir>")
            sys.exit(1)
        
        try:
            output_idx = sys.argv.index('--output')
            if output_idx + 1 >= len(sys.argv):
                print("[ERROR] --output argument requires a directory name")
                sys.exit(1)
            
            output_dir = sys.argv[output_idx + 1]
            run_dynamic_analysis(output_dir)
        except Exception as e:
            print(f"[ERROR] {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()