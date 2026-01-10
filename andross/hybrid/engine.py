"""Hybrid analysis engine - combines dynamic and static analysis

Orchestrates a two-phase analysis process:
1. Dynamic phase: Runs Frida with DEX interception script
2. Static phase: Analyzes intercepted DEX bytes using static extraction
"""

import os
import subprocess
import json
import time

from andross.dynamic.manifest_parser import extract_package_from_apk
from andross.static.dex_parser import extract_strings_from_dex_bytes
from andross.static.patterns import filter_by_pattern


def run_hybrid_analysis(output_file, apk_path, debug_mode=False, skip_filter=False, pattern_filter=None, frida_server_path=None):
    """Run hybrid analysis (dynamic DEX interception + static string extraction)
    
    This function orchestrates a two-phase analysis:
    1. Dynamic phase: Use Frida with dex_interceptor.js to intercept and extract DEX at runtime
    2. Static phase: Parse the intercepted DEX bytes and extract strings using static analysis
    
    Args:
        output_file: File path where to save processed JSON results
        apk_path: Path to the APK file
        debug_mode: Enable debug output
        skip_filter: Skip string filtering
        pattern_filter: Optional pattern name(s) to filter results by
        frida_server_path: Optional path to frida-server binary
        
    Returns:
        True if analysis completes successfully, False otherwise
    """
    
    if not os.path.exists(apk_path):
        print("\033[91m[ERROR] APK not found\033[0m")
        return False
    
    # Create parent directory if it doesn't exist
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    print("\033[93m[*] Starting hybrid analysis...\033[0m")
    
    # Extract package name from APK
    try:
        print("\033[93m[*] Extracting package name from APK...\033[0m")
        package_name = extract_package_from_apk(apk_path, debug_mode=debug_mode)
        if not package_name:
            print("\033[91m[ERROR] Failed to extract package name from APK\033[0m")
            return False
    except Exception as e:
        print(f"\033[91m[ERROR] Failed to extract package name: {e}\033[0m")
        return False
    
    print(f"\033[93m[*] Target package: {package_name}\033[0m")
    
    # Phase 1: Dynamic DEX Interception
    print("\033[93m[*] Phase 1: Running dynamic DEX interception...\033[0m")
    intercepted_dex_bytes = _run_dex_interception(apk_path, package_name, debug_mode, frida_server_path)
    
    if not intercepted_dex_bytes:
        print("\033[91m[ERROR] Failed to intercept DEX at runtime\033[0m")
        return False
    
    print(f"\033[92m[OK] Successfully intercepted DEX ({len(intercepted_dex_bytes)} bytes)\033[0m")
    if debug_mode:
        print(f"[DEBUG] Intercepted DEX size: {len(intercepted_dex_bytes)} bytes")
    
    # Phase 2: Static String Extraction from Intercepted DEX
    print("\033[93m[*] Phase 2: Running static analysis on intercepted DEX...\033[0m")
    all_strings = _extract_strings_from_intercepted_dex(intercepted_dex_bytes, debug_mode, skip_filter)
    
    if not all_strings:
        print("\033[93m[*] No strings found in intercepted DEX\033[0m")
        all_strings = []
    else:
        print(f"\033[92m[OK] Extracted {len(all_strings)} strings from intercepted DEX\033[0m")
    
    # Apply pattern filtering if specified
    if pattern_filter and not skip_filter:
        print(f"\033[93m[*] Applying pattern filter: {pattern_filter}\033[0m")
        all_strings = _filter_strings_by_pattern(all_strings, pattern_filter)
        print(f"\033[92m[OK] {len(all_strings)} strings match pattern filter\033[0m")
    
    # Save results
    _save_hybrid_results(output_file, all_strings, skip_filter, pattern_filter, debug_mode)
    
    print(f"\033[92m[OK] Hybrid analysis complete. Results saved to: {output_file}\033[0m")
    return True


def _run_dex_interception(apk_path, package_name, debug_mode, frida_server_path):
    """Run Frida with DEX interceptor script and capture DEX bytes in-memory
    
    Args:
        apk_path: Path to APK
        package_name: Package name to target
        debug_mode: Enable debug output
        frida_server_path: Optional path to frida-server
        
    Returns:
        bytes: Intercepted DEX bytes if successful, None otherwise
    """
    
    # Get the dex_interceptor.js script path
    script_path = os.path.join(os.path.dirname(__file__), 'dex_interceptor.js')
    
    if not os.path.exists(script_path):
        print(f"[ERROR] dex_interceptor.js not found at {script_path}")
        return None
    
    print(f"\033[93m[*] Loading DEX interceptor script: {script_path}\033[0m")
    
    # Build Frida command
    frida_cmd = ['frida', '-U', '-f', package_name, '-l', script_path]
    
    if debug_mode:
        print(f"[DEBUG] Frida command: {' '.join(frida_cmd)}")
    
    process = None
    intercepted_bytes = None
    
    try:
        print("\033[93m[*] Launching app with Frida for DEX interception...\033[0m")
        
        # Run Frida for 30 seconds to give app time to load DEX
        process = subprocess.Popen(
            frida_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        # Capture DEX payload from Frida output
        intercepted_bytes = _capture_dex_from_frida_output(process, debug_mode)
        
        # Terminate Frida
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        
    except Exception as e:
        print(f"\033[91m[ERROR] Frida execution failed: {e}\033[0m")
        if debug_mode:
            print(f"[DEBUG] Exception details: {e}")
        if process and process.poll() is None:
            process.terminate()
    
    return intercepted_bytes


def _capture_dex_from_frida_output(process, debug_mode):
    """Capture DEX bytes from Frida output (hex encoded)
    
    Args:
        process: Frida subprocess
        debug_mode: Enable debug output
        
    Returns:
        bytes: Decoded DEX bytes if successful, None otherwise
    """
    
    start_time = time.time()
    timeout = 30  # 30 second timeout
    payload_started = False
    hex_payload = []
    dex_found = False
    
    while time.time() - start_time < timeout:
        try:
            line = process.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            # Check for START marker
            if "[DEX_PAYLOAD_START]" in line:
                payload_started = True
                print("\033[93m[*] DEX payload transmission started\033[0m")
                continue
            
            # Collect hex payload lines (must come before END check)
            if payload_started and line.strip() and "[DEX_PAYLOAD_END]" not in line:
                hex_payload.append(line.strip())
                continue
            
            # Check for END marker (after collecting hex)
            if "[DEX_PAYLOAD_END]" in line and payload_started:
                if hex_payload:
                    dex_found = True
                    print("\033[93m[*] DEX payload transmission completed\033[0m")
                    break
                continue
            
            # Print non-payload Frida output for visibility (only if not in payload)
            if not payload_started:
                print(line.rstrip())
        
        except Exception as e:
            if debug_mode:
                print(f"[DEBUG] Error reading line: {e}")
            time.sleep(0.1)
    
    # Decode the hex payload to get DEX bytes
    if dex_found and hex_payload:
        try:
            # Join all hex lines and decode
            full_hex = ''.join(hex_payload)
            dex_bytes = bytes.fromhex(full_hex)
            
            print(f"\033[92m[OK] Captured {len(dex_bytes)} bytes of DEX from Frida\033[0m")
            if debug_mode:
                print(f"[DEBUG] DEX first 16 bytes (header): {dex_bytes[:16].hex()}")
            
            return dex_bytes
        
        except Exception as e:
            print(f"\033[91m[ERROR] Failed to decode hex DEX payload: {e}\033[0m")
            if debug_mode:
                print(f"[DEBUG] Exception details: {e}")
            return None
    
    if not dex_found:
        print("\033[93m[*] DEX payload not captured from Frida output\033[0m")
    
    return None


def _extract_strings_from_intercepted_dex(dex_bytes, debug_mode, skip_filter):
    """Extract strings from intercepted DEX bytes using static analysis
    
    Reuses the existing static dex_parser module to extract strings in memory.
    
    Args:
        dex_bytes: Raw DEX bytes
        debug_mode: Enable debug output
        skip_filter: Skip filtering
        
    Returns:
        list: List of extracted string dictionaries
    """
    
    try:
        if debug_mode:
            print(f"[DEBUG] Analyzing intercepted DEX ({len(dex_bytes)} bytes)...")
        
        # Use existing static analysis function to extract strings from DEX bytes
        extracted_strings = extract_strings_from_dex_bytes(dex_bytes, "intercepted.dex")
        
        if debug_mode:
            print(f"[DEBUG] Extracted {len(extracted_strings)} strings from intercepted DEX")
        
        return extracted_strings
        
    except Exception as e:
        print(f"\033[91m[ERROR] Failed to extract strings from intercepted DEX: {e}\033[0m")
        if debug_mode:
            print(f"[DEBUG] Exception details: {e}")
        return []


def _filter_strings_by_pattern(strings, pattern_filter):
    """Filter strings by pattern(s)
    
    Reuses the existing pattern filtering function from static analysis.
    
    Args:
        strings: List of string dictionaries
        pattern_filter: Single pattern name (str) or multiple patterns (list)
        
    Returns:
        list: Filtered list of strings
    """
    
    if isinstance(pattern_filter, str):
        pattern_filter = [pattern_filter]
    
    try:
        filtered = filter_by_pattern(strings, pattern_filter)
        return filtered
    except Exception as e:
        print(f"\033[91m[ERROR] Pattern filtering failed: {e}\033[0m")
        return strings


def _save_hybrid_results(output_file, all_strings, skip_filter, pattern_filter, debug_mode):
    """Save hybrid analysis results to JSON file
    
    Preserves the same output format as static analysis.
    
    Args:
        output_file: Path to output file
        all_strings: List of extracted strings
        skip_filter: Whether filtering was skipped
        pattern_filter: Applied pattern filter (if any)
        debug_mode: Enable debug output
    """
    
    try:
        # Count different string types
        dex_count = len(set(s.get('string', '') for s in all_strings))
        
        # Build result metadata
        results = {
            "analysis_type": "hybrid",
            "metadata": {
                "total_unique_strings": dex_count,
                "total_strings": len(all_strings),
                "skip_filter": skip_filter,
                "pattern_filter": pattern_filter if pattern_filter else None,
            },
            "strings": all_strings
        }
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        if debug_mode:
            print(f"[DEBUG] Results saved to {output_file}")
        
    except Exception as e:
        print(f"\033[91m[ERROR] Failed to save results: {e}\033[0m")


__all__ = [
    "run_hybrid_analysis",
]
