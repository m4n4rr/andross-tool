import os
import subprocess
import json
import time
import threading

from .event_processor import StringEventProcessor
from .manifest_parser import extract_package_from_apk


def run_dynamic_analysis(output_file, apk_path, minimal=False):
    """Run dynamic analysis using Frida with structured event processing
    
    Args:
        output_file: File path where to save processed JSON results
        apk_path: Path to the APK file (for package name extraction)
        minimal: If True, use minimal script (StringBuilder and valueOf disabled)
    
    Precondition: Device must be ready (ensured via ensure_device_ready())
        - Emulator is online
        - Frida-server is running
        - App is installed
    """
    
    # Extract package name from APK
    try:
        print("\033[93m[*] Extracting package name from APK...\033[0m")
        package_name = extract_package_from_apk(apk_path, debug=False)
        if not package_name:
            print("\033[91m[ERROR] Failed to extract package name from APK\033[0m")
            return False
    except Exception as e:
        print(f"\033[91m[ERROR] Failed to extract package name: {e}\033[0m")
        return False
    
    print(f"\033[93m[*] Target package: {package_name}\033[0m")
    
    # Create parent directory if it doesn't exist
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Select script based on minimal flag
    script_name = 'string_hook_minimal.js' if minimal else 'string_hook.js'
    script_path = os.path.join(os.path.dirname(__file__), script_name)
    
    if not os.path.exists(script_path):
        print(f"[ERROR] {script_name} not found in the script directory")
        return False
    
    mode_label = "minimal" if minimal else "full"
    print(f"\033[93m[*] Starting Frida dynamic analysis ({mode_label} mode)...\033[0m")
    print("\033[93m[*] Press Ctrl+C to stop the analysis\033[0m")
    
    # Initialize event processor
    processor = StringEventProcessor()
    
    process = None
    try:
        # Run Frida - capture both stdout and stderr
        process = subprocess.Popen(
            ['frida', '-U', '-f', package_name, '-l', script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1  # Line buffered
        )
        
        # Process output line by line
        event_count = 0
        print("\033[93m[*] Listening for string events...\033[0m")
        
        # Track time to detect if Frida attached to device
        start_time = time.time()
        attachment_timeout = 5  # seconds to wait for first event
        first_event_received = False
        
        # Function to read output in a separate thread
        def read_output():
            nonlocal event_count, first_event_received
            for line in process.stdout:
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                
                try:
                    event = json.loads(line)
                    if isinstance(event, dict) and 'type' in event and 'value' in event and 'caller' in event:
                        processor.process_event(event)
                        event_count += 1
                        first_event_received = True
                except json.JSONDecodeError:
                    pass
        
        # Start reader thread
        reader_thread = threading.Thread(target=read_output, daemon=True)
        reader_thread.start()
        
        # Monitor for device attachment timeout
        while process.poll() is None:
            current_time = time.time()
            elapsed = current_time - start_time
            
            # Check for timeout if no events received yet
            if event_count == 0 and elapsed > attachment_timeout:
                print(f"\n\033[91m[ERROR] Timeout: Frida did not attach to device within {attachment_timeout} seconds\033[0m")
                print("\033[93m[*] Note: Device was verified ready before starting Frida\033[0m")
                print("\033[93m[*] This may indicate a Frida-server connection issue or app crash\033[0m")
                print("\033[93m[*] Try: adb shell 'ps -A | grep <package>'\033[0m")
                
                if process and process.poll() is None:
                    try:
                        process.terminate()
                        process.wait(timeout=3)
                    except Exception:
                        process.kill()
                
                return False
            
            try:
                time.sleep(0.1)
            except KeyboardInterrupt:
                raise
        
        # Read any remaining output after process ends
        remaining_output = process.stdout.read()
        if remaining_output:
            for line in remaining_output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if isinstance(event, dict) and 'type' in event and 'value' in event and 'caller' in event:
                        processor.process_event(event)
                        event_count += 1
                except json.JSONDecodeError:
                    pass
        
        # Check return code
        if process.returncode == 0:
            print("\033[92m[OK] Frida session completed successfully\033[0m")
        else:
            print(f"\033[93m[*] Frida session ended with exit code {process.returncode}\033[0m")
            
            if not minimal and event_count < 10:
                print("\n\033[93m[*] SUGGESTION: Try again with --minimal flag to reduce memory pressure:\033[0m")
                print(f"    python Andross.py --dynamic <path/to/app.apk> --output {output_file} --minimal")
        
        # Process and save results
        aggregated_data = processor.get_aggregated_data(package_name)
        stats = processor.get_statistics()
        
        print("\n\033[93m[*] Processing results:\033[0m")
        print(f"    Total events received: {stats['total_events']}")
        print(f"    Unique string combinations: {stats['unique_combinations']}")
        print(f"    Total deduplicated count: {stats['aggregated_count']}")
        
        # Save to JSON file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(aggregated_data, f, indent=2, ensure_ascii=False)
        
        print(f"\033[92m[OK] Saved structured output to {output_file}\033[0m")
        return True
        
    except KeyboardInterrupt:
        print("\n\033[93m[*] Stopping Frida analysis...\033[0m")
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
                print("\033[92m[OK] Frida stopped gracefully\033[0m")
            except subprocess.TimeoutExpired:
                process.kill()
                print("\033[92m[OK] Frida killed forcefully\033[0m")
        
        # Get and display results statistics
        aggregated_data = processor.get_aggregated_data(package_name)
        stats = processor.get_statistics()
        
        print("\n\033[93m[*] Processing results:\033[0m")
        print(f"    Total events received: {stats['total_events']}")
        print(f"    Unique string combinations: {stats['unique_combinations']}")
        print(f"    Total deduplicated count: {stats['aggregated_count']}")
        
        # Save partial results
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(aggregated_data, f, indent=2, ensure_ascii=False)
        
        print(f"\033[92m[OK] Partial results saved to {output_file}\033[0m")
        return True
        
    except FileNotFoundError:
        print("\033[91m[ERROR] frida command not found. Make sure Frida is installed and in PATH\033[0m")
        return False
    except Exception as e:
        print(f"\033[91m[ERROR] Failed to run Frida: {e}\033[0m")
        import traceback
        traceback.print_exc()
        return False
