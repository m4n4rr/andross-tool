import os
import subprocess
import json
import time
import threading

from .event_processor import StringEventProcessor
from .manifest_parser import extract_package_from_apk
from ..utils.logger import error, info, ok


def run_dynamic_analysis(output_file, apk_path, minimal=False):
    # Extract package name from APK
    try:
        info("Extracting package name from APK...")
        package_name = extract_package_from_apk(apk_path, debug_mode=False)
        if not package_name:
            error("Failed to extract package name from APK")
            return False
    except Exception as e:
        error(f"Failed to extract package name: {e}")
        return False
    
    info(f"Target package: {package_name}")
    
    # Create parent directory if it doesn't exist
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Select script based on minimal flag
    script_name = 'string_hook_minimal.js' if minimal else 'string_hook.js'
    script_path = os.path.join(os.path.dirname(__file__), script_name)
    
    if not os.path.exists(script_path):
        error(f"{script_name} not found in the script directory")
        return False
    
    mode_label = "minimal" if minimal else "full"
    info(f"Starting Frida dynamic analysis ({mode_label} mode)...")
    info("Press Ctrl+C to stop the analysis")
    
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
        info("Listening for string events...")
        
        # Track time to detect if Frida attached to device
        start_time = time.time()
        attachment_timeout = 10  # seconds to wait for first event
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
                print("\n")
                error(f"Timeout: Frida did not attach to device within {attachment_timeout} seconds")
                info("Note: Device was verified ready before starting Frida")
                info("This may indicate a Frida-server connection issue or app crash")
                info("Try: adb shell 'ps -A | grep <package>'")
                
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
            ok("Frida session completed successfully")
        else:
            info(f"Frida session ended with exit code {process.returncode}")
            
            if not minimal and event_count < 10:
                print("")
                info("SUGGESTION: Try again with --minimal flag to reduce memory pressure:")
                print(f"    python Andross.py --dynamic <path/to/app.apk> --output {output_file} --minimal")
        
        # Process and save results
        aggregated_data = processor.get_aggregated_data(package_name)
        stats = processor.get_statistics()
        
        print("")
        info("Processing results:")
        print(f"    Total events received: {stats['total_events']}")
        print(f"    Unique string combinations: {stats['unique_combinations']}")
        print(f"    Total deduplicated count: {stats['aggregated_count']}")
        
        # Save to JSON file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(aggregated_data, f, indent=2, ensure_ascii=False)
        
        ok(f"Saved structured output to {output_file}")
        return True
        
    except KeyboardInterrupt:
        print("")
        info("Stopping Frida analysis...")
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
                ok("Frida stopped gracefully")
            except subprocess.TimeoutExpired:
                process.kill()
                ok("Frida killed forcefully")
        
        # Get and display results statistics
        aggregated_data = processor.get_aggregated_data(package_name)
        stats = processor.get_statistics()
        
        print("")
        info("Processing results:")
        print(f"    Total events received: {stats['total_events']}")
        print(f"    Unique string combinations: {stats['unique_combinations']}")
        print(f"    Total deduplicated count: {stats['aggregated_count']}")
        
        # Save partial results
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(aggregated_data, f, indent=2, ensure_ascii=False)
        
        ok(f"Partial results saved to {output_file}")
        return True
        
    except FileNotFoundError:
        error("frida command not found. Make sure Frida is installed and in PATH")
        return False
    except Exception as e:
        error(f"Failed to run Frida: {e}")
        import traceback
        traceback.print_exc()
        return False
