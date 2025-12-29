import os
import subprocess
import json
import time
import threading
from .event_processor import StringEventProcessor


def run_dynamic_analysis(output_file, package_name, minimal=False):
    """Run dynamic analysis using Frida with structured event processing
    
    Args:
        output_file: File path where to save processed JSON results
        package_name: Target package name for Frida to spawn
        minimal: If True, use minimal script (StringBuilder and valueOf disabled)
    """
    
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
    print(f"[*] Starting Frida dynamic analysis ({mode_label} mode)...")
    print(f"[*] Target package: {package_name}")
    print(f"[*] Press Ctrl+C to stop the analysis")
    
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
        print(f"[*] Listening for string events...")
        
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
                print(f"\n[ERROR] Timeout: Frida did not attach to any device within {attachment_timeout} seconds")
                print(f"[ERROR] No Android emulator or device detected")
                print(f"[*] Make sure:")
                print(f"    1. An Android emulator is running")
                print(f"    2. USB debugging is enabled (for physical devices)")
                print(f"    3. Run: adb devices (to check connected devices)")
                
                if process and process.poll() is None:
                    try:
                        process.terminate()
                        process.wait(timeout=3)
                    except:
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
            print(f"[OK] Frida session completed successfully")
        else:
            print(f"[WARNING] Frida session ended with exit code {process.returncode}")
            
            if not minimal and event_count < 10:
                print(f"\n[*] SUGGESTION: Try again with --minimal flag to reduce memory pressure:")
                print(f"    python Andross.py --dynamic <path/to/app.apk> --output {output_file} --minimal")
        
        # Process and save results
        aggregated_data = processor.get_aggregated_data(package_name)
        stats = processor.get_statistics()
        
        print(f"\n[*] Processing results:")
        print(f"    Total events received: {stats['total_events']}")
        print(f"    Unique string combinations: {stats['unique_combinations']}")
        print(f"    Total deduplicated count: {stats['aggregated_count']}")
        
        # Save to JSON file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(aggregated_data, f, indent=2, ensure_ascii=False)
        
        print(f"[OK] Saved structured output to {output_file}")
        return True
        
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
        
        # Save partial results
        aggregated_data = processor.get_aggregated_data(package_name)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(aggregated_data, f, indent=2, ensure_ascii=False)
        
        print(f"[OK] Partial results saved to {output_file}")
        return True
        
    except FileNotFoundError:
        print("[ERROR] frida command not found. Make sure Frida is installed and in PATH")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to run Frida: {e}")
        import traceback
        traceback.print_exc()
        return False
