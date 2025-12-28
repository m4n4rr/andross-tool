import os
import subprocess
import time


def run_dynamic_analysis(output_dir, package_name, minimal=False):
    """Run dynamic analysis using Frida
    
    Args:
        output_dir: Directory to save Frida output
        package_name: Target package name for Frida to spawn
        minimal: If True, use minimal script (StringBuilder and valueOf disabled)
    """
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Select script based on minimal flag
    script_name = 'string_hook_minimal.js' if minimal else 'string_hook.js'
    script_path = os.path.join(os.path.dirname(__file__), script_name)
    
    if not os.path.exists(script_path):
        print(f"[ERROR] {script_name} not found in the script directory")
        return
    
    # Run frida in USB mode with the script
    frida_output_file = os.path.join(output_dir, 'frida_output.txt')
    
    mode_label = "minimal" if minimal else "full"
    print(f"[*] Starting Frida dynamic analysis ({mode_label} mode)...")
    print(f"[*] Target package: {package_name}")
    print(f"[*] Saving output to: {frida_output_file}")
    print(f"[*] Press Ctrl+C to stop the analysis")
    
    process = None
    try:
        with open(frida_output_file, 'w', encoding='utf-8') as outfile:
            process = subprocess.Popen(
                ['frida', '-U', '-f', package_name, '-l', script_path],
                stdout=outfile,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Poll the process to allow KeyboardInterrupt to be caught
            while process.poll() is None:
                try:
                    time.sleep(0.1)
                except KeyboardInterrupt:
                    raise
            
            # Check return code for crash/disconnection
            if process.returncode == 0:
                print(f"[OK] Frida output saved to {frida_output_file}")
            else:
                print(f"[ERROR] Frida session failed with exit code {process.returncode}")
                print(f"[ERROR] The Frida session crashed or disconnected.")
                
                if not minimal:
                    print(f"\n[*] SUGGESTION: Try again with --minimal flag to reduce memory pressure:")
                    print(f"    python Andross.py --dynamic --output {output_dir} --minimal")
                
                return False
                
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
        return True
    except FileNotFoundError:
        print("[ERROR] frida command not found. Make sure Frida is installed and in PATH")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to run Frida: {e}")
        return False
    
    return True
