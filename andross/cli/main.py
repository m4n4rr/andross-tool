import sys
from andross.static.engine import run_static_analysis
from andross.dynamic.engine import run_dynamic_analysis
from andross.dynamic.manifest_parser import extract_package_from_apk


def print_usage():
    """Print usage information"""
    print("Usage: python Andross.py --static <path/to/app.apk> [--debug] [--skip-filter]")
    print("   or: python Andross.py --dynamic <path/to/app.apk> --output <output_dir> [--minimal]")


def main():
    """Main CLI entry point"""
    
    if len(sys.argv) < 2:
        print_usage()
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
        print_usage()
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
        if len(sys.argv) < 3:
            print("[ERROR] Dynamic mode requires APK path")
            print("Usage: python Andross.py --dynamic <path/to/app.apk> --output <output_dir> [--minimal]")
            sys.exit(1)
        
        apk_path = sys.argv[2]
        
        if '--output' not in sys.argv:
            print("[ERROR] Dynamic mode requires --output argument")
            print("Usage: python Andross.py --dynamic <path/to/app.apk> --output <output_dir> [--minimal]")
            sys.exit(1)
        
        try:
            output_idx = sys.argv.index('--output')
            if output_idx + 1 >= len(sys.argv):
                print("[ERROR] --output argument requires a directory name")
                sys.exit(1)
            
            output_dir = sys.argv[output_idx + 1]
            minimal_mode = '--minimal' in sys.argv
            
            # Extract package name from APK
            print(f"[*] Extracting package name from APK...")
            package_name = extract_package_from_apk(apk_path, debug=False)
            
            if not package_name:
                print("[ERROR] Failed to extract package name from APK")
                sys.exit(1)
            
            print(f"[OK] Resolved package name: {package_name}")
            
            run_dynamic_analysis(output_dir, package_name, minimal=minimal_mode)
        except Exception as e:
            print(f"[ERROR] {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
