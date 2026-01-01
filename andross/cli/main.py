import sys
import logging
import os

# Third-party
try:
    from loguru import logger as loguru_logger
    # Remove default handler and set level to ERROR (suppress DEBUG and WARNING)
    loguru_logger.remove()
    loguru_logger.add(sys.stderr, level="ERROR")
except ImportError:
    pass

# Local
from andross.static import run_static_analysis, get_available_patterns
from andross.dynamic import run_dynamic_analysis
from andross.utils import ensure_device_ready

# Suppress standard logging from androguard modules
logging.getLogger("androguard.core").setLevel(logging.ERROR)
logging.getLogger("androguard.core.dex").setLevel(logging.ERROR)
logging.getLogger("androguard.core.axml").setLevel(logging.ERROR)
logging.getLogger("androguard.core.analysis").setLevel(logging.ERROR)

# Disable propagation to prevent messages from reaching root logger
for logger_name in ["androguard", "androguard.core", "androguard.core.dex", "androguard.core.axml", "androguard.core.analysis"]:
    logging.getLogger(logger_name).propagate = False

# Set environment variables to suppress androguard logging
os.environ["ANDROGUARD_DEBUG"] = "0"


def print_usage():
    """Print usage information"""
    print("Usage: python Andross.py --static <path/to/app.apk> [--output <path>] [--pattern <name> ...] [--debug] [--skip-filter]")
    print("   or: python Andross.py --dynamic <path/to/app.apk> [--output <path>] [--frida-path <path>] [--minimal] [--debug]")
    print("\nExamples:")
    print("  python Andross.py --pattern help")
    print("  python Andross.py --static app.apk --pattern md5")
    print("  python Andross.py --static app.apk --pattern md5 jwt email")
    print("  python Andross.py --static app.apk --pattern all\n")


def print_help():
    """Print detailed help information with descriptions"""
    print("\n" + "="*70)
    print("ANDROSS - APK Analysis Tool".center(70))
    print("="*70)
    
    print("\n\033[1mDESCRIPTION:\033[0m")
    print("  Andross is a comprehensive APK analysis tool that supports both")
    print("  static and dynamic analysis modes for security research.\n")
    
    print("\033[1mUSAGE:\033[0m")
    print("  python Andross.py [MODE] [OPTIONS]\n")
    
    print("\033[1mMODES:\033[0m")
    print("  --static          Perform static analysis on the APK file")
    print("  --dynamic         Perform dynamic analysis on the APK file")
    print("  --help, -h        Display this help message\n")
    
    print("\033[1mSTATIC MODE OPTIONS:\033[0m")
    print("  <path/to/app.apk> Path to the APK file to analyze (required)")
    print("  --output <path>   Save analysis results to specified file (optional, defaults to 'static_strings.json')")
    print("  --pattern <names> Specify patterns to search for (space-separated)")
    print("                    Use: --pattern help  (to see available patterns)")
    print("                    Use: --pattern all   (to search all patterns)")
    print("  --debug           Enable debug output for detailed information")
    print("  --skip-filter     Skip result filtering and show all raw findings\n")
    
    print("\033[1mDYNAMIC MODE OPTIONS:\033[0m")
    print("  <path/to/app.apk> Path to the APK file to analyze (required)")
    print("  --output <path>   Save analysis results to specified file (optional, defaults to 'dynamic_strings.json')")
    print("  --frida-path <p>  Path to frida-server binary (optional, auto-detected if not provided)")
    print("  --minimal         Run minimal hooks (reduced instrumentation)")
    print("  --debug           Enable debug output for detailed information")
    
    print("\033[1mEXAMPLES:\033[0m")
    print("  # View available patterns")
    print("  python Andross.py --pattern help\n")
    print("  # Static analysis with specific patterns (saves to static_strings.json by default)")
    print("  python Andross.py --static app.apk --pattern md5 jwt\n")
    print("  # Static analysis with all patterns and custom output")
    print("  python Andross.py --static app.apk --pattern all --output results.json\n")
    print("  # Dynamic analysis with default output (dynamic_strings.json)")
    print("  python Andross.py --dynamic app.apk\n")
    print("  # Dynamic analysis with minimal hooks")
    print("  python Andross.py --dynamic app.apk --minimal\n")
    print("  # Dynamic analysis with custom output and frida-server path")
    print("  python Andross.py --dynamic app.apk --output results.json --frida-path /path/to/frida-server\n")    
    print()


def main():
    """Main CLI entry point"""
    
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    
    # Check if help is requested
    first_arg = sys.argv[1]
    if first_arg in ['--help', '-h', 'help']:
        print_help()
        sys.exit(0)
    
    # Check if first argument is --pattern help
    if first_arg == '--pattern' and len(sys.argv) > 2 and sys.argv[2] == 'help':
        print("\n=== Available Patterns ===\n")
        for pattern_name in get_available_patterns():
            print(f"  • {pattern_name}")
        print()
        sys.exit(0)
    
    # Check if first argument is a mode flag
    # Determine mode - MUST be --static or --dynamic
    if first_arg == '--static':
        mode = '--static'
    elif first_arg == '--dynamic':
        mode = '--dynamic'
    else:
        print("\033[91m[ERROR] Must specify either --static or --dynamic mode as the first argument\033[0m")
        print_usage()
        sys.exit(1)
    
    # Handle static mode
    if mode == '--static':
        if len(sys.argv) < 3:
            print("\033[91m[ERROR] Static mode requires APK path\033[0m")
            print("Usage: python Andross.py --static <path/to/app.apk> [--output <path>] [--pattern <name> ...] [--debug] [--skip-filter]")
            sys.exit(1)
        
        apk_path = sys.argv[2]
        debug_mode = '--debug' in sys.argv
        skip_filter = '--skip-filter' in sys.argv
        
        # Set FRIDA_DEBUG environment variable based on --debug flag (for consistency)
        os.environ['FRIDA_DEBUG'] = 'true' if debug_mode else 'false'
        
        # Check for optional --output argument
        output_file = "static_strings.json"  # Default output file
        if '--output' in sys.argv:
            try:
                output_idx = sys.argv.index('--output')
                if output_idx + 1 >= len(sys.argv):
                    print("\033[91m[ERROR] --output argument requires a path\033[0m")
                    sys.exit(1)
                output_file = sys.argv[output_idx + 1]
            except (ValueError, IndexError):
                print("\033[91m[ERROR] Invalid --output argument\033[0m")
                sys.exit(1)
        
        # Check for optional --pattern argument(s)
        pattern_filter = None
        if '--pattern' in sys.argv:
            try:
                pattern_idx = sys.argv.index('--pattern')
                patterns_list = []
                # Collect all following arguments that are pattern names (don't start with --)
                idx = pattern_idx + 1
                while idx < len(sys.argv) and not sys.argv[idx].startswith('--'):
                    patterns_list.append(sys.argv[idx])
                    idx += 1
                
                if not patterns_list:
                    print("\033[91m[ERROR] --pattern argument requires at least one pattern name\033[0m")
                    print("Use: python Andross.py --pattern help   (to see available patterns)")
                    sys.exit(1)
                
                # If only one pattern, keep as string; if multiple, pass as list
                pattern_filter = patterns_list[0] if len(patterns_list) == 1 else patterns_list
            except (ValueError, IndexError):
                print("\033[91m[ERROR] Invalid --pattern argument\033[0m")
                sys.exit(1)
        
        run_static_analysis(apk_path, output_file=output_file, debug_mode=debug_mode, skip_filter=skip_filter, pattern_filter=pattern_filter)
    
    # Handle dynamic mode
    elif mode == '--dynamic':
        if len(sys.argv) < 3:
            print("\033[91m[ERROR] Dynamic mode requires APK path\033[0m")
            print("Usage: python Andross.py --dynamic <path/to/app.apk> [--output <path>] [--minimal] [--frida-path <path>] [--debug]")
            sys.exit(1)
        
        apk_path = sys.argv[2]
        
        # Check for optional --output argument (default: dynamic_strings.json)
        output_file = "dynamic_strings.json"
        if '--output' in sys.argv:
            try:
                output_idx = sys.argv.index('--output')
                if output_idx + 1 >= len(sys.argv):
                    print("\033[91m[ERROR] --output argument requires a file path\033[0m")
                    sys.exit(1)
                output_file = sys.argv[output_idx + 1]
            except (ValueError, IndexError):
                print("\033[91m[ERROR] Invalid --output argument\033[0m")
                sys.exit(1)
        
        minimal_mode = '--minimal' in sys.argv
        debug_mode = '--debug' in sys.argv
        
        # Set FRIDA_DEBUG environment variable based on --debug flag
        os.environ['FRIDA_DEBUG'] = 'true' if debug_mode else 'false'
        
        # Check for optional frida-server path
        frida_server_path = None
        if '--frida-path' in sys.argv:
            try:
                frida_idx = sys.argv.index('--frida-path')
                if frida_idx + 1 >= len(sys.argv):
                    print("\033[91m[ERROR] --frida-path argument requires a file path\033[0m")
                    sys.exit(1)
                frida_server_path = sys.argv[frida_idx + 1]
            except (ValueError, IndexError):
                print("\033[91m[ERROR] Invalid --frida-path argument\033[0m")
                sys.exit(1)
        
        try:
            # Step 1: Ensure device is ready (emulator online, frida-server running, app installed)
            if not ensure_device_ready(apk_path=apk_path, frida_server_path=frida_server_path):
                sys.exit(1)
            
            # Step 2: Run dynamic analysis (device setup is already guaranteed)
            run_dynamic_analysis(output_file, apk_path, minimal=minimal_mode)
        except Exception as e:
            print(f"\033[91m[ERROR] {e}\033[0m")
            sys.exit(1)


if __name__ == "__main__":
    main()
