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
from andross.dynamic import run_dynamic_analysis, extract_package_from_apk

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
    print("   or: python Andross.py --dynamic <path/to/app.apk> --output <path> [--minimal]")
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
    print("  --output <path>   Save analysis results to specified file or directory")
    print("  --pattern <names> Specify patterns to search for (space-separated)")
    print("                    Use: --pattern help  (to see available patterns)")
    print("                    Use: --pattern all   (to search all patterns)")
    print("  --debug           Enable debug output for detailed information")
    print("  --skip-filter     Skip result filtering and show all raw findings\n")
    
    print("\033[1mDYNAMIC MODE OPTIONS:\033[0m")
    print("  <path/to/app.apk> Path to the APK file to analyze (required)")
    print("  --output <path>   Save analysis results to specified file (required)")
    print("  --minimal         Run minimal hooks (reduced instrumentation)\n")
    
    print("\033[1mEXAMPLES:\033[0m")
    print("  # View available patterns")
    print("  python Andross.py --pattern help\n")
    print("  # Static analysis with specific patterns")
    print("  python Andross.py --static app.apk --pattern md5 jwt\n")
    print("  # Static analysis with all patterns")
    print("  python Andross.py --static app.apk --pattern all --output results.json\n")
    print("  # Dynamic analysis with output file")
    print("  python Andross.py --dynamic app.apk --output results.json\n")
    print("  # Dynamic analysis with minimal hooks")
    print("  python Andross.py --dynamic app.apk --output results.json --minimal\n")    
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
        print("[ERROR] Must specify either --static or --dynamic mode as the first argument")
        print_usage()
        sys.exit(1)
    
    # Handle static mode
    if mode == '--static':
        if len(sys.argv) < 3:
            print("[ERROR] Static mode requires APK path")
            print("Usage: python Andross.py --static <path/to/app.apk> [--output <path>] [--pattern <name> ...] [--debug] [--skip-filter]")
            sys.exit(1)
        
        apk_path = sys.argv[2]
        debug_mode = '--debug' in sys.argv
        skip_filter = '--skip-filter' in sys.argv
        
        # Check for optional --output argument
        output_file = None
        if '--output' in sys.argv:
            try:
                output_idx = sys.argv.index('--output')
                if output_idx + 1 >= len(sys.argv):
                    print("[ERROR] --output argument requires a path")
                    sys.exit(1)
                output_file = sys.argv[output_idx + 1]
            except (ValueError, IndexError):
                print("[ERROR] Invalid --output argument")
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
                    print("[ERROR] --pattern argument requires at least one pattern name")
                    print("Use: python Andross.py --pattern help   (to see available patterns)")
                    sys.exit(1)
                
                # If only one pattern, keep as string; if multiple, pass as list
                pattern_filter = patterns_list[0] if len(patterns_list) == 1 else patterns_list
            except (ValueError, IndexError):
                print("[ERROR] Invalid --pattern argument")
                sys.exit(1)
        
        run_static_analysis(apk_path, output_file=output_file, debug_mode=debug_mode, skip_filter=skip_filter, pattern_filter=pattern_filter)
    
    # Handle dynamic mode
    elif mode == '--dynamic':
        if len(sys.argv) < 3:
            print("[ERROR] Dynamic mode requires APK path")
            print("Usage: python Andross.py --dynamic <path/to/app.apk> --output <path> [--minimal]")
            sys.exit(1)
        
        apk_path = sys.argv[2]
        
        if '--output' not in sys.argv:
            print("[ERROR] Dynamic mode requires --output argument")
            print("Usage: python Andross.py --dynamic <path/to/app.apk> --output <path> [--minimal]")
            sys.exit(1)
        
        try:
            output_idx = sys.argv.index('--output')
            if output_idx + 1 >= len(sys.argv):
                print("[ERROR] --output argument requires a file path")
                sys.exit(1)
            
            output_file = sys.argv[output_idx + 1]
            minimal_mode = '--minimal' in sys.argv
            debug_mode = '--debug' in sys.argv
            
            # Extract package name from APK
            package_name = extract_package_from_apk(apk_path, debug=debug_mode)
            
            if not package_name:
                print("[ERROR] Failed to extract package name from APK")
                sys.exit(1)
            
            print(f"[OK] Resolved package name: {package_name}")
            
            run_dynamic_analysis(output_file, package_name, minimal=minimal_mode)
        except Exception as e:
            print(f"[ERROR] {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
