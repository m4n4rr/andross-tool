RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


def error(msg):
    print(f"{RED}[ERROR] {msg}{RESET}")


def info(msg):
    print(f"{YELLOW}[*] {msg}{RESET}")


def ok(msg):
    print(f"{GREEN}[OK] {msg}{RESET}")

def debug(msg, debug_mode=True):
    if debug_mode:
        print(f"{YELLOW}[DEBUG] {msg}{RESET}")
