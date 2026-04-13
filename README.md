# Andross 🔍

> APK analysis tool — static inspection meets dynamic instrumentation.

Built by [Marla](https://github.com/m4n4rr) & geng.

---

## What it does

Andross is a command-line tool for analyzing Android APK files. It combines **static analysis** via androguard with **dynamic instrumentation** via Frida, giving you a full picture of what an APK is doing — at rest and at runtime.

---

## Requirements

- Python 3.11+
- A connected Android device or emulator (for dynamic features)
- [Frida server](https://github.com/frida/frida/releases) running on the target device

---

## Installation

```bash
git clone https://github.com/m4n4rr/andross-tool.git
cd andross-tool
pip install -r requirements.txt
```

---

## Usage

```
python Andross.py [MODE] [OPTIONS]
```

### Modes

| Flag | Description |
|---|---|
| `--static` | Perform static analysis on the APK file |
| `--dynamic` | Perform dynamic analysis on the APK file |
| `--hybrid` | Perform hybrid analysis (dynamic + static on intercepted DEX) |
| `--version` | Display the version number and exit |

### Static mode

```bash
python Andross.py --static <path/to/app.apk> [OPTIONS]
```

| Option | Description |
|---|---|
| `--output <path>` | Save results to file (default: `static_strings.json`) |
| `--pattern <names>` | Patterns to search for (space-separated). Use `--pattern help` to list available, `--pattern all` to run all |
| `--debug` | Enable debug output |
| `--skip-filter` | Show all raw findings without filtering |

### Dynamic mode

```bash
python Andross.py --dynamic <path/to/app.apk> [OPTIONS]
```

| Option | Description |
|---|---|
| `--output <path>` | Save results to file (default: `dynamic_strings.json`) |
| `--frida-path <p>` | Path to frida-server binary (auto-detected if not provided) |
| `--minimal` | Run minimal hooks (reduced instrumentation) |
| `--debug` | Enable debug output |

### Hybrid mode

```bash
python Andross.py --hybrid <path/to/app.apk> [OPTIONS]
```

| Option | Description |
|---|---|
| `--output <path>` | Save results to file (default: `hybrid_strings.json`) |
| `--frida-path <p>` | Path to frida-server binary (auto-detected if not provided) |
| `--debug` | Enable debug output |
| `--skip-filter` | Show all raw findings without filtering |

### Examples

```bash
# View available patterns
python Andross.py --pattern help

# Static analysis with specific patterns
python Andross.py --static app.apk --pattern md5 jwt

# Static analysis with all patterns and custom output
python Andross.py --static app.apk --pattern all --output results.json

# Dynamic analysis (saves to dynamic_strings.json by default)
python Andross.py --dynamic app.apk

# Dynamic analysis with minimal hooks
python Andross.py --dynamic app.apk --minimal

# Dynamic analysis with custom output and frida-server path
python Andross.py --dynamic app.apk --output results.json --frida-path /path/to/frida-server
```

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| [androguard](https://github.com/androguard/androguard) | 4.1.1 | Static APK analysis |
| [frida](https://frida.re) | 16.6.6 | Dynamic instrumentation |
| [loguru](https://github.com/Delgan/loguru) | 0.7.2 | Logging |

---

## Project structure

```
andross-tool/
├── Andross.py          # Entry point
├── andross/            # Core modules
│   └── cli.py          # CLI logic
└── requirements.txt
```

---

## Authors

Made with ☕ by **Marla** ([@m4n4rr](https://github.com/m4n4rr)) and **Ayoub** ([@ayoub-ben-salem](https://github.com/ayoub-ben-salem)).
