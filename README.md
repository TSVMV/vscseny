# Vscseny

Vscseny is a local static code scanner that looks for insecure patterns in
your own source code and suggests fixes.  Point it at a project directory and
it reports risky calls, weak crypto, hardcoded secrets, and other common
mistakes, ranked by severity.

It runs offline and never uploads your code anywhere.  Download the binary for
your OS and run it; no runtime is required.

## Download and run

Get the files from the repository **Releases** page (Assets):

- Windows: `vscseny.exe`
- Linux: `vscseny`

### Windows

1. Download `vscseny.exe`.
2. Open a terminal (or cmd) and run:

```bat
vscseny.exe C:\path\to\your\project
```

### Linux

1. Download `vscseny`.
2. `chmod +x vscseny && ./vscseny /path/to/your/project`

## Usage

```console
vscseny <path>              scan; interactive UI when stdout is a terminal
vscseny <path> --tui        force the interactive UI
vscseny <path> --report     plain text report
vscseny <path> --json       machine-readable JSON report
vscseny <path> --no-color   disable ANSI colors
vscseny --list-rules        list every rule id, severity and name
vscseny --v                 print version
```

Scanning a single file:

```console
vscseny src/app.py
```

Exit codes: `0` scan completed, `1` scan failed, `2` bad arguments.

## Interactive UI

When stdout is a terminal, Vscseny opens a line-driven TUI after the scan.
Type a command and press Enter.

| command        | action                                      |
| -------------- | ------------------------------------------- |
| `f critical`   | filter by severity                          |
| `c injection`  | filter by category                          |
| `m strcpy`     | match file / rule / code                    |
| `sev high`     | show critical and high                      |
| `s`            | clear filters                               |
| `sort sev`     | sort by severity (default)                  |
| `sort file`    | sort by file path                           |
| `n` / `p`      | next / previous page (or issue in detail)   |
| `top`          | first page                                  |
| `<number>`     | inspect issue N                             |
| `b` / `l`      | back to the list                            |
| `o`            | open the current issue in `$EDITOR`         |
| `h`            | help                                        |
| `q`            | quit                                        |

## What it detects

Rules are grouped by category.  Severity is critical / high / medium / low.

| category          | examples                                                   |
| ----------------- | ---------------------------------------------------------- |
| command-execution | os.system, subprocess shell=True, Runtime.exec, system()   |
| injection         | SQL string concatenation, innerHTML sinks                  |
| secret            | hardcoded passwords/api keys, credentials in URLs, PEM keys|
| weak-crypto       | MD5/SHA-1, DES/3DES/RC4/ECB                                |
| deserialization   | pickle.loads, yaml.load, ObjectInputStream, unserialize    |
| path-traversal    | file open calls fed from request/user inputs               |
| memory-unsafe     | gets/strcpy/strcat/sprintf, %s scanf, memcpy               |
| code-evaluation   | eval/exec of strings                                       |
| insecure-random   | predictable RNG used in security contexts                  |
| ssrf              | outbound requests built from user-controlled URLs          |

Supported languages: Python, JavaScript/TypeScript, Go, Java, C, C#, PHP, Ruby.

## Build from source

Needs Go 1.19+.

```console
./build.sh
```

Produces `dist/vscseny` (Linux amd64) and `dist/vscseny.exe` (Windows amd64).

## Notes

Vscseny is a pattern-based helper for review, not a guarantee of security.  A
clean report still warrants a manual design review.  Scan code you are
authorized to review.
