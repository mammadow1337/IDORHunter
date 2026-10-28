# IDORHunter

**IDORHunter** is a lightweight Python tool for detecting potential **Insecure Direct Object Reference (IDOR)** vulnerabilities in web applications.

> **Author:** `mammadow1337`  
> **Version:** 1.0

## Banner

```text
██╗███╗   ██╗██████╗  ██████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
  ██║████╗  ██║██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██║██╔██╗ ██║██║  ██║██║   ██║██████╔╝█████╔╝ ██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██║██║╚██╗██║██║  ██║██║   ██║██╔══██╗██╔═██╗ ██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██║██║ ╚████║██████╔╝╚██████╔╝██║  ██║██║  ██╗╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═╝╚═╝  ╚═══╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

                    ┌────────────────────────────────────────────┐
                    │  IDORHunter v1.0 — IDOR Vulnerability      │
                    │           Scanner for Web Applications     │
                    │              by : mammadow1337             │
                    └────────────────────────────────────────────┘
```

## Installation

```bash
git clone https://github.com/mammadow1337/IDORHunter.git
cd IDORHunter
pip install -r requirements.txt
```

## Usage

```bash
python idorhunter.py -u "https://example.com/profile?user_id=1337"
python idorhunter.py -l urls.txt
python idorhunter.py -u "https://example.com/profile?user_id=1337" -r 1 2 5 10
python idorhunter.py -u "https://example.com/profile?user_id=1337" -c "session=COOKIE" -H "Authorization: Bearer TOKEN" -o results.json
```

## Options

| Option | Description |
|---|---|
| `-u`, `--url` | Scan one URL |
| `-l`, `--url-list` | Scan URLs from a file |
| `-r`, `--range` | ID offsets to test; default `1 2 3` |
| `-c`, `--cookie` | Cookie header |
| `-H`, `--header` | Extra header; repeatable |
| `-t`, `--threads` | Concurrent workers; default `5` |
| `-d`, `--delay` | Delay between requests |
| `-o`, `--output` | JSON output file |
| `-v`, `--verbose` | Show all requests |
| `--no-banner` | Hide banner |

## Notice

Use only with explicit authorization. Unauthorized testing may be illegal.

## License

MIT
