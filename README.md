<div align="center">

```
 █████╗ ██╗    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██║    ██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
███████║██║    ██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║
██╔══██║██║    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║██║     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═╝      ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

### ⚔️ Async Recon Scanner &nbsp;+&nbsp; AI-Assisted Remediation Engine &nbsp;+&nbsp; Rich CLI

<p>
  <img src="https://img.shields.io/badge/python-3.13%2B-3776AB?logo=python&logoColor=white" alt="Python 3.13+">
  <img src="https://img.shields.io/badge/CLI-Typer-red" alt="Typer">
  <img src="https://img.shields.io/badge/UI-Rich-8A2BE2" alt="Rich">
  <img src="https://img.shields.io/badge/AI-OpenAI%20%2F%20Offline%20fallback-10A37F?logo=openai&logoColor=white" alt="OpenAI">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT">
  <img src="https://img.shields.io/badge/status-active-brightgreen" alt="Status: Active">
  <img src="https://img.shields.io/badge/PRs-welcome-ff69b4" alt="PRs Welcome">
</p>

**A single-file-feel CLI that scans a host, fingerprints what's listening, maps every open
port to an OWASP Top 10 category, and hands you a ready-to-run remediation patch —
AI-generated when you have an API key, deterministic when you don't.**

[Features](#-features) •
[Demo](#-demo) •
[Signature Database](#-signature-database) •
[Installation](#-installation) •
[Usage](#-usage) •
[Configuration](#-configuration) •
[Project Structure](#-project-structure) •
[Docker](#-docker) •
[Roadmap](#-roadmap) •
[Disclaimer](#-disclaimer)

</div>

---

## ✨ Features

| | |
|---|---|
| ⚡ **Async everywhere** | Built on `asyncio` from the ground up — scans hundreds of ports concurrently, capped by a configurable semaphore so it never floods local sockets. |
| 🧠 **AI-assisted remediation** | Every open port is sent to an OpenAI model for a tailored, enterprise-grade patch — no API key? It falls back to a deterministic, signature-based recommendation automatically. |
| 🧬 **24-service signature database** | FTP, SSH, Telnet, SMTP, DNS, HTTP/S, SMB, MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis, Elasticsearch, RDP, VNC, NFS, and more — each mapped to an OWASP Top 10 (2021) category. |
| 🔎 **HTTP-aware banner grabbing** | Sends a minimal `HEAD` probe to HTTP(S)-like ports so they actually return identifiable headers instead of sitting silent. |
| 🎯 **Flexible targeting** | Single host, comma-separated multi-host, single ports, ranges (`1-1024`), or built-in presets (`quick` / `default` / `full`). |
| 📊 **Live progress + summary tables** | A Rich progress bar while scanning, then a clean summary table of every exposure found. |
| 📁 **Markdown and/or JSON reports** | Human-readable audit report, machine-readable JSON for CI/CD and SIEM pipelines — or both in one run. |
| 🐳 **Docker-ready** | Ships with a slim, matching Dockerfile — build and run in seconds. |
| 🧩 **Clean, typed, modular codebase** | Separate `core/`, `ai_engine/`, `reporting/`, and `config/` layers — easy to extend with new signatures, report formats, or commands. |

---

## 🎬 Demo

```text
$ python main.py scan localhost

╭─────────────────────── ⚔️ NEXUS-AI VULNERABILITY MATRIX v2.0.0 ⚔️ ────────────────────────╮
│ [!] CRITICAL THREAT INTELLIGENCE SYSTEM INITIALIZED                                       │
│                                                                                           │
│  █████╗ ██╗    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗ │
│ ██╔══██╗██║    ██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║ │
│ ███████║██║    ██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║ │
│ ██╔══██║██║    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║ │
│ ██║  ██║██║     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║ │
│ ╚═╝  ╚═╝╚═╝      ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ │
╰────────────────────── ⚠️ AUTHORIZED CYBERSECURITY AUDITING ONLY ⚠️ ───────────────────────╯

[⚡] Initiating assessment against: localhost
[⚡] Scanning depth: 24 ports | timeout 1.5s | concurrency 250

⚠️ WARNING: Discovered 1 exposed entry point(s) on localhost.
------------------------------------------------------------------------
[CRITICAL] Port 22 (SSH)
 ╰─► OWASP Mapping: A07:2021-Identification and Authentication Failures
 ╰─► Computing remediation...

🛠️ [OFFLINE PATCH ENGINE RECOMMENDATION]
1. Restrict external access to port 22 using host/network firewall rules.
2. Audit the process bound to that port -- banner observed: 'SSH-2.0-OpenSSH_10.3p1'.
3. Disable cleartext protocols where applicable and enforce TLS.
4. If the service must remain internet-facing, place it behind an authenticated
   reverse proxy or VPN and enable rate limiting.
------------------------------------------------------------------------

                    Exposure Summary — localhost
┏━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Port ┃ Service ┃ OWASP Category                     ┃ Banner                     ┃
┡━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│   22 │ SSH     │ A07:2021-Identification and Auth… │ SSH-2.0-OpenSSH_10.3p1     │
└──────┴─────────┴─────────────────────────────────────┴───────────────────────────┘
[+] Markdown report saved: ./nexus_audit_localhost.md
```

> In a real terminal the banner is animated (a boot-sequence spinner) and everything
> above renders in full color via [Rich](https://github.com/Textualize/rich).

---

## 🧬 Signature Database

Run `python main.py signatures` anytime to print this table live from the code.
Each open port found during a scan is matched against this table and mapped to an
OWASP Top 10 (2021) category:

| Port | Service | OWASP Category | Typical Exposure |
|---|---|---|---|
| 21 | FTP | A05: Security Misconfiguration | Anonymous FTP access / plaintext authentication risk. |
| 22 | SSH | A07: Auth Failures | Outdated SSH protocol/cipher support or brute-force exposure. |
| 23 | Telnet | A02: Cryptographic Failures | Unencrypted management stream; credentials sent in cleartext. |
| 25 | SMTP | A05: Security Misconfiguration | Open relay risk / unauthenticated mail submission. |
| 53 | DNS | A05: Security Misconfiguration | Exposed recursive resolver; cache poisoning / amplification risk. |
| 80 | HTTP | A05: Security Misconfiguration | Missing security headers (HSTS, X-Frame-Options) / cleartext transport. |
| 110 | POP3 | A02: Cryptographic Failures | Unencrypted mail retrieval; credentials sent in cleartext. |
| 143 | IMAP | A02: Cryptographic Failures | Unencrypted mail access; credentials sent in cleartext. |
| 443 | HTTPS | A02: Cryptographic Failures | Potential legacy TLS negotiation or misconfigured cert chain. |
| 445 | SMB | A05: Security Misconfiguration | Exposed file-sharing service; historically a ransomware vector. |
| 993 | IMAPS | A02: Cryptographic Failures | TLS-wrapped IMAP exposed externally; verify cipher suite strength. |
| 995 | POP3S | A02: Cryptographic Failures | TLS-wrapped POP3 exposed externally; verify cipher suite strength. |
| 1433 | MSSQL | A05: Security Misconfiguration | Remote database access exposed to external interfaces. |
| 1521 | Oracle DB | A05: Security Misconfiguration | Remote database listener exposed to external interfaces. |
| 2049 | NFS | A01: Broken Access Control | Exposed network filesystem; check export permissions. |
| 3306 | MySQL | A05: Security Misconfiguration | Remote database access exposed to external interfaces. |
| 3389 | RDP | A07: Auth Failures | Exposed remote desktop; common brute-force/ransomware entry point. |
| 5432 | PostgreSQL | A05: Security Misconfiguration | Remote database access exposed to external interfaces. |
| 5900 | VNC | A07: Auth Failures | Remote framebuffer access; often weak or absent authentication. |
| 6379 | Redis | A05: Security Misconfiguration | In-memory data store commonly deployed without authentication. |
| 8080 | HTTP-Proxy | A01: Broken Access Control | Exposed admin console or proxy panel without access controls. |
| 8443 | HTTPS-Alt | A05: Security Misconfiguration | Alternate HTTPS management interface; check for default/unpatched panel. |
| 9200 | Elasticsearch | A01: Broken Access Control | Search/index engine often exposed without authentication by default. |
| 27017 | MongoDB | A01: Broken Access Control | Document database historically exposed without authentication by default. |

---

## 📦 Requirements

- Python **3.10+** (developed/tested against 3.13)
- `pip` and (recommended) a virtual environment
- An [OpenAI API key](https://platform.openai.com/api-keys) — **optional**, the scanner
  runs fully offline with signature-based patches if you skip it

---

## ⚙️ Installation

```bash
git clone https://github.com/shadownebulax8-cmd/nexus-ai-vuln-scanner.git
cd nexus-ai-vuln-scanner

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
cp .env.example .env              # optional: add your OpenAI key here
```

---

## 🚀 Usage

```bash
python main.py --help
```

### Commands

| Command | Description |
|---|---|
| `scan <target>` | Run a full recon + AI-remediation sweep against one or more targets. |
| `signatures` | List the built-in port → service → OWASP signature database. |
| `banner` | Print the intro banner without running a scan. |
| `version` | Show the application version. |

### `scan` options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--ports` | `-p` | *(preset)* | Explicit ports/ranges, comma separated — e.g. `22,80,443` or `1-1024`. Overrides `--preset`. |
| `--preset` | | `default` | Port preset: `quick` (8 ports), `default` (24 common ports), `full` (1-1024). |
| `--api-key` | `-k` | `.env` value | OpenAI API key for this run only. |
| `--model` | `-m` | `gpt-4o` | OpenAI model used for AI-assisted patch generation. |
| `--timeout` | `-t` | `1.5` | Per-port connection timeout, in seconds. |
| `--concurrency` | `-c` | `250` | Maximum concurrent port probes. |
| `--output` | `-o` | `.` | Directory to write report(s) into. |
| `--format` | `-f` | `markdown` | Report format(s): `markdown`, `json`, or `both`. |
| `--no-banner` | | off | Skip the animated intro banner (handy for CI/scripted runs). |
| `--verbose` | `-v` | off | Show raw handshake banners in the live console output. |

### Examples

```bash
# Basic scan
python main.py scan localhost

# Explicit ports
python main.py scan example.com --ports 22,80,443

# A full port-range sweep
python main.py scan example.com --preset full

# Multiple targets in one run, with a rollup summary at the end
python main.py scan example.com,192.168.1.10 --preset quick

# Export both report formats into a custom folder
python main.py scan example.com --format both --output ./reports

# One-off key/model override, CI-friendly (no banner, verbose logging)
python main.py scan example.com -k sk-... -m gpt-4o-mini --no-banner --verbose
```

---

## 🔧 Configuration

All settings can be set via environment variables or a `.env` file (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | *(empty)* | Enables AI-generated patches. Leave blank for offline mode. |
| `OPENAI_MODEL` | `gpt-4o` | Default model, overridable per-run with `--model`. |
| `GLOBAL_TIMEOUT` | `1.5` | Default per-port connection timeout (seconds). |
| `BANNER_READ_TIMEOUT` | `0.6` | How long to wait for a banner after connecting. |
| `MAX_CONCURRENCY` | `250` | Default concurrent-probe cap. |
| `REPORT_OUTPUT_DIR` | `.` | Default directory for generated reports. |

---

## 🗂️ Project Structure

```
ai_vuln_scanner/
├── main.py                     # CLI entrypoint (Typer) — scan / signatures / banner / version
├── config/
│   └── settings.py             # env-driven settings (pydantic-settings)
├── core/
│   ├── banner.py                # intro banner
│   ├── network_scanner.py       # async scanner + 24-service signature DB
│   └── port_parser.py           # port / range / preset parsing
├── ai_engine/
│   └── patch_generator.py       # AI (async) + offline remediation patches
├── reporting/
│   ├── markdown_writer.py       # .md report export
│   └── json_writer.py           # .json report export
├── requirements.txt
├── Dockerfile
├── .env.example
└── .gitignore
```

---

## 🐳 Docker

```bash
docker build -t nexus-ai .
docker run --rm nexus-ai scan example.com
```

---

## 🗺️ Roadmap

- [ ] UDP port support
- [ ] Export to HTML report
- [ ] Anthropic/Claude backend option alongside OpenAI
- [ ] Scheduled/recurring scan mode with diffing against the previous report
- [ ] Plugin system for custom signature packs

Contributions and PRs are welcome — feel free to open an issue first for larger changes.

---

## ⚠️ Disclaimer

This tool is built for **authorized security auditing and educational purposes only**.
Only scan hosts and networks you **own** or have **explicit written permission** to test.
Unauthorized scanning of systems you do not control may violate the law (e.g. the
Computer Fraud and Abuse Act in the US, or equivalent legislation elsewhere) —
you are solely responsible for how you use this software.

## 📄 License

Released under the [MIT License](LICENSE).

---

<div align="center">

Made with ⚔️ using [Typer](https://typer.tiangolo.com/), [Rich](https://github.com/Textualize/rich), and the OpenAI API.

</div>
