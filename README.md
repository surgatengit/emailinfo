<div align="center">

# 📧 email-audit.sh

### Full Email Authentication Audit from your Terminal

[![Bash](https://img.shields.io/badge/Made_with-Bash-1f425f?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux_|_macOS-blue)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/surgatengit/email-audit/pulls)

**One command. Ten checks. Full visibility into your domain's email security.**

[Features](#-features) · [Quick Start](#-quick-start) · [Checks](#-what-it-checks) · [Examples](#-example-output) · [Install](#-installation) · [FAQ](#-faq)

---

</div>

## 🔍 What is this?

`email-audit.sh` is a zero-dependency\* Bash script that performs a comprehensive audit of your domain's email authentication configuration. It checks **10 critical areas** of email security and gives you a scored report with actionable recommendations — all without leaving your terminal.

> \*Only `dig` is required. `openssl`, `curl` and `nc` unlock additional checks automatically.

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🌐 | **Bilingual (ES/EN)** | Auto-detects your system language. Force with `--lang es` or `--lang en` |
| 🎯 | **Scored report** | Every check contributes to a final score with a visual progress bar |
| 🔎 | **Provider detection** | Identifies 50+ email providers, security gateways and hosting platforms |
| 🎨 | **Beautiful output** | Color-coded results with Unicode box-drawing and status indicators |
| ⚡ | **Zero config** | Just point it at a domain — no API keys, no accounts, no setup |
| 🧩 | **Graceful degradation** | Works with just `dig`; unlocks more checks as optional tools are available |
| 📋 | **Actionable advice** | Every finding comes with a clear recommendation and RFC reference |

---

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/surgatengit/email-audit.git
cd email-audit

# Make it executable
chmod +x email-audit.sh

# Run it
./email-audit.sh example.com
```

That's it. No install steps, no containers, no dependencies to chase.

---

## 📦 Installation

### Option A — Clone & run

```bash
git clone https://github.com/YOUR_USER/email-audit.git
cd email-audit
chmod +x email-audit.sh
```

### Option B — One-liner download

```bash
curl -sLO https://raw.githubusercontent.com/YOUR_USER/email-audit/main/email-audit.sh && chmod +x email-audit.sh
```

### Option C — Add to your PATH

```bash
sudo cp email-audit.sh /usr/local/bin/email-audit
email-audit example.com
```

### Dependencies

| Tool | Required? | What it enables |
|------|-----------|-----------------|
| `dig` | **Yes** | All DNS lookups (core of the tool) |
| `openssl` | Optional | TLS certificate verification on MX servers |
| `curl` | Optional | MTA-STS policy download, BIMI logo validation |
| `nc` + `timeout` | Optional | Basic STARTTLS detection on port 25 |

<details>
<summary><b>📥 Install dependencies by distro</b></summary>

```bash
# Debian / Ubuntu
sudo apt-get install dnsutils openssl curl netcat-openbsd

# CentOS / RHEL / Fedora
sudo yum install bind-utils openssl curl nmap-ncat

# Arch Linux
sudo pacman -S bind openssl curl openbsd-netcat

# macOS (Homebrew)
brew install bind openssl curl
```

</details>

---

## 🛡️ What it Checks

```
 ┌─────────────────────────────────────────────────────────────┐
 │  #   Check           What it verifies                       │
 │ ─── ─────────────── ─────────────────────────────────────── │
 │  1   MX              Mail servers, priority, provider ID    │
 │  2   SPF             Sender policy, -all vs ~all, lookups   │
 │  3   DKIM            50+ common selectors, key presence     │
 │  4   DMARC           Policy (none/quarantine/reject),       │
 │                       pct, rua/ruf reporting                │
 │  5   DANE/TLSA       DNSSEC validation, TLSA records per MX │
 │  6   MTA-STS         DNS record + HTTPS policy download     │
 │  7   TLS-RPT         Reporting endpoints for TLS failures   │
 │  8   BIMI            Brand logo record, VMC, logo access    │
 │  9   TLS Certs       Certificate validity, expiry, hostname │
 │                       match, self-signed detection          │
 │ 10   Subdomains      SPF on common subdomains (mail, smtp…) │
 └─────────────────────────────────────────────────────────────┘
```

---

## 🖥️ Usage

```
Usage: ./email-audit.sh [--lang es|en] [domain]

Options:
  --lang es    Force Spanish output
  --lang en    Force English output
  -h, --help   Show help

If no --lang is given, language is auto-detected from your system locale.
If no domain is given, you'll be prompted interactively.
```

### Examples

```bash
# Basic audit
./email-audit.sh google.com

# Force English
./email-audit.sh --lang en empresa.es

# Force Spanish
./email-audit.sh --lang es example.com

# Interactive mode (prompts for domain)
./email-audit.sh

# Pipe to file (colors stripped automatically by most terminals)
./email-audit.sh example.com 2>&1 | tee audit-report.txt
```

---

## 📸 Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║       EMAIL AUTHENTICATION AUDIT                             ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  Domain:  example.com                                        ║
║  Date:    2026-03-18 14:30:00                                ║
║  Checks:  MX · SPF · DKIM · DMARC · DANE/TLSA                ║
║           MTA-STS · TLS-RPT · BIMI · TLS · Subdomains        ║
╚══════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────┐
│ 1. MX (Mail eXchange)                                        │
│ ...                                                          │
│  ✓ MX servers found:                                         │
│    PRIORITY     SERVER                                       │
│    10           mail.example.com.                            │
│                                                              │
│  Detected provider: Google Workspace                         │
└──────────────────────────────────────────────────────────────┘

              ... (8 more sections) ...

╔══════════════════════════════════════════════════════════════╗
║                     FINAL RESULT                             ║
╠══════════════════════════════════════════════════════════════╣
║   [████████████████░░░░]  16/20 points (80%)                 ║
║   Security level: GOOD  🟢                                   ║
╠══════════════════════════════════════════════════════════════╣
║  Check summary:                                              ║
║   ✓ MX    ✓ SPF    ✓ DKIM    ✓ DMARC                        ║
║   ✗ DANE  ✓ MTA-STS ✓ TLS-RPT ℹ BIMI                       ║
╠══════════════════════════════════════════════════════════════╣
║  Recommendations:                                            ║
║   1. Enable DNSSEC to protect DNS integrity                  ║
║   2. After DNSSEC, implement DANE/TLSA on MX                 ║
║   3. Consider BIMI to display brand logo in inboxes          ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 🏷️ Scoring

The audit uses a point-based system across all 10 checks:

| Score | Level | Meaning |
|-------|-------|---------|
| **≥ 80%** | 🟢 **Good** | Solid configuration, review periodically |
| **50–79%** | 🟡 **Improvable** | Basic protections in place, gaps remain |
| **< 50%** | 🔴 **Poor** | Significant vulnerabilities, action needed |

---

## 🔌 Provider Detection

The script identifies **50+ email providers** across categories:

<details>
<summary><b>Click to see the full list</b></summary>

**Email Providers:** Google Workspace, Microsoft 365, ProtonMail, Zoho, Yahoo, iCloud, Yandex, Fastmail, Tuta, Mailfence, Migadu

**Security Gateways:** Mimecast, Barracuda, Proofpoint, Symantec/Broadcom, Trend Micro, Sophos, Forcepoint, Cisco IronPort, Trellix/FireEye, SpamExperts, Hornetsecurity, Cloudflare

**Transactional/Marketing:** Mailgun, SendGrid, Amazon SES, Postmark, Mailchimp/Mandrill, Mailjet

**Hosting/Registrars:** OVH, IONOS, Gandi, Hover, Namecheap, GoDaddy, Rackspace, HostGator, Bluehost, DreamHost, Hetzner, Strato, Arsys, Dinahosting

**Platforms:** cPanel, Plesk, Zimbra

</details>

---

## 🌍 Language Support

| Language | Detection | Force flag |
|----------|-----------|------------|
| 🇪🇸 Español | Auto (`es_*` locale) | `--lang es` |
| 🇬🇧 English | Auto (everything else) | `--lang en` |

The script reads `$LANG`, `$LC_ALL`, and `$LC_MESSAGES` in that order. If your locale starts with `es`, you get Spanish. Everything else defaults to English.

---

## 📚 RFC References

This tool checks compliance with the following standards:

| Standard | RFC | Year |
|----------|-----|------|
| SPF | [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208) | 2014 |
| DKIM | [RFC 6376](https://datatracker.ietf.org/doc/html/rfc6376) | 2011 |
| DMARC | [RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489) | 2015 |
| DANE | [RFC 6698](https://datatracker.ietf.org/doc/html/rfc6698) / [RFC 7672](https://datatracker.ietf.org/doc/html/rfc7672) | 2012/2015 |
| MTA-STS | [RFC 8461](https://datatracker.ietf.org/doc/html/rfc8461) | 2018 |
| TLS-RPT | [RFC 8460](https://datatracker.ietf.org/doc/html/rfc8460) | 2018 |
| BIMI | [Draft](https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/) | WG |

---

## 🤔 FAQ

<details>
<summary><b>Is this safe to run against any domain?</b></summary>

Yes. The script only performs **passive DNS lookups** and optional TLS connections to public MX servers on standard ports. It does not send email, modify records, or perform any intrusive testing.
</details>

<details>
<summary><b>Why can't it check TLS certificates?</b></summary>

Most home ISPs and cloud providers block outbound port 25. If the script detects this, it provides links to online tools (ssl-tools.net, CheckTLS, Hardenize, MXToolbox, Internet.nl) as alternatives.
</details>

<details>
<summary><b>Why doesn't it find my DKIM records?</b></summary>

DKIM selectors are not discoverable from DNS alone. The script tests **50+ common selectors** (google, selector1, default, k1, protonmail, etc.), but your domain may use a custom one. Check your email headers for the `s=` tag to find it, then verify manually:

```bash
dig TXT yourselector._domainkey.yourdomain.com
```
</details>

<details>
<summary><b>Can I use this in CI/CD?</b></summary>

Absolutely. The script returns exit code `0` on success. You could parse the score from the output or adapt the script to output JSON for automated pipelines.
</details>

<details>
<summary><b>How do I contribute a new language?</b></summary>

Add a `load_strings_XX()` function following the pattern of `load_strings_es` / `load_strings_en`, update the `--lang` parser and `detect_language()`, and open a PR.
</details>

---

## 🤝 Contributing

Contributions are welcome! Here are some ideas:

- 🌍 **New languages** — add `load_strings_XX()` for your language
- 🔎 **More DKIM selectors** — found one missing? Add it to the list
- 🏢 **More providers** — help identify MX patterns for new providers
- 📊 **JSON output mode** — for CI/CD and automation
- 🐛 **Bug reports** — please include the domain (if public) and your OS

```bash
# Fork, clone, branch, hack, push, PR
git checkout -b feature/my-improvement
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

**If this tool helped you, give it a ⭐ — it helps others find it too.**

Made with ☕ and `dig`

</div>
