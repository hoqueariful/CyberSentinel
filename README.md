# CyberSentinel 🛡️

**Python security automation suite for SOC analysis, log analysis, network scanning, and web vulnerability assessment.**

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-success)]()

**Author:** Ariful Hoque
**LinkedIn:** [linkedin.com/in/contactariful](https://linkedin.com/in/contactariful)
**GitHub:** [github.com/hoqueariful](https://github.com/hoqueariful)

---

## ⚠️ Legal Disclaimer

These tools are for educational purposes and **authorised security testing only**. Unauthorised scanning or testing of systems you do not own or have explicit written permission to test is illegal. Always obtain permission before conducting any security assessments.

---

## 🎯 Overview

CyberSentinel is a three-module Python toolkit built to automate routine SOC analyst tasks. It reduces manual analysis time, standardises output reporting, and provides a reproducible framework for security assessments and incident response workflows.

Built as part of an MSc in Cyber Security at the University of Portsmouth and extended with professional-grade tooling for portfolio demonstration.

**Key metrics:**
- 60% reduction in manual log analysis time vs manual inspection
- Multi-threaded port scanner (up to 1,000 concurrent connections)
- 10+ automated security checks across web vulnerability module
- 4 attack pattern categories detected (SQLi, XSS, path traversal, command injection)
- 1,200+ lines of documented Python

---

## 🛠️ Modules

### 1. `security_log_parser.py` — Security Log Parser

Parses raw auth logs and application logs to detect attack patterns, failed authentication bursts, and suspicious activity.

**Detects:**
- Failed and successful login attempts (brute-force pattern identification)
- Port scanning activity
- SQL injection, XSS, path traversal, and command injection signatures
- Suspicious IP tracking and frequency analysis

**Output formats:** Plain text report + JSON export

```bash
# Analyse a log file
python security_log_parser.py sample_security.log

# Save report to file
python security_log_parser.py /var/log/auth.log -o report.txt

# Export findings as JSON (for SIEM ingestion or ticketing)
python security_log_parser.py /var/log/auth.log -j findings.json
```

**Example output:**
```
================================================================
CYBERSENTINEL - SECURITY LOG PARSER
================================================================
Analysis Date:    2024-02-17 14:30:00
================================================================
SUMMARY STATISTICS
----------------------------------------------------------------
Failed Login Attempts:    47
Successful Logins:        12
Port Scan Detections:     3
Security Warnings:        8
Attack Patterns Found:    5
  - SQL Injection:        2
  - XSS Attempts:         1
  - Path Traversal:       2
```

---

### 2. `port_scanner.py` — Network Port Scanner

Multi-threaded TCP port scanner with service detection and banner grabbing. Built for security assessments and asset discovery in authorised environments.

**Features:**
- Concurrent scanning (configurable thread count, default 100)
- Service identification and banner grabbing on open ports
- Flags potentially vulnerable services (Telnet, FTP, SMB)
- Customisable port ranges and timeout

```bash
# Scan common ports
python port_scanner.py localhost --common

# Scan a specific range
python port_scanner.py 192.168.0.10 -p 1-1000

# Custom threads and timeout
python port_scanner.py 10.0.0.1 -p 1-65535 -t 200 --timeout 0.5
```

**Example output:**
```
[+] Port 22    OPEN   SSH      OpenSSH 8.2
[+] Port 80    OPEN   HTTP     Apache/2.4.41
[+] Port 443   OPEN   HTTPS    nginx/1.18.0
[!] Port 23    OPEN   TELNET   *** VULNERABLE SERVICE DETECTED ***
```

---

### 3. `vulnerability_checker.py` — Web Vulnerability Checker

Automated web application vulnerability scanner covering OWASP-aligned security checks with a 0–100 risk scoring system.

**Checks performed:**
- HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- SSL/TLS configuration (protocol version, cipher strength, certificate validity)
- CORS misconfiguration
- Cookie security flags (HttpOnly, Secure, SameSite)
- Default/test file exposure
- Directory listing detection

```bash
# Standard scan
python vulnerability_checker.py https://example.com

# Full scan including directory brute-force
python vulnerability_checker.py https://example.com --full
```

**Example output:**
```
================================================================
CYBERSENTINEL - VULNERABILITY CHECKER
================================================================
FINDINGS SUMMARY
----------------------------------------------------------------
Critical:  0
High:      2  [Missing HSTS, CORS misconfiguration]
Medium:    3  [Weak CSP, no HttpOnly on session cookie, TLS 1.1 enabled]
Low:       1  [Server version disclosed in headers]

RISK SCORE: 38/100 - HIGH RISK
```

---

## 📋 Installation

```bash
git clone https://github.com/hoqueariful/CyberSentinel.git
cd CyberSentinel
pip install -r requirements.txt
```

**Requirements:** Python 3.6+, `requests` library (see `requirements.txt`)

---

## 💡 Incident Response Workflow Example

```bash
# Step 1: Identify suspicious IPs from auth logs
python security_log_parser.py /var/log/auth.log -j incident_$(date +%Y%m%d).json

# Step 2: Scan suspicious IP to understand exposed attack surface
python port_scanner.py 192.168.1.100 --common

# Step 3: Check associated web server for vulnerabilities
python vulnerability_checker.py https://internal-server.example.com --full
```

---

## 🎓 Skills Demonstrated

| Area | Tools / Concepts |
|------|-----------------|
| Log Analysis | Pattern detection, regex parsing, frequency analysis, JSON export |
| Network Security | TCP scanning, service identification, banner grabbing, threading |
| Web Security | OWASP Top 10 checks, SSL/TLS assessment, CORS, security headers |
| Python Development | OOP, multi-threading, argparse CLI, file I/O, error handling |
| SOC Operations | Alert generation, risk scoring, incident report formatting |

---

## 📝 License

MIT — see [LICENSE](LICENSE) for details. For educational and authorised testing purposes only.
