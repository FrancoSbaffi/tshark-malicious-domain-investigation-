# TShark Network Forensics – Malicious Domain Investigation 🕵️‍♂️

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Last Update](https://img.shields.io/github/last-commit/<username>/tshark-malicious-domain-investigation)
[![TryHackMe Room](https://img.shields.io/badge/TryHackMe-TShark__Challenges__Two-red)](https://tryhackme.com/room/tsharkchallengestwo)

Hands-on case study proving a SOC alert true positive by isolating **jx2-bavuong[.]com**, counting 14 HTTP requests, carving `vlauto[.]exe`, and confirming a **TROJAN** verdict in VirusTotal.

---

## 📑 Table of Contents
1. [Overview](#overview)
2. [Repository Structure](#repository-structure)
3. [Quick Start](#quick-start)
4. [Key Findings (IOCs)](#key-findings-iocs)
5. [Reproducing the Analysis](#reproducing-the-analysis)
6. [Evidence Files](#evidence-files)
7. [Disclaimer & Safety Notice](#disclaimer--safety-notice)

---

## Overview
This investigation was performed inside the TryHackMe *TShark Challenges Two* VM using **TShark 4.2.0** and **VirusTotal**.  
The goal: verify an alert that “a user came across a poor file index, and their curiosity led to problems.”

**Outcome**

| Evidence | Value |
|----------|-------|
| Malicious domain | `jx2-bavuong[.]com` |
| Server IP | `141[.]164[.]41[.]174` |
| HTTP requests | `14` |
| Server banner | `Apache/2.2.11 … PHP/5.2.9` |
| Web shell | `123[.]php` |
| Payload | `vlauto[.]exe` |
| SHA-256 | `b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de` |
| PEiD packer | `.NET executable` |
| Sandbox verdict | `MALWARE TROJAN` |

Full methodology and screenshots live in **[docs/report.md](docs/report.md)**.

---

## Repository Structure
tshark-malicious-domain-investigation/
├── README.md
├── docs/
│ └── report.md # Detailed step-by-step write-up
├── evidence/
│ ├── directory-curiosity.pcap
│ └── vlauto_sample.zip # password: infected
└── .gitignore # prevents accidental upload of extracted binaries


---

## Quick Start
```bash
# 1) Clone
git clone https://github.com/FrancoSbaffi/tshark-malicious-domain-investigation-.git
cd tshark-malicious-domain-investigation

# 2) Read the full report
code docs/report.md   # or open in your browser on GitHub

# 3) (Optional) Re-run analysis in a sandbox VM
tshark -r evidence/directory-curiosity.pcap --export-object "http,extracted"
```

---

### Key Findings (IOCs)
See Overview table above or import evidence/iocs.csv (generated from the report) into your SIEM for correlation.

---

### Reproducing the Analysis

Filter DNS queries

```bash
# 1)
tshark -r directory-curiosity.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name
Count HTTP hits

# 2)
tshark -r directory-curiosity.pcap -Y 'http.host=="jx2-bavuong.com"' -T fields -e http.request.method | wc -l
Export HTTP objects

# 3) 
tshark -r directory-curiosity.pcap --export-object "http,extracted"
```

Hash vlauto.exe and verify on VirusTotal.

All commands and reasoning appear in docs/report.md.

---

### Disclaimer & Safety Notice
The vlauto[.]exe sample is live malware. It is zipped with password infected to prevent accidental execution.

Inspect binaries only in an isolated lab VM.

All indicators are defanged ( [.] ) to avoid inadvertent clicks.