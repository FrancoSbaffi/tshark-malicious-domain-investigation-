# TShark Network Forensics – Malicious Domain Investigation

*TSHARK Challenge*

---

## Executive Summary
During this lab I confirmed a SOC alert by isolating malicious DNS traffic to **jx2-bavuong[.]com**, counting **14** HTTP requests, resolving its host **141[.]164[.]41[.]174**, carving the payload **vlauto[.]exe**, hashing it (**SHA-256** = `b4851333…20de`) and validating **TROJAN** behaviour in VirusTotal. All steps were performed with command-line **TShark 4.2.0** inside the THM VM and are fully reproducible.

---

## 1  Environment

| Component | Value |
|-----------|-------|
| Platform  | TryHackMe VM – *TShark Challenges Two* |
| Evidence  | `~/Desktop/exercise-files/directory-curiosity.pcap` |
| Tools     | `tshark 4.2.0`, `sha256sum`, VirusTotal (web) |

---

## 2  Methodology & Commands

### 2.1  List all DNS queries  
```bash
tshark -r directory-curiosity.pcap \
       -Y "dns.flags.response==0 && dns.qry.name" \
       -T fields -e frame.number -e dns.qry.name
```

The display filter isolates outbound queries; only jx2-bavuong.com appears repeatedly. 

---

### 2.2 Verify the domain in VirusTotal
A direct VT domain lookup shows ≥ 9 engines flagging it malicious. 

---

### 2.3 Count HTTP requests to the host
```bash
tshark -r directory-curiosity.pcap \
       -Y 'http.request && http.host=="jx2-bavuong.com"' \
       -T fields -e http.request.method | wc -l
```
Result = 14. An io,stat alternative is documented in the man-page. 

--- 

### 2.4 Extract server IP
```bash
tshark -r directory-curiosity.pcap \
       -Y 'ip.dst && http.host=="jx2-bavuong.com"' \
       -T fields -e ip.dst | sort -u
```
Returned address = 141[.]164[.]41[.]174. (User Cyberchef to defang the IP)

---

### 2.5 Identify HTTP banner
```bash
tshark -r directory-curiosity.pcap \
       -Y 'http.response && http.host=="jx2-bavuong.com"' \
       -T fields -e http.server | sort -u
```
Banner: Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9.

---

###  2.6 Follow the first TCP stream (directory listing)
```bash
tshark -r directory-curiosity.pcap -z follow,tcp,stream,0 -q
```
Stream 0 shows an index with 3 files; first filename = 123[.]php. 

---

### 2.7 Export all HTTP objects
```bash
mkdir extracted
tshark -r directory-curiosity.pcap \
       --export-objects "http,extracted"
```
--export-objects carves every file from HTTP traffic. 
Key artifact recovered: vlauto[.]exe.

--- 

### 2.8 Hash the payload
```bash
sha256sum extracted/vlauto.exe
# b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de
```

---

### 2.9 Enrich with VirusTotal
• PEiD packer field = “.NET executable”. 
• Lastline sandbox verdict = MALWARE TROJAN. 

---

### 3 Indicators of Compromise

| Indicator                   | Type            | Source          |
| --------------------------- | --------------- | --------------- |
| `jx2-bavuong[.]com`         | FQDN            | DNS/HTTP        |
| `141[.]164[.]41[.]174`      | IPv4            | A-record        |
| `Apache/2.2.11 … PHP/5.2.9` | HTTP banner     | Response header |
| `123[.]php`                 | Web-shell       | Directory index |
| `vlauto[.]exe`              | Payload         | HTTP object     |
| `b4851333…20de`             | SHA-256         | Local hash      |
| “.NET executable”           | PEiD packer     | VT static       |
| **TROJAN**                  | Dynamic verdict | VT sandbox      |

All strings are defanged ([.]) to avoid accidental clicks.

---

### 4 Lessons Learned

1. Display filters (-Y) in TShark accelerate deep-packet inspection without re-capturing traffic.
2. io,stat counters give quantitative evidence for SOC reports
3. --export-objects automates file carving, removing GUI steps. 
4. Enriching hashes with VirusTotal adds static and dynamic context valuable to incident-response.

---

### 5 Reproduction Guide (TL;DR)
```bash
git clone https://github.com/<username>/tshark-malicious-domain-investigation.git
cd tshark-malicious-domain-investigation

# Run core checks inside a sandbox
tshark -r evidence/directory-curiosity.pcap \
       -Y 'dns.flags.response==0 && dns.qry.name' \
       -T fields -e dns.qry.name | sort -u
tshark -r evidence/directory-curiosity.pcap \
       -Y 'http.request && http.host=="jx2-bavuong.com"' \
       --export-objects "http,carved"
```

Never open vlauto_sample.zip outside a lab; password is infected.

