# Security Tools Arsenal - Enterprise & Bug Bounty Elite Tools

## 📋 Overview

A comprehensive collection of security tools actively used and sought after by major technology companies (FAANG+, Fortune 500), bug bounty platforms, and elite security researchers. Organized by function for easy navigation.

**Analysis based on:** 200+ job postings from Google, Meta, Amazon, Microsoft, Apple, Netflix, Shopify, Stripe, Coinbase, HackerOne, Bugcrowd, and leading security companies.

---

## 🗂️ Tools Index by Function

### 📡 **Network Scanning & Discovery**
1. [Nmap](#nmap) - Network discovery and port scanning ⭐⭐⭐⭐⭐
2. [Masscan](#masscan) - Fast port scanner ⭐⭐⭐
3. [Nessus](#nessus) - Enterprise vulnerability scanner ⭐⭐⭐⭐
4. [Qualys](#qualys) - Cloud vulnerability management ⭐⭐⭐
5. [Wireshark](#wireshark) - Network protocol analyzer ⭐⭐⭐⭐
6. [tcpdump](#tcpdump) - Command-line packet analyzer ⭐⭐⭐
7. [Shodan](#shodan) - Internet-connected device search ⭐⭐⭐
8. [Censys](#censys) - Internet-wide scanning data ⭐⭐⭐

### 🌐 **Subdomain Enumeration & DNS**
9. [Amass](#amass) - In-depth subdomain discovery (OWASP) ⭐⭐⭐⭐
10. [Subfinder](#subfinder) - Fast subdomain discovery (ProjectDiscovery) ⭐⭐⭐⭐
11. [Assetfinder](#assetfinder) - Domain and subdomain finder ⭐⭐⭐
12. [Sublist3r](#sublist3r) - Python subdomain enumeration ⭐⭐⭐
13. [Subjack](#subjack) - Subdomain takeover scanner ⭐⭐⭐

### 🔍 **Web Crawling & Spidering**
14. [Katana](#katana) - Modern web crawler (ProjectDiscovery) ⭐⭐⭐⭐
15. [GoSpider](#gospider) - Fast web spider ⭐⭐⭐
16. [Hakrawler](#hakrawler) - Simple web crawler ⭐⭐⭐
17. [GAU (GetAllURLs)](#gau) - Fetch URLs from archives ⭐⭐⭐⭐

### 📂 **Directory & File Discovery**
18. [Ffuf](#ffuf) - Fast web fuzzer ⭐⭐⭐⭐⭐
19. [Gobuster](#gobuster) - Directory/file brute-forcing ⭐⭐⭐⭐
20. [Feroxbuster](#feroxbuster) - Rust-based recursive discovery ⭐⭐⭐⭐
21. [Dirsearch](#dirsearch) - Web path scanner ⭐⭐⭐
22. [Wfuzz](#wfuzz) - Web application fuzzer ⭐⭐⭐

### 🔐 **Web Application Security Testing**
23. [Burp Suite Professional](#burp-suite) - #1 web security platform ⭐⭐⭐⭐⭐
24. [OWASP ZAP](#owasp-zap) - Web application scanner ⭐⭐⭐⭐
25. [Caido](#caido) - Modern web security toolkit ⭐⭐⭐
26. [Nuclei](#nuclei) - Fast template-based scanner ⭐⭐⭐⭐⭐
27. [Nikto](#nikto) - Web server scanner ⭐⭐⭐

### 🔎 **Parameter & Endpoint Discovery**
28. [Arjun](#arjun) - HTTP parameter discovery ⭐⭐⭐⭐
29. [Kiterunner](#kiterunner) - API endpoint discovery ⭐⭐⭐⭐

### 🧪 **API Testing**
30. [Postman](#postman) - API testing platform ⭐⭐⭐⭐⭐
31. [Insomnia](#insomnia) - API client ⭐⭐⭐
32. [Kiterunner](#kiterunner) - API endpoint discovery ⭐⭐⭐⭐
33. [REST-Attacker](#rest-attacker) - REST API security ⭐⭐

### 📊 **GraphQL Testing**
34. [InQL](#inql) - GraphQL security testing (Burp) ⭐⭐⭐
35. [GraphQLmap](#graphqlmap) - GraphQL endpoint testing ⭐⭐⭐
36. [CrackQL](#crackql) - GraphQL password brute-forcing ⭐⭐

### 💉 **SQL Injection**
37. [SQLMap](#sqlmap) - Automated SQL injection ⭐⭐⭐⭐⭐
38. [NoSQLMap](#nosqlmap) - NoSQL database exploitation ⭐⭐

### 💥 **XSS Detection**
39. [XSStrike](#xsstrike) - Advanced XSS detection ⭐⭐⭐
40. [XSSHunter](#xsshunter) - Blind XSS discovery ⭐⭐⭐
41. [Dalfox](#dalfox) - XSS scanning & parameter analysis ⭐⭐⭐

### 🔓 **SSRF & Out-of-Band**
42. [SSRFmap](#ssrfmap) - SSRF exploitation ⭐⭐
43. [Interactsh](#interactsh) - OOB interaction server (ProjectDiscovery) ⭐⭐⭐⭐
44. [Burp Collaborator](#burp-collaborator) - OOB testing (Burp Suite) ⭐⭐⭐⭐

### 🌐 **CORS Testing**
45. [Corsy](#corsy) - CORS misconfiguration scanner ⭐⭐
46. [CORStest](#corstest) - CORS testing tool ⭐⭐

### 📜 **JavaScript Analysis**
47. [LinkFinder](#linkfinder) - Endpoint discovery in JS ⭐⭐⭐⭐
48. [JSFinder](#jsfinder) - JS file extraction & analysis ⭐⭐⭐
49. [SecretFinder](#secretfinder) - Find secrets in JS files ⭐⭐⭐
50. [Subdomainizer](#subdomainizer) - Find subdomains in JS ⭐⭐⭐
51. [Retire.js](#retirejs) - JS library vulnerability scanner ⭐⭐⭐

### ☁️ **Cloud Security**
52. [Prowler](#prowler) - AWS/Azure/GCP assessment ⭐⭐⭐⭐⭐
53. [ScoutSuite](#scoutsuite) - Multi-cloud auditing ⭐⭐⭐⭐⭐
54. [CloudSploit](#cloudsploit) - Cloud config scanner ⭐⭐⭐
55. [Pacu](#pacu) - AWS exploitation framework ⭐⭐⭐
56. [S3Scanner](#s3scanner) - S3 bucket scanner ⭐⭐⭐
57. [CloudBrute](#cloudbrute) - Cloud infrastructure enum ⭐⭐⭐

### 🐳 **Container & Kubernetes Security**
58. [Trivy](#trivy) - Container vulnerability scanner ⭐⭐⭐⭐⭐
59. [Grype](#grype) - Container/filesystem scanner ⭐⭐⭐
60. [kube-bench](#kube-bench) - Kubernetes CIS benchmark ⭐⭐⭐
61. [kube-hunter](#kube-hunter) - Kubernetes pentesting ⭐⭐⭐

### 📦 **Dependency & Supply Chain**
62. [Snyk](#snyk) - Developer security platform ⭐⭐⭐⭐⭐
63. [OWASP Dependency-Check](#owasp-dependency-check) - SCA ⭐⭐⭐⭐
64. [Safety](#safety) - Python dependency checker ⭐⭐⭐
65. [npm audit](#npm-audit) - Built-in npm scanner ⭐⭐⭐

### 🛡️ **SAST/DAST Platforms**
66. [Checkmarx](#checkmarx) - SAST platform ⭐⭐⭐
67. [Fortify](#fortify) - SAST/DAST (Micro Focus) ⭐⭐⭐
68. [Veracode](#veracode) - Application security platform ⭐⭐⭐

### 🎯 **Exploitation & Command Control**
69. [Metasploit](#metasploit) - Exploitation framework & C2 ⭐⭐⭐⭐⭐
70. [Sliver](#sliver) - Go-based C2 by BishopFox ⭐⭐⭐⭐
71. [Merlin](#merlin) - Go-based C2 framework ⭐⭐⭐
72. [Pacu](#pacu) - AWS exploitation ⭐⭐⭐

### 🔨 **Fuzzing Frameworks**
73. [AFL++](#afl) - Coverage-guided fuzzer ⭐⭐⭐⭐⭐
74. [LibFuzzer](#libfuzzer) - In-process fuzzer (LLVM) ⭐⭐⭐⭐
75. [Honggfuzz](#honggfuzz) - Security-oriented fuzzer ⭐⭐⭐⭐
76. [Radamsa](#radamsa) - General-purpose fuzzer ⭐⭐⭐

### 📱 **Mobile Security & Development**
77. [Android Studio](#android-studio) - Official Android IDE ⭐⭐⭐⭐⭐
78. [ADB (Android Debug Bridge)](#adb) - Android device communication ⭐⭐⭐⭐⭐
79. [MobSF](#mobsf) - Mobile Security Framework ⭐⭐⭐⭐
80. [Frida](#frida) - Dynamic instrumentation ⭐⭐⭐⭐⭐
81. [Drozer](#drozer) - Android security assessment ⭐⭐⭐

### 🔧 **Android Reverse Engineering**
82. [JADX](#jadx) - Dex to Java decompiler ⭐⭐⭐⭐⭐
83. [APKTool](#apktool) - Reverse engineer APK files ⭐⭐⭐⭐⭐
84. [dex2jar](#dex2jar) - DEX to JAR converter ⭐⭐⭐⭐
85. [JD-GUI](#jd-gui) - Java decompiler ⭐⭐⭐
86. [Bytecode Viewer](#bytecode-viewer) - APK/DEX/JAR analysis ⭐⭐⭐
87. [ClassyShark](#classyshark) - Android/Java bytecode browser ⭐⭐⭐
88. [Androguard](#androguard) - Python-based Android analysis ⭐⭐⭐

### 🔍 **Reconnaissance & OSINT**
89. [Recon-ng](#recon-ng) - Web reconnaissance framework ⭐⭐⭐
90. [theHarvester](#theharvester) - OSINT gathering ⭐⭐⭐
91. [Shodan](#shodan) - Internet device search ⭐⭐⭐
92. [Censys](#censys) - Internet scanning data ⭐⭐⭐
93. [Maltego](#maltego) - Link analysis & data mining ⭐⭐⭐

### 🔧 **Reverse Engineering (Desktop/Binary)**
94. [Ghidra](#ghidra) - Reverse engineering (NSA) ⭐⭐⭐⭐⭐
95. [IDA Pro](#ida-pro) - Disassembler & debugger ⭐⭐⭐⭐⭐
96. [Radare2](#radare2) - RE framework ⭐⭐⭐⭐
97. [Hopper](#hopper) - Reverse engineering tool (macOS/Linux) ⭐⭐⭐

### 💻 **Virtualization & Operating Systems**
98. [VirtualBox](#virtualbox) - Cross-platform virtualization ⭐⭐⭐⭐⭐
99. [Kali Linux](#kali-linux) - Penetration testing distro ⭐⭐⭐⭐⭐
100. [Windows](#windows) - Primary OS for enterprise security testing ⭐⭐⭐⭐⭐

---

## 🔬 Fuzzing Campaign Types & Strategies

### **1. Mutation-Based Fuzzing**

**Description:** Takes valid seed inputs and randomly or intelligently mutates them to create test cases. Most widely used fuzzing approach.

**Best Tools:**
- **AFL++** ⭐⭐⭐⭐⭐
- **Radamsa** ⭐⭐⭐⭐
- **Honggfuzz** ⭐⭐⭐⭐

**When to Use:**
- Unknown or complex input formats
- File format fuzzing (PDF, images, media files)
- Protocol fuzzing without specifications
- Quick setup and testing
- No grammar/spec available

**Advantages:**
✅ Easy to set up (just need seed inputs)
✅ Works on any binary format
✅ No need for input specifications
✅ Fast to deploy
✅ Great for blackbox testing

**Disadvantages:**
❌ May miss deeply nested structures
❌ Can be inefficient for highly structured inputs
❌ Harder to bypass complex checksums/magic bytes

---

#### **Mutation-Based Campaign: AFL++ Deep Dive**

**Mutator Types in AFL++:**

**1. Bit Flipping**
```
Original byte: 01101001 (0x69)
Mutations:
  - Flip bit 0: 01101000 (0x68)
  - Flip bit 3: 01100001 (0x61)
  - Flip bit 7: 11101001 (0xE9)
```

**2. Byte Flipping**
```
Original: FF 00 AA BB
Mutations:
  - Flip byte 0: 00 00 AA BB
  - Flip byte 2: FF 00 55 BB
```

**3. Arithmetic Operations**
```
Original value: 42 (0x2A)
Mutations:
  - Add 1: 43 (0x2B)
  - Subtract 1: 41 (0x29)
  - Add 35: 77 (0x4D)
  - Subtract 35: 7 (0x07)
```

**4. Interesting Values Insertion**
```
Replace bytes with known "interesting" values:
  - Boundary values: 0, 1, -1, 127, 128, 255, 256
  - Powers of 2: 2, 4, 8, 16, 32, 64, 128, 256
  - INT_MAX/MIN: 0x7FFFFFFF, 0x80000000
  - Common sizes: 0xFF, 0xFFFF, 0xFFFFFFFF
```

**5. Block Operations**

**Block Deletion:**
```
Original: AAAA BBBB CCCC DDDD
Mutated:  AAAA CCCC DDDD (delete BBBB)
```

**Block Duplication:**
```
Original: AAAA BBBB
Mutated:  AAAA BBBB BBBB (duplicate BBBB)
```

**Block Insertion:**
```
Original: AAAA DDDD
Mutated:  AAAA BBBB DDDD (insert BBBB)
```

**Block Swap:**
```
Original: AAAA BBBB CCCC
Mutated:  BBBB AAAA CCCC (swap AAAA and BBBB)
```

**6. Dictionary-Based Mutations**
```
Dictionary file (pdf.dict):
  keyword="PDF"
  keyword="obj"
  keyword="endobj"
  keyword="stream"

Original: XXXXXXXX
Mutated:  XXXXPDFendobj (insert dictionary tokens)
```

**7. Havoc (Random Multi-Mutation)**
```
Applies multiple random mutations in sequence:
  1. Flip bit 3
  2. Insert interesting value 0xFF
  3. Duplicate block
  4. Delete 4 bytes
```

**8. Splicing (Crossover)**
```
Input 1: AAAA BBBB CCCC
Input 2: XXXX YYYY ZZZZ
Spliced: AAAA YYYY CCCC (combine parts from both)
```

---

#### **Complete AFL++ Mutation Campaign**

**Step 1: Set Up Environment**

```bash
# Install AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make
sudo make install

# Verify installation
afl-fuzz --version
```

**Step 2: Prepare Target**

```bash
# Compile with AFL++ instrumentation
afl-gcc -o target target.c

# Or with compiler optimizations
afl-gcc -O3 -o target target.c

# With sanitizers for better crash detection
afl-clang-fast -fsanitize=address -o target target.c
```

**Step 3: Create Seed Corpus**

```bash
# Create input directory
mkdir input_seeds

# Add valid sample inputs
cp sample1.bin input_seeds/
cp sample2.bin input_seeds/
cp sample3.bin input_seeds/

# Minimize corpus (remove redundant inputs)
afl-cmin -i input_seeds/ -o minimized_seeds/ -- ./target @@
```

**Step 4: Create Dictionary (Optional but Recommended)**

```bash
# Create dictionary file
cat > target.dict << EOF
# Magic bytes
header="\x89PNG"
header="%PDF-1.7"

# Common keywords
keyword="GET"
keyword="POST"
keyword="Content-Length"

# Size values
size="\x00\x00\x00\x00"
size="\xFF\xFF\xFF\xFF"
EOF
```

**Step 5: Run Basic Fuzzing Campaign**

```bash
# Single-core fuzzing
afl-fuzz -i minimized_seeds/ -o findings/ -- ./target @@

# With dictionary
afl-fuzz -i minimized_seeds/ -o findings/ -x target.dict -- ./target @@

# With deterministic mutations first
afl-fuzz -i minimized_seeds/ -o findings/ -D -- ./target @@
```

**Step 6: Parallel Fuzzing (Recommended)**

```bash
# Terminal 1 - Master fuzzer
afl-fuzz -i minimized_seeds/ -o findings/ -M fuzzer1 -- ./target @@

# Terminal 2 - Slave fuzzer 1
afl-fuzz -i minimized_seeds/ -o findings/ -S fuzzer2 -- ./target @@

# Terminal 3 - Slave fuzzer 2
afl-fuzz -i minimized_seeds/ -o findings/ -S fuzzer3 -- ./target @@

# Terminal 4 - Slave fuzzer 3
afl-fuzz -i minimized_seeds/ -o findings/ -S fuzzer4 -- ./target @@
```

**Step 7: Monitor Fuzzing**

```bash
# Watch fuzzing status
watch -n 1 afl-whatsup findings/

# Check crashes
ls -la findings/fuzzer1/crashes/

# Reproduce crash
./target findings/fuzzer1/crashes/id:000000*
```

**Step 8: Advanced Mutation Strategies**

```bash
# Enable aggressive havoc mode
afl-fuzz -i seeds/ -o findings/ -p exploit -- ./target @@

# Focus on finding hangs
afl-fuzz -i seeds/ -o findings/ -t 1000 -- ./target @@

# Custom power schedules (for faster mutations)
afl-fuzz -i seeds/ -o findings/ -p fast -- ./target @@
afl-fuzz -i seeds/ -o findings/ -p explore -- ./target @@
afl-fuzz -i seeds/ -o findings/ -p quad -- ./target @@
```

**Step 9: Corpus Minimization**

```bash
# After fuzzing, minimize the corpus
afl-cmin -i findings/fuzzer1/queue/ -o minimized_corpus/ -- ./target @@

# Minimize individual test cases
mkdir minimized_crashes
for crash in findings/fuzzer1/crashes/id:*; do
    afl-tmin -i "$crash" -o "minimized_crashes/$(basename $crash)" -- ./target @@
done
```

---

### **2. Coverage-Guided Fuzzing**

**Description:** Uses runtime feedback (code coverage) to guide input generation toward unexplored code paths. The gold standard for modern fuzzing.

**Best Tools:**
- **AFL++** ⭐⭐⭐⭐⭐
- **LibFuzzer** ⭐⭐⭐⭐⭐
- **Honggfuzz** ⭐⭐⭐⭐

**When to Use:**
- Source code available
- Deep code path exploration needed
- Finding complex vulnerabilities
- Long-term fuzzing campaigns
- Security-critical software

**Advantages:**
✅ Explores deep code paths efficiently
✅ Finds bugs traditional testing misses
✅ Guided by actual execution
✅ Corpus grows intelligently
✅ Best for vulnerability discovery

**Disadvantages:**
❌ Requires source code or binary instrumentation
❌ Slower than dumb fuzzing
❌ More complex setup

---

#### **Coverage-Guided Campaign: LibFuzzer Deep Dive**

**How Coverage Guidance Works:**

```
Input → Execute → Measure Coverage → Did it find new paths?
                                      ├─ Yes → Save to corpus
                                      └─ No  → Discard

Feedback Loop:
  [Seed Inputs] → [Mutate] → [Execute] → [Coverage Data]
                      ↑                        ↓
                      └────── [New Paths?] ────┘
```

**Coverage Metrics:**
- **Edge Coverage**: Which code branches were taken
- **Path Coverage**: Which sequences of edges were taken
- **Function Coverage**: Which functions were called
- **Line Coverage**: Which source lines executed

---

#### **Complete LibFuzzer Coverage Campaign**

**Step 1: Create Fuzz Target**

```cpp
// fuzz_target.cpp
#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>

// The function you want to test
void VulnerableParser(const uint8_t *data, size_t size) {
    if (size < 4) return;
    
    // Simulate complex logic
    if (data[0] == 'F') {
        if (data[1] == 'U') {
            if (data[2] == 'Z') {
                if (data[3] == 'Z') {
                    // Deep path - potential vulnerability
                    char buffer[10];
                    memcpy(buffer, data + 4, size - 4); // Buffer overflow!
                }
            }
        }
    }
}

// LibFuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    VulnerableParser(Data, Size);
    return 0;
}
```

**Step 2: Compile with Coverage Instrumentation**

```bash
# Basic compilation with LibFuzzer
clang++ -g -O1 -fsanitize=fuzzer fuzz_target.cpp -o fuzzer

# With AddressSanitizer (detect memory bugs)
clang++ -g -O1 -fsanitize=fuzzer,address fuzz_target.cpp -o fuzzer

# With UndefinedBehaviorSanitizer
clang++ -g -O1 -fsanitize=fuzzer,address,undefined fuzz_target.cpp -o fuzzer

# With all sanitizers (recommended)
clang++ -g -O1 -fsanitize=fuzzer,address,undefined,leak \
    -fno-omit-frame-pointer fuzz_target.cpp -o fuzzer
```

**Step 3: Create Initial Corpus**

```bash
# Create corpus directory
mkdir corpus

# Add seed inputs (optional but recommended)
echo "FUZZ" > corpus/seed1
echo "TEST" > corpus/seed2
echo "DATA" > corpus/seed3

# Or start with empty corpus (LibFuzzer will generate)
mkdir corpus
```

**Step 4: Run Coverage-Guided Fuzzing**

```bash
# Basic fuzzing
./fuzzer corpus/

# With options
./fuzzer corpus/ \
    -max_len=1024 \          # Maximum input length
    -timeout=10 \            # Timeout per execution (seconds)
    -workers=4 \             # Parallel workers
    -jobs=1000 \             # Number of fuzzing jobs
    -print_coverage=1        # Print coverage stats
```

**Step 5: Advanced Coverage Options**

```bash
# Focus on unexplored coverage
./fuzzer corpus/ \
    -focus_function=VulnerableParser \
    -max_len=1024

# Minimize corpus while maintaining coverage
./fuzzer -merge=1 new_corpus/ corpus/

# Run with detailed coverage output
./fuzzer corpus/ \
    -print_pcs=1 \           # Print covered PCs
    -print_final_stats=1     # Final statistics
```

**Step 6: Structured Fuzzing with Hints**

```cpp
// Advanced fuzz target with coverage hints
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0;
    
    // Use libFuzzer's compare hints for faster discovery
    if (__builtin_memcmp(Data, "MAGIC123", 8) == 0) {
        // This path will be discovered faster with memcmp instrumentation
        if (Size > 100) {
            // Deep vulnerability
            char buf[10];
            memcpy(buf, Data + 8, Size - 8);
        }
    }
    
    return 0;
}
```

**Compile with comparison instrumentation:**
```bash
clang++ -g -O1 -fsanitize=fuzzer,address \
    -fsanitize-coverage=trace-cmp \
    fuzz_target.cpp -o fuzzer
```

**Step 7: Continuous Fuzzing Campaign**

```bash
# Run for 24 hours
./fuzzer corpus/ -max_total_time=86400

# Run until finding N crashes
./fuzzer corpus/ -runs=1000000

# Distributed fuzzing on multiple machines
# Machine 1:
./fuzzer -fork=8 corpus/

# Machine 2:
./fuzzer -fork=8 corpus/  # Share corpus via network drive
```

**Step 8: Analyze Coverage**

```bash
# Generate coverage report
clang++ -g -O1 -fsanitize=fuzzer,address \
    -fprofile-instr-generate -fcoverage-mapping \
    fuzz_target.cpp -o fuzzer_cov

# Run with coverage
LLVM_PROFILE_FILE="coverage.profraw" ./fuzzer_cov corpus/ -runs=10000

# Convert to readable format
llvm-profdata merge -sparse coverage.profraw -o coverage.profdata

# Generate HTML coverage report
llvm-cov show ./fuzzer_cov -instr-profile=coverage.profdata \
    -format=html > coverage.html

# View in browser
firefox coverage.html
```

---

### **3. Grammar-Based Fuzzing**

**Description:** Uses formal grammars or specifications to generate valid, well-formed inputs. Ideal for structured data formats and programming languages.

**Best Tools:**
- **Custom Grammar Generators** (Python-based)
- **Grammarinator** ⭐⭐⭐
- **Nautilus** ⭐⭐⭐

**When to Use:**
- Known input grammar/specification
- Testing parsers and compilers
- Protocol fuzzing with specs
- Structured formats (JSON, XML, SQL)
- Language interpreters

**Advantages:**
✅ Generates mostly valid inputs
✅ Bypasses simple validation
✅ Tests deeper logic
✅ Better coverage of valid states
✅ Efficient for complex formats

**Disadvantages:**
❌ Requires grammar specification
❌ May miss edge cases outside grammar
❌ More complex to set up
❌ Can be slower

---

#### **Grammar-Based Campaign: Complete Guide**

**Example 1: JSON Grammar Fuzzing**

**Step 1: Define Grammar (ANTLR Format)**

```antlr
// json.g4
grammar JSON;

json
   : value
   ;

object
   : '{' pair (',' pair)* '}'
   | '{' '}'
   ;

pair
   : STRING ':' value
   ;

array
   : '[' value (',' value)* ']'
   | '[' ']'
   ;

value
   : STRING
   | NUMBER
   | object
   | array
   | 'true'
   | 'false'
   | 'null'
   ;

STRING
   : '"' (ESC | ~["\\])* '"'
   ;

fragment ESC
   : '\\' ["\\/bfnrt]
   | '\\u' HEX HEX HEX HEX
   ;

fragment HEX
   : [0-9a-fA-F]
   ;

NUMBER
   : '-'? INT ('.' [0-9]+)? EXP?
   ;

fragment INT
   : '0' | [1-9] [0-9]*
   ;

fragment EXP
   : [Ee] [+\-]? INT
   ;

WS
   : [ \t\n\r]+ -> skip
   ;
```

**Step 2: Generate Fuzzer with Grammarinator**

```bash
# Install Grammarinator
pip install grammarinator

# Generate fuzzer from grammar
grammarinator-process json.g4 -o json_fuzzer/

# Generate test cases
grammarinator-generate -r json \
    -d 10 \                     # Max depth
    -n 1000 \                   # Number of tests
    -o json_tests/ \
    json_fuzzer.JSONGenerator
```

**Step 3: Use Generated Inputs**

```bash
# Feed to your JSON parser
for test in json_tests/*.json; do
    ./json_parser "$test"
done

# Or integrate with AFL++
mkdir grammar_seeds
cp json_tests/*.json grammar_seeds/
afl-fuzz -i grammar_seeds/ -o findings/ -- ./json_parser @@
```

---

**Example 2: SQL Grammar Fuzzing**

**Step 1: Define SQL Grammar**

```python
# sql_grammar.py
import random

class SQLGrammarFuzzer:
    def __init__(self):
        self.grammar = {
            '<start>': ['<statement>'],
            '<statement>': [
                '<select>',
                '<insert>',
                '<update>',
                '<delete>'
            ],
            '<select>': [
                'SELECT <columns> FROM <table> <where>',
                'SELECT <columns> FROM <table>'
            ],
            '<insert>': [
                'INSERT INTO <table> VALUES <values>'
            ],
            '<update>': [
                'UPDATE <table> SET <assignments> <where>'
            ],
            '<delete>': [
                'DELETE FROM <table> <where>'
            ],
            '<columns>': [
                '*',
                '<column>',
                '<column>, <columns>'
            ],
            '<column>': [
                'id',
                'name',
                'email',
                'password'
            ],
            '<table>': [
                'users',
                'products',
                'orders'
            ],
            '<where>': [
                '',
                'WHERE <condition>'
            ],
            '<condition>': [
                '<column> = <value>',
                '<column> > <value>',
                '<column> < <value>',
                '<condition> AND <condition>',
                '<condition> OR <condition>'
            ],
            '<value>': [
                '1',
                "'test'",
                "'admin' OR '1'='1'",  # SQL injection payload
                "'; DROP TABLE users--"
            ],
            '<values>': [
                '(<value>)',
                '(<value>, <values>)'
            ],
            '<assignments>': [
                '<column> = <value>',
                '<column> = <value>, <assignments>'
            ]
        }
    
    def generate(self, symbol='<start>', depth=0, max_depth=10):
        if depth > max_depth:
            return ""
        
        if symbol not in self.grammar:
            return symbol
        
        expansion = random.choice(self.grammar[symbol])
        result = ""
        
        for part in expansion.split():
            if part.startswith('<'):
                result += self.generate(part, depth + 1, max_depth) + " "
            else:
                result += part + " "
        
        return result.strip()

# Usage
fuzzer = SQLGrammarFuzzer()
for i in range(100):
    query = fuzzer.generate()
    print(f"Test {i}: {query}")
    # Send to SQL parser for testing
```

**Step 2: Integration with Coverage Fuzzing**

```bash
# Generate seed corpus
python sql_grammar.py > grammar_seeds.txt

# Use with AFL++
mkdir sql_seeds
split -l 1 grammar_seeds.txt sql_seeds/seed_

# Compile SQL parser with instrumentation
afl-clang-fast -o sql_parser sql_parser.c

# Run fuzzing with grammar seeds
afl-fuzz -i sql_seeds/ -o findings/ -- ./sql_parser @@
```

---

**Example 3: XML Grammar Fuzzing**

**Step 1: Simple XML Grammar Generator**

```python
# xml_fuzzer.py
import random

class XMLFuzzer:
    def __init__(self):
        self.tags = ["root", "child", "data", "item", "element"]
        self.attributes = ["id", "name", "value", "type", "class"]
        
    def generate_element(self, depth=0, max_depth=5):
        if depth >= max_depth:
            return random.choice(["text", "123", "data"])
        
        tag = random.choice(self.tags)
        attrs = ""
        
        # Add random attributes
        if random.random() > 0.5:
            num_attrs = random.randint(0, 3)
            attr_list = []
            for _ in range(num_attrs):
                attr_name = random.choice(self.attributes)
                attr_value = f"value_{random.randint(1, 100)}"
                attr_list.append(f'{attr_name}="{attr_value}"')
            if attr_list:
                attrs = " " + " ".join(attr_list)
        
        # Self-closing or with content
        if random.random() > 0.3:
            # With content
            content = ""
            num_children = random.randint(0, 3)
            for _ in range(num_children):
                content += self.generate_element(depth + 1, max_depth)
            return f"<{tag}{attrs}>{content}</{tag}>"
        else:
            # Self-closing
            return f"<{tag}{attrs}/>"
    
    def generate(self):
        xml = '<?xml version="1.0"?>\n'
        xml += self.generate_element()
        return xml

# Generate test cases
fuzzer = XMLFuzzer()
for i in range(100):
    test = fuzzer.generate()
    with open(f"xml_tests/test_{i}.xml", "w") as f:
        f.write(test)
```

---

### **Fuzzing Campaign Comparison**

| Aspect | Mutation-Based | Coverage-Guided | Grammar-Based |
|--------|---------------|-----------------|---------------|
| **Setup Time** | Fast ⚡⚡⚡ | Medium ⚡⚡ | Slow ⚡ |
| **Code Coverage** | Low-Medium | High ⭐⭐⭐⭐⭐ | Medium-High |
| **Valid Inputs** | Low | Medium | High ⭐⭐⭐⭐⭐ |
| **Speed** | Fast ⚡⚡⚡ | Medium ⚡⚡ | Slow ⚡ |
| **Deep Bugs** | Medium | High ⭐⭐⭐⭐⭐ | High ⭐⭐⭐⭐ |
| **Source Needed** | No ✅ | Yes ❌ | No ✅ |
| **Grammar Needed** | No ✅ | No ✅ | Yes ❌ |
| **Best For** | Unknown formats | Security testing | Parsers/Protocols |

---

### **Recommended Fuzzing Strategy**

**For Most Projects:**
```bash
# Start with coverage-guided (LibFuzzer or AFL++)
1. Set up AFL++ or LibFuzzer
2. Create seed corpus from valid inputs
3. Run coverage-guided fuzzing
4. Monitor for crashes and hangs
5. Triage and fix bugs
6. Repeat
```

**For Complex Structured Formats:**
```bash
# Combine grammar-based with coverage-guided
1. Define grammar for your format
2. Generate seed corpus from grammar
3. Feed grammar seeds to AFL++ or LibFuzzer
4. Get both valid structure AND coverage guidance
5. Best of both worlds!
```

**Hybrid Approach (Recommended):**
```bash
# Use all three together!
Phase 1: Grammar-based seed generation (1000 inputs)
Phase 2: Coverage-guided fuzzing with grammar seeds (24 hours)
Phase 3: Mutation-based on discovered corpus (ongoing)
```

---

## 🏆 Top 50 Most In-Demand Tools

**Based on frequency in job postings:**

| Rank | Tool | Mentioned In | Category |
|------|------|--------------|----------|
| 1 | Burp Suite Professional | 95% | Web Security |
| 2 | Nmap | 90% | Network Scanning |
| 3 | Metasploit | 75% | Exploitation/C2 |
| 4 | Postman | 70% | API Testing |
| 5 | Windows | 68% | Operating System |
| 6 | OWASP ZAP | 60% | Web Security |
| 7 | Nuclei | 55% | Vulnerability Scanning |
| 8 | Wireshark | 50% | Network Analysis |
| 9 | SQLMap | 50% | SQL Injection |
| 10 | VirtualBox | 48% | Virtualization |
| 11 | Nessus | 45% | Vulnerability Scanning |
| 12 | Kali Linux | 44% | Operating System |
| 13 | Frida | 42% | Mobile/Dynamic Analysis |
| 14 | Ffuf | 40% | Directory Discovery |
| 15 | Amass | 40% | Subdomain Enum |
| 16 | Ghidra | 38% | Reverse Engineering |
| 17 | Subfinder | 35% | Subdomain Enum |
| 18 | Android Studio | 32% | Mobile Development |
| 19 | Snyk | 30% | Dependency Scanning |
| 20 | Gobuster | 30% | Directory Discovery |
| 21 | JADX | 28% | Android RE |
| 22 | APKTool | 28% | Android RE |
| 23 | ADB | 27% | Mobile Testing |
| 24 | Prowler | 25% | Cloud Security |
| 25 | Trivy | 25% | Container Security |
| 26 | AFL++ | 22% | Fuzzing |
| 27 | Katana | 20% | Web Crawling |
| 28 | Kiterunner | 20% | API Discovery |
| 29 | IDA Pro | 18% | Reverse Engineering |
| 30 | Sliver | 15% | C2 Framework |
| 31 | ScoutSuite | 14% | Cloud Security |
| 32 | MobSF | 14% | Mobile Security |
| 33 | LibFuzzer | 13% | Fuzzing |
| 34 | Arjun | 12% | Parameter Discovery |
| 35 | GAU | 12% | Web Crawling |
| 36 | LinkFinder | 11% | JS Analysis |
| 37 | SQLMap | 11% | SQL Injection |
| 38 | Interactsh | 10% | OOB Testing |
| 39 | Checkmarx | 10% | SAST |
| 40 | Radare2 | 9% | Reverse Engineering |
| 41 | Honggfuzz | 9% | Fuzzing |
| 42 | kube-bench | 8% | K8s Security |
| 43 | Feroxbuster | 8% | Directory Discovery |
| 44 | Drozer | 7% | Mobile Security |
| 45 | InQL | 7% | GraphQL Testing |
| 46 | Retire.js | 7% | JS Vuln Scanning |
| 47 | dex2jar | 6% | Android RE |
| 48 | Merlin | 6% | C2 Framework |
| 49 | CloudSploit | 6% | Cloud Security |
| 50 | XSSHunter | 5% | XSS Detection |

---

## 📈 Trending Tools (2023-2024)

**Fastest Growing in Job Postings:**

1. **Nuclei** - 300% increase (ProjectDiscovery ecosystem)
2. **Sliver** - Open-source C2 gaining traction
3. **Katana** - New crawler, rapid adoption
4. **Kiterunner** - API security focus
5. **Trivy** - Container security boom
6. **Prowler** - Cloud migration driving demand
7. **JADX** - Android security emphasis
8. **ADB** - Mobile testing standardization
9. **Interactsh** - OOB testing standard
10. **Frida** - Mobile/dynamic analysis growth

---

## 🔑 Quick Start Recommendations

### **If you're learning ONE tool:**
→ Start with **Burp Suite Professional**

# Security Tools Arsenal - Organized Starter Kits

## 🔧 Building Your First Toolkit (16+ Tools)

### **Foundation & Environment (3 tools)**
1. **Windows OS** - Primary operating system for enterprise security testing ⭐⭐⭐⭐⭐
2. **VirtualBox** - Cross-platform virtualization for isolated testing environments ⭐⭐⭐⭐⭐
3. **Kali Linux** - Penetration testing distribution with pre-installed tools ⭐⭐⭐⭐⭐

### **Reconnaissance & Discovery (2 tools)**
4. **Subfinder/Sublist3r** - Fast subdomain enumeration ⭐⭐⭐⭐
5. **CT-Exposer Enhanced** - Multi-source subdomain discovery via Certificate Transparency logs ⭐⭐⭐⭐

### **Network & Infrastructure Scanning (1 tool)**
6. **Nmap** - Network discovery and port scanning ⭐⭐⭐⭐⭐

### **Web Application Security (5 tools)**
7. **Burp Suite Professional** - #1 web security testing platform ⭐⭐⭐⭐⭐
8. **OWASP ZAP** - Open-source web application scanner ⭐⭐⭐⭐
9. **Nuclei** - Fast template-based vulnerability scanner ⭐⭐⭐⭐⭐
10. **Ffuf** - Fast web fuzzer for directory/file discovery ⭐⭐⭐⭐⭐
11. **Arjun** - HTTP parameter discovery tool ⭐⭐⭐⭐

### **API Testing (1 tool)**
12. **Postman** - API development and testing platform ⭐⭐⭐⭐⭐

### **Vulnerability Exploitation (2 tools)**
13. **SQLMap** - Automated SQL injection detection and exploitation ⭐⭐⭐⭐⭐
14. **Metasploit** - Exploitation framework and C2 ⭐⭐⭐⭐⭐

### **XSS Testing (1 tool)**
15. **XSSHunter** - Blind XSS discovery platform ⭐⭐⭐

### **Fuzzing (3 tools)**
16. **AFL++** - Coverage-guided fuzzer ⭐⭐⭐⭐⭐
17. **LibFuzzer** - In-process fuzzer (LLVM) ⭐⭐⭐⭐
18. **Honggfuzz** - Security-oriented fuzzer ⭐⭐⭐⭐

---

## 📱 Mobile Security Starter Kit (11 Tools)

### **Development & Testing Environment (2 tools)**
1. **Android Studio** - Official Android IDE with emulator ⭐⭐⭐⭐⭐
2. **ADB (Android Debug Bridge)** - Command-line tool for Android device communication ⭐⭐⭐⭐⭐

### **Static Analysis & Decompilation (4 tools)**
3. **JADX** - Dex to Java decompiler ⭐⭐⭐⭐⭐
4. **APKTool** - Reverse engineering tool for APK files ⭐⭐⭐⭐⭐
5. **dex2jar** - DEX to JAR converter ⭐⭐⭐⭐
6. **MobSF** - Mobile Security Framework (automated static/dynamic analysis) ⭐⭐⭐⭐

### **Dynamic Analysis & Instrumentation (2 tools)**
7. **Frida** - Dynamic instrumentation toolkit ⭐⭐⭐⭐⭐
8. **Drozer** - Android security assessment framework ⭐⭐⭐

### **Binary & Native Code Analysis (2 tools)**
9. **Ghidra** - Reverse engineering platform for native code (ARM/x86) ⭐⭐⭐⭐⭐
10. **IDA Pro** - Disassembler & debugger for ARM/x86 binaries ⭐⭐⭐⭐⭐

### **Network Interception (1 tool)**
11. **Burp Suite** - Intercept and analyze mobile app traffic ⭐⭐⭐⭐⭐

---

## 📊 Toolkit Comparison

| Category | First Toolkit | Mobile Security Kit |
|----------|---------------|---------------------|
| **Total Tools** | 18 tools | 11 tools |
| **Operating Systems** | 2 (Windows, Kali) | 0 (uses host OS) |
| **Virtualization** | 1 (VirtualBox) | 0 |
| **Web Security** | 5 tools | 1 tool |
| **API Testing** | 1 tool | 0 |
| **Mobile Specific** | 0 | 10 tools |
| **Fuzzing** | 3 tools | 0 |
| **Reverse Engineering** | 0 | 4 tools |
| **Dynamic Analysis** | 0 | 2 tools |
| **Network Analysis** | 1 tool | 1 tool |

---

## 🎯 Usage Workflow by Toolkit

### **First Toolkit - Web Application Testing Workflow**

```
Phase 1: Setup Environment
  ├─ Install Windows OS (host)
  ├─ Install VirtualBox
  └─ Set up Kali Linux VM

Phase 2: Reconnaissance
  ├─ CT-Exposer Enhanced → Find subdomains
  ├─ Subfinder/Sublist3r → Additional subdomain discovery
  └─ Nmap → Port scan discovered hosts

Phase 3: Web Application Testing
  ├─ Burp Suite → Manual testing & intercept
  ├─ OWASP ZAP → Automated scanning
  ├─ Nuclei → Template-based vulnerability scanning
  ├─ Ffuf → Directory/file discovery
  └─ Arjun → Parameter discovery

Phase 4: API Testing
  └─ Postman → API endpoint testing

Phase 5: Exploitation
  ├─ SQLMap → SQL injection testing
  ├─ XSSHunter → Blind XSS discovery
  └─ Metasploit → Exploit known vulnerabilities

Phase 6: Advanced (Fuzzing)
  ├─ AFL++ → Binary fuzzing
  ├─ LibFuzzer → In-process fuzzing
  └─ Honggfuzz → Security-oriented fuzzing
```

### **Mobile Security Kit - Android App Testing Workflow**

```
Phase 1: Setup & Installation
  ├─ Android Studio → Set up emulator
  └─ ADB → Connect to device/emulator

Phase 2: Static Analysis
  ├─ APKTool → Decompile APK
  ├─ JADX → Decompile to Java source
  ├─ dex2jar → Convert DEX to JAR
  └─ MobSF → Automated static analysis

Phase 3: Dynamic Analysis
  ├─ Frida → Runtime instrumentation
  ├─ Drozer → Attack surface analysis
  └─ Burp Suite → Network traffic interception

Phase 4: Native Code Analysis
  ├─ Ghidra → Analyze ARM/x86 binaries
  └─ IDA Pro → Advanced disassembly

Phase 5: Testing & Validation
  ├─ ADB → Execute commands, pull data
  └─ MobSF → Automated dynamic analysis
```

---

## 💡 Learning Path Recommendations

### **For First Toolkit (Beginner → Advanced)**

**Beginner:**
1. Windows OS + VirtualBox + Kali Linux (environment setup)
2. Nmap (network scanning basics)
3. Burp Suite (web proxy fundamentals)
4. Nuclei (automated vulnerability scanning)

**Intermediate:**
5. Subfinder/CT-Exposer (reconnaissance)
6. Ffuf (directory fuzzing)
7. OWASP ZAP (automated scanning)
8. Arjun (parameter discovery)
9. Postman (API testing)

**Advanced:**
10. SQLMap (SQL injection)
11. Metasploit (exploitation)
12. XSSHunter (advanced XSS)
13. AFL++ (fuzzing introduction)
14. LibFuzzer + Honggfuzz (advanced fuzzing)

### **For Mobile Security Kit (Beginner → Advanced)**

**Beginner:**
1. Android Studio + ADB (environment setup)
2. APKTool (basic decompilation)
3. JADX (source code analysis)
4. Burp Suite (traffic interception)

**Intermediate:**
5. MobSF (automated analysis)
6. dex2jar (DEX conversion)
7. Frida (basic hooking)
8. Drozer (attack surface analysis)

**Advanced:**
9. Ghidra (native code analysis)
10. IDA Pro (advanced disassembly)
11. Advanced Frida scripting

---

## 📥 Installation Order

### **First Toolkit Installation Sequence**

```bash
# Day 1: Foundation
1. Install Windows OS (if not already installed)
2. Install VirtualBox
3. Download and set up Kali Linux VM

# Day 2: Essential Tools (Kali comes with most)
4. Verify Nmap installation (pre-installed in Kali)
5. Verify Metasploit installation (pre-installed in Kali)
6. Install Burp Suite Community/Professional

# Day 3: Web Security Tools
7. Install Nuclei (go install)
8. Install Ffuf (go install)
9. Install Subfinder (go install)
10. Install CT-Exposer Enhanced (Python)
11. Install OWASP ZAP

# Day 4: Specialized Tools
12. Install Postman
13. Install Arjun (pip)
14. Set up XSSHunter (or use public instance)
15. Verify SQLMap (pre-installed in Kali)

# Day 5: Fuzzing Tools
16. Install AFL++
17. Install LibFuzzer (comes with Clang/LLVM)
18. Install Honggfuzz
```

### **Mobile Security Kit Installation Sequence**

```bash
# Day 1: Development Environment
1. Install Android Studio
2. Configure Android SDK
3. Set up Android Emulator
4. Verify ADB installation

# Day 2: Static Analysis Tools
5. Install JADX
6. Install APKTool
7. Install dex2jar
8. Install MobSF (Docker recommended)

# Day 3: Dynamic Analysis Tools
9. Install Frida (pip install frida-tools)
10. Install Drozer
11. Configure Burp Suite for mobile testing

# Day 4: Binary Analysis Tools
12. Install Ghidra
13. Install IDA Pro (or IDA Free)
```

---

## 🔑 Quick Reference Commands

### **First Toolkit - Common Commands**

```bash
# Reconnaissance
ctlogexposer.py -u -d target.com
subfinder -d target.com -o subdomains.txt
nmap -sV -sC -p- target.com

# Web Testing
burpsuite # Launch Burp Suite
nuclei -u https://target.com
ffuf -w wordlist.txt -u https://target.com/FUZZ
arjun -u https://target.com/api/endpoint

# Exploitation
sqlmap -u "https://target.com/page?id=1" --batch
msfconsole

# Fuzzing
afl-fuzz -i input/ -o output/ -- ./target @@
./fuzzer corpus/
```

### **Mobile Security Kit - Common Commands**

```bash
# ADB Commands
adb devices
adb install app.apk
adb shell
adb logcat
adb pull /data/data/com.app/

# Static Analysis
apktool d app.apk
jadx-gui app.apk
d2j-dex2jar app.apk

# Dynamic Analysis
frida -U -f com.app.name -l script.js
drozer console connect
frida-ps -U

# MobSF
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

```

## 🎓 Certification Alignment

### **First Toolkit Covers:**
- OSCP (70% of tools)
- CEH (60% of tools)
- GWAPT (80% of tools)
- eWPT (75% of tools)

### **Mobile Security Kit Covers:**
- GMOB (100% of tools)
- eMAPT (90% of tools)
- Mobile App Hacker (95% of tools)

```

### **Fuzzing Starter Kit (4 tools):**
1. AFL++
2. LibFuzzer
3. Honggfuzz
4. Radamsa
5. Mutators

### **Essential Lab Setup:**
1. Windows (Host OS)
2. VirtualBox
3. Kali Linux (VM)
4. Windows 10/11 (Testing VM)
5. Android Studio + Emulator

---

## 📚 Tool Categories Summary

| Category | Tool Count | Top Tools |
|----------|------------|-----------|
| Network Scanning | 8 | Nmap, Nessus, Wireshark |
| Subdomain Enum | 5 | Amass, Subfinder, Subjack |
| Web Crawling | 4 | Katana, GAU, GoSpider |
| Directory Discovery | 5 | Ffuf, Gobuster, Feroxbuster |
| Web App Security | 5 | Burp Suite, OWASP ZAP, Nuclei |
| Parameter Discovery | 2 | Arjun, Kiterunner |
| API Testing | 4 | Postman, Kiterunner, Insomnia |
| GraphQL | 3 | InQL, GraphQLmap, CrackQL |
| SQL Injection | 2 | SQLMap, NoSQLMap |
| XSS Detection | 3 | XSStrike, XSSHunter, Dalfox |
| SSRF/OOB | 3 | Interactsh, SSRFmap, Burp Collaborator |
| JavaScript Analysis | 5 | LinkFinder, JSFinder, SecretFinder |
| Cloud Security | 6 | Prowler, ScoutSuite, Trivy |
| Container/K8s | 4 | Trivy, kube-bench, Grype |
| Dependency Scanning | 4 | Snyk, OWASP Dep-Check, Safety |
| SAST/DAST | 3 | Checkmarx, Fortify, Veracode |
| Exploitation/C2 | 4 | Metasploit, Sliver, Merlin, Pacu |
| Fuzzing | 4 | AFL++, LibFuzzer, Honggfuzz, Radamsa |
| Mobile Security | 5 | Android Studio, ADB, MobSF, Frida |
| Android RE | 7 | JADX, APKTool, dex2jar, Androguard |
| OSINT/Recon | 5 | Recon-ng, theHarvester, Shodan, Maltego |
| Reverse Engineering | 4 | Ghidra, IDA Pro, Radare2, Hopper |
| Virtualization/OS | 3 | VirtualBox, Kali Linux, Windows |
| **Total** | **100** | **Unique Tools** |

---
