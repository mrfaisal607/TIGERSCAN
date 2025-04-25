# 🐅 TIGERSCAN

**TIGERSCAN** is a modular, CLI-based domain reconnaissance framework built in Python. It’s designed to help security researchers, penetration testers, and developers gather intelligence about internet-facing domains using a fast, unified, and readable command-line interface.  

With a focus on clarity, ease of use, and informative output, TIGERSCAN consolidates multiple scanning techniques (WHOIS, DNS, subdomain enumeration, port scanning, tech fingerprinting) into a single, scriptable tool.

---

## ✨ Key Features

- 🔍 **WHOIS Lookup**: Retrieve domain registration info including registrar, creation/expiry dates, name servers, etc.
- 🌐 **DNS Record Enumeration**: Fetch DNS record types (A, AAAA, MX, NS, TXT, SOA, CNAME) for target domains.
- 🕵️‍♂️ **Subdomain Enumeration**: Discover subdomains using public Certificate Transparency logs via `crt.sh`.
- 🔓 **Port Scanning**: Identify open common ports (80, 443, 22, etc.) using native socket connections.
- 🧠 **Technology Detection**: Analyze HTTP response headers to detect server software, frameworks, and basic security posture.
- 💾 **JSON Output**: Optionally export all scan results into a structured `.json` file for reporting or further processing.
- 🎨 **Rich CLI Output**: Clean, color-coded tables and panels powered by the `rich` library for better readability.

---

## 📌 Project Goals

TIGERSCAN was created to simplify the initial information gathering phase in security testing. It's not a full replacement for tools like Nmap, Amass, or Wappalyzer, but rather a fast way to get answers — right from the terminal, in a format that makes sense.

---

## 🧱 Requirements

Python 3.6 or higher

### Python Packages:
- `rich`
- `whois`
- `dnspython`
- `requests`

Install dependencies via pip:

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install rich whois dnspython requests
```

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/mrfaisal607/TIGERSCAN.git
cd TIGERSCAN
```

Make the script executable (optional):

```bash
chmod +x tigerscan.py
```

Run the tool using:

```bash
python3 tigerscan.py -d example.com --all
```

---

## 🛠️ Usage

### Basic Syntax

```bash
python3 tigerscan.py -d <domain> [options]
```

### Required Argument

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Target domain (e.g. `example.com`) |

---

### Scan Options

| Flag         | Description                                  |
|--------------|----------------------------------------------|
| `--whois`    | Perform a WHOIS lookup                       |
| `--dns`      | Retrieve DNS records (A, NS, MX, TXT, etc.)  |
| `--sub`      | Enumerate subdomains using crt.sh            |
| `--ports`    | Scan common TCP ports (22, 80, 443, etc.)    |
| `--tech`     | Detect technologies via response headers      |
| `--all`      | Run all of the above scans                   |

---

### Output Options

| Flag         | Description                                  |
|--------------|----------------------------------------------|
| `--output`   | Save results to a JSON file (e.g., `out.json`) |

---

### Help Menu

```bash
python3 tigerscan.py --help
```

---

## 📦 Examples

#### Run WHOIS and DNS Scan

```bash
python3 tigerscan.py -d example.com --whois --dns
```

#### Full Recon with Output to File

```bash
python3 tigerscan.py -d example.com --all --output results.json
```

#### Subdomain and Port Scan Only

```bash
python3 tigerscan.py -d example.com --sub --ports
```

---

## 📊 Output Formats

### CLI (Terminal Output)

Uses `rich.console` for formatted tables and colored panels. Makes results easy to interpret in real-time.

### JSON Export

Scan results can be saved to disk in `.json` format, preserving structure and enabling integration with other tools or automation.

---

## 📁 File Structure

```
TIGERSCAN/
├── tigerscan.py           # Main executable
├── requirements.txt       # Python dependencies
├── README.md              # Project documentation
```

---

## ✅ Modules Overview

### WHOIS Module

Uses the `whois` Python package to retrieve registrar info, important dates, domain status, and associated name servers.

### DNS Lookup

Resolves standard DNS records using `dnspython` including:
- A, AAAA
- MX (Mail Exchange)
- NS (Name Servers)
- TXT (SPF, DMARC, etc.)
- CNAME, SOA

### Subdomain Enumeration

Fetches historical subdomain entries from public certificate transparency logs via `crt.sh`. Simple and effective for passive subdomain recon.

### Port Scanner

Uses `socket` to scan common ports on the resolved IP address of the domain. Includes:
- FTP (21)
- SSH (22)
- HTTP (80)
- HTTPS (443)
- MySQL (3306)

More ports can be added easily in the code.

### Technology Detection

Makes a standard HTTP(S) request and extracts:
- Final URL after redirects
- Server and X-Powered-By headers
- Presence of security headers like:
  - Content-Security-Policy
  - X-Frame-Options
  - X-XSS-Protection

---

## 🔒 Disclaimer

> This tool is intended for **authorized testing, educational use, and learning purposes only**.  
> Do **NOT** use TIGERSCAN to scan domains or networks without proper authorization. Unauthorized scanning is illegal and unethical.

---

## 👨‍💻 Author

**Faisal Khan (Khansaab)**  
- GitHub: [@mrfaisal607](https://github.com/mrfaisal607)
- Contributions, feedback, and improvements are welcome!

---

## 🧩 Future Roadmap

- [ ] Add support for custom port ranges
- [ ] Parallel subdomain brute-force option
- [ ] Add CDN / hosting provider detection
- [ ] Option to export HTML or Markdown reports
- [ ] CLI auto-completion or interactive mode

---



## 🙌 Contributions Welcome

If you’d like to contribute:
1. Fork the repo
2. Create a new branch
3. Make your changes
4. Submit a pull request

Open issues or suggest features — this is an open-source project, and your input matters.
